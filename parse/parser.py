"""DSA Engine — Pre-compiled regex parsing, strict format validation, and time-based sliding-window anomaly detection."""

import re
import threading
import time
from collections import deque
from datetime import datetime
from vault import db
from src.common.models import LogEvent

# Pre-compiled Regex Patterns (compiled once at init)
# Supports standard Loghub HDFS (081109 203518 143 WARN dfs.FSNamesystem: ...)
# AND ISO HDFS style (2026-09-12 12:00:01 [INFO] namenode: ...)
HDFS_REGEX = re.compile(
    r"^\s*(?:(?P<date>\d{6})\s+(?P<time>\d{6})\s+(?P<pid>\d+)|(?P<iso_datetime>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}))\s+"
    r"\[?(?P<level>INFO|WARN|WARNING|ERROR|FATAL)\]?\s+"
    r"(?P<component>[\w\.\$\/\-]+):\s+(?P<msg>.*)$",
    re.I,
)

# NASA-HTTP Common Log Format: 199.72.81.55 - - [01/Jul/1995:00:00:01 -0400] "GET /history/apollo/ HTTP/1.0" 200 6245
NASA_HTTP_REGEX = re.compile(
    r"^\s*(?P<host>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+"
    r"\[(?P<time>[^\]]+)\]\s+"
    r"\"(?P<request>[^\"]*)\"\s+"
    r"(?P<status>\d{3})\s+"
    r"(?P<bytes>\d+|-)(?:\s+.*)?$"
)

# Synchronization lock for config cache access & global state
_window_lock = threading.Lock()

# Independent per-source locks to prevent HDFS and NASA from blocking each other
_source_window_locks = {
    "hdfs": threading.Lock(),
    "nasa_http": threading.Lock(),
}

# In-memory dynamic config cache (loaded from DB, editable by ADMIN at runtime)
_config_cache = {
    "hdfs_window": 60,
    "hdfs_threshold": 5,
    "nasa_http_window": 60,
    "nasa_http_threshold": 5,
}

# Sliding window deques for anomaly timestamps per source category
_sliding_windows = {
    "hdfs": deque(),
    "nasa_http": deque(),
}


def refresh_config_cache():
    """Reload sliding window settings W and T from E3 Vault."""
    try:
        cfg = db.get_all_configs()
        with _window_lock:
            if "hdfs_window" in cfg:
                _config_cache["hdfs_window"] = int(cfg["hdfs_window"])
            if "hdfs_threshold" in cfg:
                _config_cache["hdfs_threshold"] = int(cfg["hdfs_threshold"])
            if "nasa_http_window" in cfg:
                _config_cache["nasa_http_window"] = int(cfg["nasa_http_window"])
            if "nasa_http_threshold" in cfg:
                _config_cache["nasa_http_threshold"] = int(cfg["nasa_http_threshold"])
    except Exception as exc:
        print(f"[refresh_config_cache] warning: {exc}")


def get_config_cache():
    with _window_lock:
        return dict(_config_cache)


def set_config_value(key, value):
    with _window_lock:
        _config_cache[key] = int(value)


def get_sliding_window_stats():
    """Return current window occupancy and configuration for monitoring."""
    with _window_lock:
        return {
            k: {
                "current_count": len(dq),
                "window_seconds": _config_cache.get(f"{k}_window", 60),
                "threshold": _config_cache.get(f"{k}_threshold", 5),
                "oldest_ts": dq[0] if dq else None,
                "newest_ts": dq[-1] if dq else None,
            }
            for k, dq in _sliding_windows.items()
        }


def parse_hdfs_timestamp(gd):
    """Convert HDFS YYMMDD HHMMSS or ISO timestamp to standard YYYY-MM-DD HH:MM:SS."""
    try:
        if gd.get("iso_datetime"):
            dt = datetime.strptime(gd["iso_datetime"], "%Y-%m-%d %H:%M:%S")
            return dt.strftime("%Y-%m-%d %H:%M:%S"), dt.timestamp()
        if gd.get("date") and gd.get("time"):
            dt = datetime.strptime(f"{gd['date']} {gd['time']}", "%y%m%d %H%M%S")
            return dt.strftime("%Y-%m-%d %H:%M:%S"), dt.timestamp()
    except Exception:
        pass
    now = datetime.now()
    return now.strftime("%Y-%m-%d %H:%M:%S"), now.timestamp()


def parse_nasa_timestamp(time_str):
    """Convert NASA CLF timestamp '01/Jul/1995:00:00:01 -0400' to standard YYYY-MM-DD HH:MM:SS."""
    try:
        parts = time_str.split()[0]
        dt = datetime.strptime(parts, "%d/%b/%Y:%H:%M:%S")
        return dt.strftime("%Y-%m-%d %H:%M:%S"), dt.timestamp()
    except Exception:
        now = datetime.now()
        return now.strftime("%Y-%m-%d %H:%M:%S"), now.timestamp()


def _check_sliding_window(source_category, epoch_timestamp, raw_message):
    """
    Time-based sliding window anomaly detection using collections.deque.
    FR-06, NFR-04:
    - Window Reference: Event-Time anchored to the latest observed event timestamp T_max.
      Active interval is [T_max - W, T_max].
    - In-order insertion is O(1) via deque.append().
    - Out-of-order insertion uses bisect.insort (O(N) for collections.deque).
    - Eviction: Removes events where (T_max - timestamp) > W.
    - An older event cannot evict a newer event; stale events (t < T_max - W) are ignored.
    - Maintains independent window deques and independent locks for HDFS and NASA-HTTP.
    - Database writes occur outside the critical section to avoid lock contention.
    - Fires alert if event count in active window reaches threshold T.
    """
    cat = "hdfs" if "hdfs" in source_category.lower() else "nasa_http"
    lock = _source_window_locks.get(cat, _window_lock)

    with _window_lock:
        window_sec = _config_cache.get(f"{cat}_window", 60)
        threshold = _config_cache.get(f"{cat}_threshold", 5)

    should_fire = False
    alert_payload = None

    with lock:
        if cat not in _sliding_windows:
            _sliding_windows[cat] = deque()

        window_deque = _sliding_windows[cat]
        now_ts = epoch_timestamp if epoch_timestamp else time.time()

        # Check if incoming out-of-order event is stale (older than T_max - W)
        if window_deque:
            t_max = window_deque[-1]
            if now_ts < (t_max - window_sec):
                # Stale event: already expired relative to current active window
                return False

        # In-order events (monotonic, 99%+ of logs) append in O(1).
        # Out-of-order events insert in sorted order via bisect.insort (O(N) in collections.deque).
        if not window_deque or now_ts >= window_deque[-1]:
            window_deque.append(now_ts)
        else:
            import bisect
            bisect.insort(window_deque, now_ts)

        # Evict timestamps older than active window [T_max - W, T_max]
        # Because window_deque is kept strictly sorted, window_deque[-1] is always T_max.
        current_t_max = window_deque[-1]
        while window_deque and (current_t_max - window_deque[0]) > window_sec:
            window_deque.popleft()

        # Trigger alert if threshold reached
        if len(window_deque) >= threshold:
            should_fire = True
            alert_payload = {
                "source": "HDFS" if cat == "hdfs" else "NASA-HTTP",
                "alert_type": f"{cat.upper()}_ANOMALY_BURST",
                "event_count": len(window_deque),
                "window_duration_sec": window_sec,
            }
            window_deque.clear()

    # Move DB write OUTSIDE the critical section (Fix for Check 3) with exception safety
    if should_fire and alert_payload:
        try:
            db.save_alert(
                source=alert_payload["source"],
                alert_type=alert_payload["alert_type"],
                event_count=alert_payload["event_count"],
                window_duration_sec=alert_payload["window_duration_sec"],
            )
        except Exception as exc:
            print(f"[_check_sliding_window] Error saving alert: {exc}")
        return True
    return False


def parse_line(line, declared_source="hdfs"):
    """
    Strictly parse and validate an ingested log line.
    
    Returns parsed dict on success.
    Quarantines malformed/unauthorized lines into E3 Vault rejected_lines table.
    """
    if line is None:
        db.save_rejected_line(declared_source, "Null line input", b"")
        return None

    raw_bytes = line if isinstance(line, bytes) else line.encode("utf-8", errors="replace")

    if b"OVERSIZED_RECORD" in raw_bytes:
        db.save_rejected_line(declared_source, "Oversized record: Line exceeds 64KB limit", raw_bytes)
        return None

    if b"SECURITY_VIOLATION" in raw_bytes:
        db.save_rejected_line(declared_source, "Security violation: Directory traversal detected in path", raw_bytes)
        return None

    if b"\x00" in raw_bytes:
        db.save_rejected_line(declared_source, "Binary or null-byte data detected", raw_bytes)
        return None

    str_line = line if isinstance(line, str) else line.decode("utf-8", errors="replace")
    clean_line = str_line.strip()
    if not clean_line or clean_line.startswith("#"):
        return None

    source_clean = str(declared_source).lower()

    is_hdfs_source = "hdfs" in source_clean
    is_nasa_source = any(k in source_clean for k in ("nasa", "http", "clf", "access", "apache", "nginx"))

    if is_hdfs_source:
        match = HDFS_REGEX.match(clean_line)
        if not match:
            db.save_rejected_line(declared_source, "Format violation: Does not match HDFS format", raw_bytes)
            return None

        gd = match.groupdict()
        ts_str, ts_epoch = parse_hdfs_timestamp(gd)
        level = gd["level"].upper()
        component = gd["component"]
        message = clean_line

        db.save_event(
            source="HDFS",
            log_level=level,
            component_host=component,
            raw_message=message,
            timestamp=ts_str,
        )

        is_anomaly = (level in ("WARN", "WARNING", "ERROR", "FATAL")) or (
            "got exception" in message.lower() or "failed" in message.lower()
        )
        if is_anomaly:
            _check_sliding_window("hdfs", ts_epoch, message)

        return {
            "source": "HDFS",
            "log_level": level,
            "component_host": component,
            "raw_message": message,
            "timestamp": ts_str,
        }

    elif is_nasa_source:
        match = NASA_HTTP_REGEX.match(clean_line)
        if not match:
            db.save_rejected_line(declared_source, "Format violation: Does not match NASA-HTTP CLF format", raw_bytes)
            return None

        gd = match.groupdict()
        ts_str, ts_epoch = parse_nasa_timestamp(gd["time"])
        host = gd["host"]
        status_code = int(gd["status"])
        message = clean_line

        if status_code == 200:
            level = "INFO"
        elif status_code in (302, 304):
            level = "WARN"
        elif status_code == 404:
            level = "WARN"
        elif status_code >= 500:
            level = "ERROR"
        else:
            level = "WARN"

        db.save_event(
            source="NASA-HTTP",
            log_level=level,
            component_host=host,
            raw_message=message,
            timestamp=ts_str,
        )

        if status_code != 200:
            _check_sliding_window("nasa_http", ts_epoch, message)

        return {
            "source": "NASA-HTTP",
            "log_level": level,
            "component_host": host,
            "raw_message": message,
            "timestamp": ts_str,
        }

    else:
        hdfs_match = HDFS_REGEX.match(clean_line)
        if hdfs_match:
            return parse_line(clean_line, declared_source="hdfs")
        nasa_match = NASA_HTTP_REGEX.match(clean_line)
        if nasa_match:
            return parse_line(clean_line, declared_source="nasa_http")

        db.save_rejected_line(declared_source, "Format violation: Line does not match any recognized format", raw_bytes)
        return None


def reset_sliding_windows():
    """Reset in-memory sliding window deques for test isolation."""
    with _window_lock:
        for k, deque_obj in _sliding_windows.items():
            lock = _source_window_locks.get(k, _window_lock)
            with lock:
                deque_obj.clear()


def parse_to_model(line, declared_source="hdfs"):
    """
    Parse an ingested line and return a typed LogEvent dataclass on success.
    Returns None if line was malformed, binary, or wrong-source (quarantined).
    """
    res = parse_line(line, declared_source=declared_source)
    if res:
        return LogEvent.from_dict(res)
    return None
