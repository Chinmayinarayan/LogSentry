"""
Engine 1: E1 WATCH — Concurrent Log Ingestion and Monitoring Engine.

Responsibilities (FR-01, FR-02, FR-13, NFR-01, NFR-02):
- Bounded shared queue (maxsize=10,000) with blocking backpressure.
- Thread-per-source concurrent live file tailing (`tail -f` equivalent).
- Memory-efficient streaming ingestion for large log files (e.g. 205 MB NASA HTTP log).
- ZIP archive container validation, safe member extraction, and invalid container quarantine.
- Thread-safe ingestion statistics and active watcher registry.
"""

import io
import os
import queue
import threading
import time
import zipfile
from typing import Dict, Any, Union, Optional

from parse import parser

# FR-02, NFR-01: Shared bounded queue (maxsize=10,000 records)
QUEUE_MAXSIZE = 10000
log_queue: queue.Queue = queue.Queue(maxsize=QUEUE_MAXSIZE)

# Memory Bound Constraint: Max individual record size (64 KB).
# With QUEUE_MAXSIZE=10,000, worst-case memory ceiling for the queue buffer is <= 640 MB.
MAX_RECORD_SIZE = 65536

# Thread synchronization primitives (NFR-02)
_events_processed = 0
_events_lock = threading.Lock()
_active_watchers: Dict[str, Any] = {}  # source_name -> (Thread, threading.Event, file_path)
_watchers_lock = threading.Lock()


def _increment_processed(count: int = 1):
    """Thread-safe increment of ingested lines counter."""
    global _events_processed
    with _events_lock:
        _events_processed += count


def reset_metrics():
    """Reset ingestion metrics for test isolation."""
    global _events_processed
    with _events_lock:
        _events_processed = 0


def get_metrics() -> Dict[str, Any]:
    """
    Expose queue size, active watcher thread count, events queued/processed, and queue capacity.
    Called by E4 SIGNAL /api/stats endpoint.
    """
    with _watchers_lock:
        active = len(_active_watchers)
    with _events_lock:
        processed = _events_processed
    return {
        "queue_size": log_queue.qsize(),
        "queue_capacity": QUEUE_MAXSIZE,
        "active_threads": active,
        "events_queued": processed,
        "events_processed": processed,  # Backward compatibility alias
    }


def get_active_watchers() -> Dict[str, Dict[str, Any]]:
    """Return status metadata for all active watcher threads."""
    with _watchers_lock:
        result = {}
        for name, (thread, stop_event, path) in _active_watchers.items():
            result[name] = {
                "source": name,
                "file_path": path,
                "is_alive": thread.is_alive(),
                "stopped": stop_event.is_set(),
            }
        return result


def worker_thread(source_name: str, file_path: str, stop_event: threading.Event):
    """
    Continuous worker thread tailing a live log file (equivalent to `tail -f`).
    FR-01, FR-02:
    - Dedicated thread per live source.
    - Moves to EOF initially to capture incoming continuous records.
    - Zero dropped lines: log_queue.put() blocks when queue reaches maxsize=10,000 (backpressure).
    """
    try:
        directory = os.path.dirname(file_path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
        if not os.path.exists(file_path):
            open(file_path, "a", encoding="utf-8").close()

        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            fh.seek(0, os.SEEK_END)
            while not stop_event.is_set():
                line = fh.readline(MAX_RECORD_SIZE + 1)
                if line:
                    if len(line) > MAX_RECORD_SIZE:
                        parser.parse_line(b"OVERSIZED_RECORD: Line exceeds 64KB limit", declared_source=source_name)
                        fh.readline()  # Flush remainder of oversized line
                        continue
                    clean_line = line.rstrip("\r\n")
                    if clean_line:
                        # Non-blocking backpressure: blocks up to 0.2s then checks stop_event
                        while not stop_event.is_set():
                            try:
                                log_queue.put((source_name, clean_line), timeout=0.2)
                                _increment_processed(1)
                                break
                            except queue.Full:
                                continue
                else:
                    time.sleep(0.1)
    except Exception as exc:
        print(f"[worker_thread] Watcher '{source_name}' error on file '{file_path}': {exc}")


def start_watcher(source_name: str, file_path: str) -> threading.Thread:
    """
    Spawn a dedicated daemon thread that continuously tails file_path for source_name.
    Re-uses existing thread if source_name is already active on the same file.
    """
    with _watchers_lock:
        if source_name in _active_watchers:
            t, stop_event, existing_path = _active_watchers[source_name]
            if t.is_alive():
                print(f"[start_watcher] Watcher for '{source_name}' already active.")
                return t

        stop_event = threading.Event()
        t = threading.Thread(
            target=worker_thread,
            args=(source_name, file_path, stop_event),
            name=f"tailer-{source_name}",
            daemon=True,
        )
        _active_watchers[source_name] = (t, stop_event, file_path)
        t.start()
        return t


def stop_watcher(source_name: str) -> bool:
    """Stop an active tailer thread gracefully by setting its stop event."""
    with _watchers_lock:
        if source_name in _active_watchers:
            t, stop_event, _ = _active_watchers[source_name]
            stop_event.set()
            del _active_watchers[source_name]
            return True
    return False


def stop_all_watchers():
    """Stop all running watcher threads."""
    with _watchers_lock:
        for name, (thread, stop_event, _) in list(_active_watchers.items()):
            stop_event.set()
        _active_watchers.clear()


def ingest_file_stream(source_name: str, file_stream_or_bytes: Union[bytes, io.BytesIO, Any], filename: str = "") -> Dict[str, Any]:
    """
    Ingest a log file stream or raw bytes into the bounded queue.
    FR-01, FR-13:
    - Auto-detects and extracts ZIP containers.
    - Streams lines into log_queue with backpressure.
    - Quarantines invalid ZIP files or binary records via E2 PARSE.
    - Retains full backward compatibility with existing tests and API callers.
    """
    # 1. Determine if input is ZIP archive by extension or PK magic number
    is_zip = False
    raw_head = b""

    if isinstance(file_stream_or_bytes, bytes):
        raw_bytes = file_stream_or_bytes
        raw_head = raw_bytes[:4]
        is_zip = filename.lower().endswith(".zip") or raw_head.startswith(b"PK\x03\x04")
        bio = io.BytesIO(raw_bytes)
    elif hasattr(file_stream_or_bytes, "read"):
        stream = file_stream_or_bytes
        # Read small sample to probe for ZIP header without buffering entire file in memory
        raw_head = stream.read(4)
        stream.seek(0)
        is_zip = filename.lower().endswith(".zip") or raw_head.startswith(b"PK\x03\x04")
        bio = stream
    else:
        return {"status": "error", "message": "Invalid file input type"}

    # 2. Handle ZIP Archives (FR-13)
    if is_zip:
        return _ingest_zip_container(source_name, bio, filename=filename)

    # 3. Handle Standard Text / Log Stream with Streaming (Memory-Efficient)
    return _ingest_text_stream(source_name, bio)


def _ingest_zip_container(source_name: str, stream: Any, filename: str = "") -> Dict[str, Any]:
    """Extract and enqueue log members from a ZIP container. Quarantines invalid archives."""
    try:
        if not zipfile.is_zipfile(stream):
            # Probe failed — invalid or corrupt ZIP
            stream.seek(0)
            corrupt_bytes = stream.read(512)
            parser.parse_line(corrupt_bytes, declared_source=source_name)
            return {"status": "error", "message": "Invalid ZIP container: Corrupted or not a valid archive"}

        stream.seek(0)
        with zipfile.ZipFile(stream) as zf:
            members = [m for m in zf.namelist() if not m.endswith("/")]

            # Security: Path traversal protection
            for m in members:
                normalized = m.replace("\\", "/")
                parts = normalized.split("/")
                if ".." in parts or normalized.startswith("/") or ":" in normalized:
                    parser.parse_line(f"SECURITY_VIOLATION: Directory traversal path in ZIP: {m}".encode("utf-8"), declared_source=source_name)
                    return {"status": "error", "message": f"Security restriction: Directory traversal detected in ZIP member '{m}'"}

            # Resource exhaustion protections (zip bomb mitigation)
            if len(members) > 100:
                return {"status": "error", "message": f"Security restriction: ZIP archive contains {len(members)} files (max limit 100)"}

            total_uncompressed = sum(zf.getinfo(m).file_size for m in members)
            if total_uncompressed > 100 * 1024 * 1024:
                return {"status": "error", "message": f"Security restriction: ZIP uncompressed size {total_uncompressed / (1024*1024):.1f}MB exceeds limit of 100MB"}

            log_members = [m for m in members if m.lower().endswith((".log", ".txt", ".csv"))]
            if not log_members and members:
                log_members = [members[0]]  # Fallback to first non-directory member

            if not log_members:
                return {"status": "error", "message": "ZIP archive contains no readable log files"}

            processed_count = 0
            for member in log_members:
                with zf.open(member, "r") as member_file:
                    text_stream = io.TextIOWrapper(member_file, encoding="utf-8", errors="replace")
                    for line in text_stream:
                        if len(line) > MAX_RECORD_SIZE:
                            parser.parse_line(b"OVERSIZED_RECORD: Line in ZIP exceeds 64KB limit", declared_source=source_name)
                            continue
                        clean_line = line.rstrip("\r\n")
                        if clean_line:
                            log_queue.put((source_name, clean_line))
                            _increment_processed(1)
                            processed_count += 1

            return {"status": "success", "lines_queued": processed_count}

    except Exception as exc:
        # Quarantine invalid zip data via E2 Parser
        try:
            stream.seek(0)
            corrupt_bytes = stream.read(512)
        except Exception:
            corrupt_bytes = b"CORRUPTED_ZIP_STREAM"
        parser.parse_line(corrupt_bytes, declared_source=source_name)
        return {"status": "error", "message": f"Invalid zip file: {exc}"}


def _ingest_text_stream(source_name: str, stream: Any) -> Dict[str, Any]:
    """Stream text lines line-by-line into the queue without loading whole file into memory."""
    try:
        # Wrap stream in TextIOWrapper if binary
        if isinstance(stream, io.BytesIO):
            # Check for binary null-byte probe
            stream.seek(0)
            probe = stream.read(1024)
            if b"\x00" in probe:
                stream.seek(0)
                parser.parse_line(stream.read(), declared_source=source_name)
                return {"status": "rejected", "lines": 1}
            stream.seek(0)
            text_stream = io.TextIOWrapper(stream, encoding="utf-8", errors="replace")
        elif hasattr(stream, "read"):
            text_stream = io.TextIOWrapper(stream, encoding="utf-8", errors="replace")
        else:
            text_stream = stream

        processed_count = 0
        for line in text_stream:
            if len(line) > MAX_RECORD_SIZE:
                parser.parse_line(b"OVERSIZED_RECORD: Line exceeds 64KB limit", declared_source=source_name)
                continue
            clean_line = line.rstrip("\r\n")
            if clean_line and not clean_line.startswith("#"):
                log_queue.put((source_name, clean_line))
                _increment_processed(1)
                processed_count += 1

        return {"status": "success", "lines_queued": processed_count}

    except Exception as exc:
        return {"status": "error", "message": f"Text stream ingestion error: {exc}"}


def ingest_file_path(source_name: str, file_path: str) -> Dict[str, Any]:
    """
    Ingest a file from disk line-by-line (e.g. 205 MB NASA HTTP log or HDFS_2k.log).
    Guarantees $O(1)$ memory usage via line-by-line streaming generator.
    """
    if not os.path.exists(file_path):
        return {"status": "error", "message": f"File not found: {file_path}"}

    # If ZIP, use ingest_file_stream
    if file_path.lower().endswith(".zip"):
        with open(file_path, "rb") as f:
            return ingest_file_stream(source_name, f, filename=os.path.basename(file_path))

    processed_count = 0
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if len(line) > MAX_RECORD_SIZE:
                    parser.parse_line(b"OVERSIZED_RECORD: Line exceeds 64KB limit", declared_source=source_name)
                    continue
                clean_line = line.rstrip("\r\n")
                if clean_line and not clean_line.startswith("#"):
                    log_queue.put((source_name, clean_line))
                    _increment_processed(1)
                    processed_count += 1
        return {"status": "success", "lines_queued": processed_count}
    except Exception as exc:
        return {"status": "error", "message": f"Disk ingestion error: {exc}"}
