# LogSentry — Full Source Code Dump

## 2. FULL SOURCE CODE

Complete current contents of every project source/config/sample file (excluding `venv/` and the binary `.db` file).

### `signal_app.py`

```python
"""Web & Networks Engine — Flask controller for LogSentry."""

import os
import sys
import threading

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import RequestEntityTooLarge

sys.path.insert(0, os.path.dirname(__file__))

from parse.parser import parse_line
from vault.db import (
    get_event_stats,
    get_logs,
    get_recent_alerts,
    get_recent_events,
    get_timeseries,
    init_db,
    reset_events_and_alerts,
    save_upload_history,
)
from watch.tailer import get_metrics, log_queue, start_watcher

app = Flask(__name__, template_folder="signal/templates")
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50MB upload limit

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
os.makedirs(DATA_DIR, exist_ok=True)


def start_monitoring_source(filename, saved_file_path):
    """Queue existing lines, then start an OS-engine watcher thread."""
    try:
        with open(saved_file_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.strip():
                    log_queue.put((filename, line))
    except OSError as exc:
        print(f"[start_monitoring_source] read error: {exc}")
    start_watcher(filename, saved_file_path)


def process_queue():
    """Background consumer: pull lines from log_queue and parse them."""
    while True:
        source, line = log_queue.get()
        try:
            parse_line(line, source)
        except Exception as exc:
            print(f"[process_queue] error: {exc}")
        finally:
            log_queue.task_done()


@app.errorhandler(413)
@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(error):
    return jsonify({"error": "File exceeds the 50MB limit"}), 413


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/upload", methods=["POST"])
def api_upload():
    if "file" not in request.files:
        return jsonify({"error": "No file part in request"}), 400

    uploaded = request.files["file"]
    if not uploaded or not uploaded.filename:
        return jsonify({"error": "No file selected"}), 400

    filename = os.path.basename(uploaded.filename)
    saved_file_path = os.path.join(DATA_DIR, filename)
    uploaded.save(saved_file_path)

    file_size = os.path.getsize(saved_file_path)
    save_upload_history(filename, file_size)

    start_monitoring_source(filename, saved_file_path)

    return jsonify(
        {
            "status": "success",
            "message": "File uploaded and thread started",
            "filename": filename,
            "file_size": file_size,
        }
    )


@app.route("/api/reset", methods=["POST"])
def api_reset():
    """Clear events and alerts so testing starts fresh at 0."""
    reset_events_and_alerts()
    return jsonify(
        {
            "status": "success",
            "message": "Events and alerts cleared",
            "total_events": 0,
            "active_alerts": 0,
        }
    )


@app.route("/api/metrics/timeseries", methods=["GET"])
def api_metrics_timeseries():
    """Event counts grouped by minute for Chart.js."""
    return jsonify(get_timeseries())


@app.route("/api/logs", methods=["GET"])
def api_logs():
    """Structured event logs for the dashboard table (supports search/severity)."""
    limit = request.args.get("limit", 200, type=int)
    search = request.args.get("search", "", type=str) or None
    severity = request.args.get("severity", "", type=str) or None
    if severity and severity.upper() in ("", "ALL", "*"):
        severity = None
    events = get_logs(limit=limit, search=search, severity=severity)
    return jsonify(
        {
            "events": events,
            "filters": {
                "search": search or "",
                "severity": severity or "",
            },
        }
    )


@app.route("/api/stats")
def api_stats():
    db_stats = get_event_stats()
    runtime = get_metrics()
    return jsonify(
        {
            "total_events": db_stats["total_events"],
            "errors": db_stats["errors"],
            "active_alerts": db_stats["active_alerts"],
            "active_threads": runtime["active_threads"],
            "queue_size": runtime["queue_size"],
            "events_processed": runtime["events_processed"],
        }
    )


@app.route("/api/events")
def api_events():
    return jsonify(get_recent_events(limit=100))


@app.route("/api/alerts")
def api_alerts():
    return jsonify(get_recent_alerts(limit=50))



@app.route("/api/simulate-auth-failure", methods=["POST", "GET"])
@app.route("/simulate", methods=["POST", "GET"])
def api_simulate_auth_failure():
    """Push 5 fake failed-login lines to trigger the sliding-window alert."""
    fake_lines = [
        "[ERROR] authentication failed for user admin from 10.0.0.1",
        "[ERROR] Failed login attempt for user root",
        "[ERROR] authentication failed — invalid password",
        "[ERROR] Failed login for user guest",
        "[ERROR] auth failure: bad credentials for user operator",
    ]
    for line in fake_lines:
        log_queue.put(("simulator", line))
    return jsonify(
        {
            "status": "ok",
            "queued": len(fake_lines),
            "message": "Queued 5 fake auth failures for sliding-window detection",
        }
    )


if __name__ == "__main__":
    init_db()

    sample_log = os.path.join(os.path.dirname(__file__), "data", "sample.log")
    start_watcher("server1", sample_log)

    consumer = threading.Thread(
        target=process_queue, name="queue-consumer", daemon=True
    )
    consumer.start()

    app.run(host="0.0.0.0", port=5050, debug=False, use_reloader=False)
```

### `seed.py`

```python
﻿import sys
sys.path.insert(0, '.')
from parse.parser import parse_line, SlidingWindowDetector
from vault.db import get_connection, insert_event, insert_alert

conn = get_connection()
detector = SlidingWindowDetector()

with open('data/sample.log') as f:
    for line in f:
        event = parse_line(line, source='server1')
        insert_event(conn, event['timestamp'], event['severity'], event['category'], event['source'], event['message'])
        if event['severity'] in ('ERROR', 'FATAL') and detector.record(event['category']):
            insert_alert(conn, event['timestamp'], event['category'], detector.threshold,
                         f"Spike detected in category '{event['category']}'")
```

### `requirements.txt`

```text
flask
flask-socketio
python-socketio
eventlet
```

### `README.md`

```markdown
# LogSentry - quick start

pip install -r requirements.txt
python vault/db.py
python -c "
import sys; sys.path.insert(0, '.')
from parse.parser import parse_line, SlidingWindowDetector
from vault.db import get_connection, insert_event, insert_alert
conn = get_connection()
detector = SlidingWindowDetector()
with open('data/sample.log') as f:
    for line in f:
        event = parse_line(line, source='server1')
        insert_event(conn, event['timestamp'], event['severity'], event['category'], event['source'], event['message'])
        if event['severity'] in ('ERROR','FATAL') and detector.record(event['category']):
            insert_alert(conn, event['timestamp'], event['category'], detector.threshold, f\"Spike detected in category '{event['category']}'\")
"
python signal_app.py
# then open http://localhost:5050
```

### `.cursorrules`

```text
# Master Cursor Architecture Context & Rules File
# Project: LogSentry — Multi-threaded Log Analysis & Alerting System (Theme 5)

## 1. Project Mandate & Academic Context
- **Theme Selection:** Theme 5: Multi-threaded Log Analysis & Alerting System[cite: 1].
- **Team Size:** 4 third-year students building a resume-grade, enterprise-ready Security Information and Event Management (SIEM) application[cite: 1].
- **Evaluation Framework:** Compliant with a Hybrid SDLC 4-Engine, 5-Gate evaluation rubric (spanning problem definition, functional requirements, shared architecture, implementation, validation, and root cause analysis)[cite: 1].

## 2. The 4-Engine Architectural Model
Every feature and component must align cleanly with one of these four core computer science domains[cite: 1]:
* **OS Engine:** Multithreaded log tailers (`watch/tailer.py`), background worker thread pools, thread-safe synchronization queues, and bounded concurrency protection[cite: 1].
* **DSA Engine:** Sliding-window anomaly detection algorithms, regular expression pattern matchers, and real-time threshold telemetry[cite: 1].
* **DBMS Engine:** Append-only SQLite database vaults (`logsentry.db`), audit trail tables (`upload_history`), and persistent state tracking[cite: 1].
* **Web & Networks Engine:** Flask RESTful API endpoints (`/api/reset`, `/api/metrics/timeseries`, `/api/logs`, `/api/upload`), async polling loops, and a dark-themed SOC dashboard with live Chart.js visualizations[cite: 1].

## 3. Current Implementation Status & Objective
- **Stable Core:** Backend APIs, append-only SQLite storage, and sliding-window alerts are fully operational.
- **Current Focus:** Elevating the frontend interface, refining modern file selection components, optimizing chart rendering, and ensuring strict visual and architectural polish for the college viva[cite: 1].

## 4. Coding Instructions for Cursor
- When writing code or modifying files, preserve the decoupled architecture where Flask serves as a JSON API backend and the HTML/JS dashboard consumes telemetry asynchronously.
- Avoid breaking existing database schemas or route names unless explicitly instructed.
- Maintain production-grade clean code practices suitable for technical interviews and formal academic evaluation[cite: 1].
```

### `vault/db.py`

```python
"""DBMS Engine — SQLite persistence for events, alerts, sources, and rules."""

import os
import sqlite3
import threading
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "logsentry.db")
_lock = threading.Lock()


def get_db_connection():
    """Open a SQLite connection with Row factory enabled."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create events, alerts, log_sources, and detection_rules tables."""
    conn = get_db_connection()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            severity TEXT NOT NULL,
            category TEXT NOT NULL,
            source TEXT,
            message TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            source TEXT,
            message TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS log_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            file_path TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS detection_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            category TEXT NOT NULL,
            window_seconds INTEGER NOT NULL,
            threshold INTEGER NOT NULL,
            enabled INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS upload_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_events_category ON events(category);
        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
        CREATE INDEX IF NOT EXISTS idx_upload_history_timestamp ON upload_history(timestamp);

        INSERT OR IGNORE INTO detection_rules (name, category, window_seconds, threshold)
        VALUES ('auth_failure_burst', 'auth_failure', 10, 5);
        """
    )
    conn.commit()
    conn.close()
    print("Database initialized at", DB_PATH)


def save_event(severity, category, source, message):
    """Persist a parsed log event and return its row id."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _lock:
        conn = get_db_connection()
        cur = conn.execute(
            "INSERT INTO events (timestamp, severity, category, source, message) "
            "VALUES (?, ?, ?, ?, ?)",
            (timestamp, severity, category, source, message),
        )
        conn.commit()
        event_id = cur.lastrowid
        conn.close()
    return event_id


def save_alert(alert_type, category, severity, source, message):
    """Persist a detection alert and return its row id."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _lock:
        conn = get_db_connection()
        cur = conn.execute(
            "INSERT INTO alerts (timestamp, alert_type, category, severity, source, message) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (timestamp, alert_type, category, severity, source, message),
        )
        conn.commit()
        alert_id = cur.lastrowid
        conn.close()
    return alert_id


def get_recent_events(limit=100):
    """Return the most recent events as dicts."""
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_recent_alerts(limit=50):
    """Return the most recent alerts as dicts."""
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_event_stats():
    """Aggregate counts used by the dashboard metrics API."""
    conn = get_db_connection()
    total_events = conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]
    errors = conn.execute(
        "SELECT COUNT(*) AS c FROM events WHERE severity IN ('ERROR', 'FATAL')"
    ).fetchone()["c"]
    active_alerts = conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]
    conn.close()
    return {
        "total_events": total_events,
        "errors": errors,
        "active_alerts": active_alerts,
    }


def reset_events_and_alerts():
    """Clear events and alerts so testing can start from zero."""
    with _lock:
        conn = get_db_connection()
        conn.execute("DELETE FROM events")
        conn.execute("DELETE FROM alerts")
        conn.execute("DELETE FROM sqlite_sequence WHERE name IN ('events', 'alerts')")
        conn.commit()
        conn.close()
    return {"events": 0, "alerts": 0}


def get_timeseries():
    """
    Event/error counts grouped by minute for Chart.js.
    Shape matches the dashboard: totals + timeline.
    """
    conn = get_db_connection()
    rows = conn.execute(
        """
        SELECT
            substr(timestamp, 1, 16) AS minute,
            COUNT(*) AS events,
            SUM(
                CASE
                    WHEN severity IN ('ERROR', 'FATAL')
                      OR category = 'auth_failure'
                    THEN 1 ELSE 0
                END
            ) AS errors
        FROM events
        GROUP BY minute
        ORDER BY minute ASC
        """
    ).fetchall()
    stats = get_event_stats()
    conn.close()

    labels = [row["minute"] for row in rows]
    events = [row["events"] for row in rows]
    errors = [int(row["errors"] or 0) for row in rows]

    return {
        "totals": {
            "events": stats["total_events"],
            "errors": stats["errors"],
            "alerts": stats["active_alerts"],
        },
        "timeline": {
            "labels": labels,
            "events": events,
            "errors": errors,
        },
        # Backward-compatible fields
        "labels": labels,
        "data": events,
        "points": [
            {"timestamp": label, "count": count}
            for label, count in zip(labels, events)
        ],
    }


def get_logs(limit=200, search=None, severity=None):
    """Structured event logs with optional search and severity filters."""
    conn = get_db_connection()
    clauses = []
    params = []

    if search:
        term = f"%{search.strip()}%"
        clauses.append(
            "(message LIKE ? OR source LIKE ? OR category LIKE ? OR severity LIKE ?)"
        )
        params.extend([term, term, term, term])

    if severity:
        sev = severity.strip().upper()
        if sev == "WARN":
            clauses.append("UPPER(severity) IN ('WARN', 'WARNING')")
        else:
            clauses.append("UPPER(severity) = ?")
            params.append(sev)

    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = (
        "SELECT id, timestamp, severity, category, source, message "
        f"FROM events {where_sql} "
        "ORDER BY id DESC LIMIT ?"
    )
    params.append(limit)
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def save_upload_history(filename, file_size):
    """Record an ingested file name, size, and timestamp."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _lock:
        conn = get_db_connection()
        cur = conn.execute(
            "INSERT INTO upload_history (filename, file_size, timestamp) VALUES (?, ?, ?)",
            (filename, int(file_size), timestamp),
        )
        conn.commit()
        row_id = cur.lastrowid
        conn.close()
    return row_id


def get_upload_history(limit=50):
    """Return recent upload history rows."""
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT * FROM upload_history ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


if __name__ == "__main__":
    init_db()
```

### `vault/schema.sql`

```sql
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    source TEXT,
    message TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    category TEXT NOT NULL,
    count INTEGER NOT NULL,
    message TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_events_category ON events(category);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
```

### `vault/__init__.py`

```python
(empty file)
```

### `parse/parser.py`

```python
"""DSA Engine — Regex parsing and sliding-window anomaly detection."""

import re
import time
from collections import deque

from vault import db

WINDOW_SECONDS = 10
THRESHOLD = 5

# Sliding windows keyed by category — timestamps of recent matching events
sliding_windows = {
    "auth_failure": deque(),
}

SEVERITY_PATTERN = re.compile(r"\[(INFO|WARN|WARNING|ERROR|FATAL)\]", re.I)
CATEGORY_RULES = [
    (re.compile(r"failed login|authentication failed|auth.?fail", re.I), "auth_failure"),
    (re.compile(r"connection refused|timeout|unreachable", re.I), "network_failure"),
    (re.compile(r"disk full|no space left", re.I), "storage_failure"),
    (re.compile(r"outofmemory|heap space", re.I), "resource_exhaustion"),
]


def _extract_severity(line):
    match = SEVERITY_PATTERN.search(line)
    return match.group(1).upper() if match else "INFO"


def _extract_category(line):
    for pattern, category in CATEGORY_RULES:
        if pattern.search(line):
            return category
    return "uncategorized"


def _check_sliding_window(category, source, message):
    """If 5 auth_failure events occur within 10 seconds, raise an alert."""
    if category not in sliding_windows:
        return

    now = time.time()
    window = sliding_windows[category]
    window.append(now)

    # Drop timestamps outside the window
    while window and now - window[0] > WINDOW_SECONDS:
        window.popleft()

    if len(window) >= THRESHOLD:
        db.save_alert(
            alert_type="sliding_window",
            category=category,
            severity="CRITICAL",
            source=source,
            message=(
                f"Anomaly: {THRESHOLD}+ '{category}' events within "
                f"{WINDOW_SECONDS}s — last: {message}"
            ),
        )
        window.clear()


def parse_line(line, source):
    """
    Parse a raw log line with regex, persist the event, and run
    sliding-window detection for auth_failure bursts.
    """
    message = line.strip()
    if not message:
        return None

    severity = _extract_severity(message)
    category = _extract_category(message)

    db.save_event(severity, category, source, message)
    _check_sliding_window(category, source, message)

    return {
        "severity": severity,
        "category": category,
        "source": source,
        "message": message,
    }
```

### `parse/rules.py`

```python
import re

CATEGORY_RULES = [
    (re.compile(r"failed login|authentication failed", re.I), "auth_failure"),
    (re.compile(r"connection refused|timeout|unreachable", re.I), "network_failure"),
    (re.compile(r"disk full|no space left", re.I), "storage_failure"),
    (re.compile(r"outofmemory|heap space", re.I), "resource_exhaustion"),
]

SEVERITY_PATTERN = re.compile(r"\[(INFO|WARN|WARNING|ERROR|FATAL)\]", re.I)
TIMESTAMP_PATTERN = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")


def categorize(message: str) -> str:
    for pattern, category in CATEGORY_RULES:
        if pattern.search(message):
            return category
    return "uncategorized"


def extract_severity(line: str) -> str:
    match = SEVERITY_PATTERN.search(line)
    return match.group(1).upper() if match else "INFO"


def extract_timestamp(line: str) -> str:
    match = TIMESTAMP_PATTERN.search(line)
    return match.group(1) if match else ""
```

### `parse/__init__.py`

```python
(empty file)
```

### `watch/tailer.py`

```python
"""OS Engine — Multithreaded log file watchers feeding a shared queue."""

import os
import queue
import threading
import time

log_queue = queue.Queue()

_events_processed = 0
_events_lock = threading.Lock()
_active_workers = 0
_workers_lock = threading.Lock()


def _increment_processed():
    global _events_processed
    with _events_lock:
        _events_processed += 1


def worker_thread(source_name, file_path):
    """
    Tail a log file and push (source_name, line) tuples onto log_queue.
    Creates the file if missing, then follows new lines like `tail -f`.
    """
    global _active_workers

    with _workers_lock:
        _active_workers += 1

    try:
        directory = os.path.dirname(file_path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
        if not os.path.exists(file_path):
            open(file_path, "a", encoding="utf-8").close()

        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            # Start at end so we only process newly appended lines
            fh.seek(0, os.SEEK_END)
            while True:
                line = fh.readline()
                if line:
                    log_queue.put((source_name, line))
                    _increment_processed()
                else:
                    time.sleep(0.25)
    finally:
        with _workers_lock:
            _active_workers -= 1


def start_watcher(source_name, file_path):
    """Spawn a daemon thread that tails file_path for source_name."""
    t = threading.Thread(
        target=worker_thread,
        args=(source_name, file_path),
        name=f"tailer-{source_name}",
        daemon=True,
    )
    t.start()
    return t


def get_metrics():
    """Expose queue size, active thread count, and events processed."""
    with _workers_lock:
        active = _active_workers
    with _events_lock:
        processed = _events_processed
    return {
        "queue_size": log_queue.qsize(),
        "active_threads": active,
        "events_processed": processed,
    }
```

### `watch/__init__.py`

```python
(empty file)
```

### `signal/templates/dashboard.html`

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LogSentry — Live Monitoring Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --bg: #0f1117;
            --panel: #161b22;
            --border: #30363d;
            --text: #c9d1d9;
            --muted: #8b949e;
            --red: #f85149;
            --blue: #58a6ff;
            --green: #3fb950;
            --amber: #d29922;
        }

        * { box-sizing: border-box; }

        body {
            background: var(--bg);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 24px;
            line-height: 1.45;
        }

        .page-header {
            display: flex;
            flex-wrap: wrap;
            align-items: baseline;
            justify-content: space-between;
            gap: 12px;
            margin-bottom: 18px;
        }

        h1 {
            font-size: 24px;
            color: #fff;
            margin: 0;
            letter-spacing: -0.02em;
        }

        .subtitle {
            color: var(--muted);
            font-size: 13px;
            margin: 0;
        }

        h2 {
            font-size: 15px;
            color: #fff;
            margin: 0 0 12px;
            font-weight: 600;
        }

        .status-bar {
            min-height: 20px;
            margin: 0 0 16px;
            color: var(--muted);
            font-size: 13px;
        }

        .status-bar.ok { color: var(--green); }
        .status-bar.err { color: var(--red); }
        .status-bar.busy { color: var(--amber); }

        .controls {
            display: flex;
            gap: 12px;
            margin-bottom: 20px;
            align-items: center;
            flex-wrap: wrap;
            background: var(--panel);
            padding: 14px 16px;
            border: 1px solid var(--border);
            border-radius: 8px;
        }

        button {
            background: #21262d;
            color: var(--text);
            border: 1px solid var(--border);
            padding: 9px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 500;
            font-size: 14px;
            transition: background 0.15s ease, border-color 0.15s ease, opacity 0.15s ease;
            white-space: nowrap;
        }

        button:hover:not(:disabled) { background: #30363d; }
        button:disabled { opacity: 0.55; cursor: wait; }

        .btn-sim {
            background: #f85149;
            color: #fff;
            border: none;
        }
        .btn-sim:hover:not(:disabled) { background: #da3633; }

        .btn-upload {
            background: #1f6feb;
            color: #fff;
            border: none;
        }
        .btn-upload:hover:not(:disabled) { background: #1a60d0; }

        .btn-reset {
            background: #21262d;
            color: var(--red);
            border: 1px solid var(--red);
            margin-left: auto;
        }
        .btn-reset:hover:not(:disabled) { background: rgba(248, 81, 73, 0.1); }

        /* Custom drop-zone file picker */
        .dropzone {
            position: relative;
            display: flex;
            align-items: center;
            gap: 10px;
            min-width: 260px;
            max-width: 360px;
            min-height: 42px;
            padding: 8px 14px;
            background: #0d1117;
            border: 1px dashed var(--border);
            border-radius: 6px;
            cursor: pointer;
            transition: border-color 0.15s ease, background 0.15s ease;
            overflow: hidden;
        }

        .dropzone:hover,
        .dropzone.dragover {
            border-color: var(--blue);
            background: rgba(88, 166, 255, 0.06);
        }

        .dropzone.has-file {
            border-style: solid;
            border-color: var(--blue);
        }

        .dropzone input[type="file"] {
            position: absolute;
            inset: 0;
            opacity: 0;
            cursor: pointer;
            width: 100%;
            height: 100%;
        }

        .dropzone-icon { font-size: 16px; flex-shrink: 0; }

        .dropzone-meta {
            display: flex;
            flex-direction: column;
            gap: 2px;
            min-width: 0;
            pointer-events: none;
        }

        .dropzone-title {
            color: var(--muted);
            font-size: 13px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .dropzone.has-file .dropzone-title { color: var(--blue); font-weight: 500; }

        .dropzone-sub {
            color: var(--muted);
            font-size: 11px;
            min-height: 14px;
        }

        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin-bottom: 20px;
        }

        .metric-card {
            background: var(--panel);
            border: 1px solid var(--border);
            padding: 18px 20px;
            border-radius: 8px;
        }

        .metric-card h3 {
            margin: 0;
            font-size: 12px;
            color: var(--muted);
            text-transform: uppercase;
            letter-spacing: 0.04em;
            font-weight: 600;
        }

        .metric-card .value {
            font-size: 28px;
            font-weight: 700;
            color: #fff;
            margin-top: 6px;
            font-variant-numeric: tabular-nums;
            min-height: 34px;
        }

        .charts-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 24px;
        }

        .chart-panel {
            background: var(--panel);
            border: 1px solid var(--border);
            padding: 14px 16px 10px;
            border-radius: 8px;
            display: flex;
            flex-direction: column;
            min-width: 0;
        }

        .chart-panel h3 {
            margin: 0 0 10px;
            font-size: 13px;
            color: var(--muted);
            text-transform: uppercase;
            letter-spacing: 0.03em;
            font-weight: 600;
        }

        .chart-canvas-wrap {
            position: relative;
            width: 100%;
            height: 250px;
            max-height: 250px;
        }

        .chart-canvas-wrap canvas {
            width: 100% !important;
            height: 100% !important;
        }

        .table-panel {
            background: var(--panel);
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow: hidden;
            margin-bottom: 20px;
        }

        .table-panel > h2 {
            margin: 0;
            padding: 14px 16px 10px;
            border-bottom: 1px solid var(--border);
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin: 0;
        }

        th, td {
            padding: 11px 14px;
            text-align: left;
            border-bottom: 1px solid var(--border);
            font-size: 13px;
            vertical-align: top;
        }

        th {
            background: #1f242c;
            color: var(--muted);
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            font-weight: 600;
        }

        tbody tr:last-child td { border-bottom: none; }
        tbody tr:hover { background: rgba(255, 255, 255, 0.02); }

        .empty-row td {
            color: var(--muted);
            text-align: center;
            padding: 22px;
        }

        .badge-critical {
            background: rgba(248, 81, 73, 0.15);
            color: var(--red);
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: 700;
            font-size: 12px;
        }

        .sev-ERROR, .sev-FATAL { color: var(--red); font-weight: 600; }
        .sev-WARN, .sev-WARNING { color: var(--amber); }
        .sev-INFO { color: var(--blue); }

        .msg-cell {
            max-width: 420px;
            word-break: break-word;
        }

        .logs-toolbar {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            align-items: center;
            padding: 12px 16px;
            border-bottom: 1px solid var(--border);
            background: #0d1117;
        }

        .logs-toolbar input[type="search"],
        .logs-toolbar select {
            background: #21262d;
            color: var(--text);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 8px 12px;
            font-size: 13px;
            outline: none;
        }

        .logs-toolbar input[type="search"] {
            flex: 1;
            min-width: 180px;
        }

        .logs-toolbar input[type="search"]:focus,
        .logs-toolbar select:focus {
            border-color: var(--blue);
        }

        .logs-toolbar select {
            min-width: 140px;
            cursor: pointer;
        }

        .filter-hint {
            color: var(--muted);
            font-size: 12px;
            margin-left: auto;
        }

        @media (max-width: 960px) {
            .metrics-grid,
            .charts-grid { grid-template-columns: 1fr; }
            .btn-reset { margin-left: 0; }
            .dropzone { max-width: 100%; width: 100%; }
            .filter-hint { margin-left: 0; width: 100%; }
        }
    </style>
</head>
<body>
    <div class="page-header">
        <h1>LogSentry — Live Monitoring Dashboard</h1>
        <p class="subtitle">Theme 5 · Multi-threaded Log Analysis &amp; Alerting · SOC Command Center</p>
    </div>

    <div id="statusBar" class="status-bar" aria-live="polite"></div>

    <div class="controls">
        <button type="button" class="btn-sim" id="btnSimulate" onclick="simulateAttack()">Simulate Auth Failures</button>

        <div class="dropzone" id="dropzone" title="Select a .log or .txt file">
            <span class="dropzone-icon" id="dropIcon">📁</span>
            <div class="dropzone-meta">
                <span class="dropzone-title" id="fileLabel">Select log file (.log, .txt)</span>
                <span class="dropzone-sub" id="fileMeta">Max 50MB · drag &amp; drop or click</span>
            </div>
            <input type="file" id="logFileInput" accept=".log,.txt,text/plain" onchange="handleFileSelection(this)">
        </div>

        <button type="button" class="btn-upload" id="btnUpload" onclick="uploadLogFile()">Upload Log File</button>
        <button type="button" class="btn-reset" id="btnReset" onclick="resetDatabase()">Reset Dashboard</button>
    </div>

    <div class="metrics-grid">
        <div class="metric-card">
            <h3>Total Events</h3>
            <div class="value" id="totalEvents">0</div>
        </div>
        <div class="metric-card">
            <h3>Errors</h3>
            <div class="value" id="errorCount">0</div>
        </div>
        <div class="metric-card">
            <h3>Active Threads</h3>
            <div class="value" id="activeThreads">0</div>
        </div>
        <div class="metric-card">
            <h3>Active Alerts</h3>
            <div class="value" id="activeAlerts">0</div>
        </div>
    </div>

    <div class="charts-grid">
        <div class="chart-panel">
            <h3>Events Over Time</h3>
            <div class="chart-canvas-wrap">
                <canvas id="eventsOverTimeChart"></canvas>
            </div>
        </div>
        <div class="chart-panel">
            <h3>Error Spikes</h3>
            <div class="chart-canvas-wrap">
                <canvas id="errorSpikeChart"></canvas>
            </div>
        </div>
    </div>

    <div class="table-panel">
        <h2>Alerts</h2>
        <table id="alertsTable">
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Type</th>
                    <th>Category</th>
                    <th>Severity</th>
                    <th>Source</th>
                    <th>Message</th>
                </tr>
            </thead>
            <tbody></tbody>
        </table>
    </div>

    <div class="table-panel">
        <h2>Recent Events</h2>
        <div class="logs-toolbar">
            <input
                type="search"
                id="logSearch"
                placeholder="Search logs (message, source, category…)"
                autocomplete="off"
            >
            <select id="severityFilter" aria-label="Filter by severity">
                <option value="">All severities</option>
                <option value="INFO">INFO</option>
                <option value="WARN">WARN</option>
                <option value="ERROR">ERROR</option>
                <option value="FATAL">FATAL</option>
            </select>
            <span class="filter-hint" id="filterHint">Showing latest events</span>
        </div>
        <table id="logsTable">
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Severity</th>
                    <th>Category</th>
                    <th>Source</th>
                    <th>Message</th>
                </tr>
            </thead>
            <tbody></tbody>
        </table>
    </div>

    <script>
        let lineChart = null;
        let barChart = null;
        let polling = false;

        const chartOptions = {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 280 },
            plugins: {
                legend: {
                    labels: { color: '#8b949e', boxWidth: 12, font: { size: 11 } }
                }
            },
            scales: {
                x: {
                    ticks: { color: '#8b949e', maxRotation: 45, autoSkip: true, maxTicksLimit: 8 },
                    grid: { color: 'rgba(48, 54, 61, 0.6)' }
                },
                y: {
                    beginAtZero: true,
                    ticks: { color: '#8b949e', precision: 0 },
                    grid: { color: 'rgba(48, 54, 61, 0.6)' }
                }
            }
        };

        function setStatus(message, kind) {
            const el = document.getElementById('statusBar');
            el.textContent = message || '';
            el.className = 'status-bar' + (kind ? ' ' + kind : '');
        }

        function formatBytes(bytes) {
            if (!Number.isFinite(bytes) || bytes < 0) return '';
            if (bytes < 1024) return bytes + ' B';
            if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
            return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
        }

        function escapeHtml(value) {
            const div = document.createElement('div');
            div.textContent = value == null ? '' : String(value);
            return div.innerHTML;
        }

        function initCharts() {
            const lineCtx = document.getElementById('eventsOverTimeChart').getContext('2d');
            lineChart = new Chart(lineCtx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Events',
                        data: [],
                        borderColor: '#58a6ff',
                        backgroundColor: 'rgba(88, 166, 255, 0.12)',
                        tension: 0.25,
                        fill: true,
                        pointRadius: 2,
                        pointHoverRadius: 4,
                        borderWidth: 2
                    }]
                },
                options: chartOptions
            });

            const barCtx = document.getElementById('errorSpikeChart').getContext('2d');
            barChart = new Chart(barCtx, {
                type: 'bar',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Errors / auth_failure',
                        data: [],
                        backgroundColor: 'rgba(248, 81, 73, 0.75)',
                        borderColor: '#f85149',
                        borderWidth: 1,
                        borderRadius: 3,
                        maxBarThickness: 28
                    }]
                },
                options: chartOptions
            });
        }

        function wireDropzone() {
            const zone = document.getElementById('dropzone');
            ['dragenter', 'dragover'].forEach(evt => {
                zone.addEventListener(evt, e => {
                    e.preventDefault();
                    e.stopPropagation();
                    zone.classList.add('dragover');
                });
            });
            ['dragleave', 'drop'].forEach(evt => {
                zone.addEventListener(evt, e => {
                    e.preventDefault();
                    e.stopPropagation();
                    zone.classList.remove('dragover');
                });
            });
            zone.addEventListener('drop', e => {
                const input = document.getElementById('logFileInput');
                const files = e.dataTransfer && e.dataTransfer.files;
                if (!files || !files.length) return;
                const dt = new DataTransfer();
                dt.items.add(files[0]);
                input.files = dt.files;
                handleFileSelection(input);
            });
        }

        function handleFileSelection(input) {
            const zone = document.getElementById('dropzone');
            const label = document.getElementById('fileLabel');
            const meta = document.getElementById('fileMeta');
            const icon = document.getElementById('dropIcon');

            if (input.files && input.files.length > 0) {
                const file = input.files[0];
                zone.classList.add('has-file');
                icon.textContent = '📄';
                label.textContent = file.name;
                meta.textContent = formatBytes(file.size) + ' selected';
            } else {
                zone.classList.remove('has-file');
                icon.textContent = '📁';
                label.textContent = 'Select log file (.log, .txt)';
                meta.textContent = 'Max 50MB · drag & drop or click';
            }
        }

        function resetFilePicker() {
            const input = document.getElementById('logFileInput');
            input.value = '';
            handleFileSelection(input);
        }

        function setBusy(buttonIds, busy) {
            buttonIds.forEach(id => {
                const btn = document.getElementById(id);
                if (btn) btn.disabled = !!busy;
            });
        }

        function updateChartsFromPayload(data) {
            if (!lineChart || !barChart || !data) return;

            const timeline = data.timeline || {};
            const labels = timeline.labels || data.labels || [];
            const events = timeline.events || data.data || [];
            const errors = timeline.errors || [];

            lineChart.data.labels = labels;
            lineChart.data.datasets[0].data = events;
            lineChart.update('none');

            barChart.data.labels = labels;
            barChart.data.datasets[0].data = errors.length ? errors : events;
            barChart.update('none');
        }

        function renderAlerts(alerts) {
            const tbody = document.querySelector('#alertsTable tbody');
            tbody.innerHTML = '';

            if (!alerts || !alerts.length) {
                tbody.innerHTML = '<tr class="empty-row"><td colspan="6">No active alerts</td></tr>';
                return;
            }

            alerts.forEach(a => {
                const severity = a.severity || '';
                const severityHtml = String(severity).toUpperCase() === 'CRITICAL'
                    ? `<span class="badge-critical">${escapeHtml(severity)}</span>`
                    : escapeHtml(severity);
                const tr = document.createElement('tr');
                tr.innerHTML =
                    `<td>${escapeHtml(a.timestamp)}</td>` +
                    `<td>${escapeHtml(a.alert_type)}</td>` +
                    `<td>${escapeHtml(a.category)}</td>` +
                    `<td>${severityHtml}</td>` +
                    `<td>${escapeHtml(a.source)}</td>` +
                    `<td class="msg-cell">${escapeHtml(a.message)}</td>`;
                tbody.appendChild(tr);
            });
        }

        function renderLogs(events) {
            const tbody = document.querySelector('#logsTable tbody');
            tbody.innerHTML = '';

            if (!events || !events.length) {
                tbody.innerHTML = '<tr class="empty-row"><td colspan="5">No matching events</td></tr>';
                return;
            }

            events.slice(0, 50).forEach(ev => {
                const sev = ev.severity || '';
                const tr = document.createElement('tr');
                tr.innerHTML =
                    `<td>${escapeHtml(ev.timestamp)}</td>` +
                    `<td class="sev-${escapeHtml(sev)}">${escapeHtml(sev)}</td>` +
                    `<td>${escapeHtml(ev.category)}</td>` +
                    `<td>${escapeHtml(ev.source)}</td>` +
                    `<td class="msg-cell">${escapeHtml(ev.message)}</td>`;
                tbody.appendChild(tr);
            });
        }

        function getLogFilters() {
            const search = (document.getElementById('logSearch')?.value || '').trim();
            const severity = (document.getElementById('severityFilter')?.value || '').trim();
            return { search, severity };
        }

        function updateFilterHint(count, filters) {
            const hint = document.getElementById('filterHint');
            if (!hint) return;
            const parts = [];
            if (filters.search) parts.push(`search "${filters.search}"`);
            if (filters.severity) parts.push(`severity ${filters.severity}`);
            if (parts.length) {
                hint.textContent = `${count} match${count === 1 ? '' : 'es'} · ${parts.join(' · ')}`;
            } else {
                hint.textContent = `Showing latest ${count} event${count === 1 ? '' : 's'}`;
            }
        }

        async function fetchFilteredLogs() {
            const filters = getLogFilters();
            const params = new URLSearchParams();
            params.set('limit', '100');
            if (filters.search) params.set('search', filters.search);
            if (filters.severity) params.set('severity', filters.severity);

            try {
                const res = await fetch(`/api/logs?${params.toString()}`);
                if (!res.ok) return;
                const logsData = await res.json();
                const events = logsData.events || [];
                renderLogs(events);
                updateFilterHint(events.length, filters);
            } catch (err) {
                console.error('Log filter fetch failed:', err);
            }
        }

        let filterDebounce = null;
        function onLogFilterChanged() {
            clearTimeout(filterDebounce);
            filterDebounce = setTimeout(fetchFilteredLogs, 200);
        }

        async function updateDashboard() {
            if (polling) return;
            polling = true;
            try {
                const [statsRes, tsRes, alertsRes] = await Promise.all([
                    fetch('/api/stats'),
                    fetch('/api/metrics/timeseries'),
                    fetch('/api/alerts')
                ]);

                if (statsRes.ok) {
                    const stats = await statsRes.json();
                    document.getElementById('activeThreads').textContent = stats.active_threads ?? 0;
                }

                if (tsRes.ok) {
                    const data = await tsRes.json();
                    if (data.totals) {
                        document.getElementById('totalEvents').textContent = data.totals.events ?? 0;
                        document.getElementById('errorCount').textContent = data.totals.errors ?? 0;
                        document.getElementById('activeAlerts').textContent = data.totals.alerts ?? 0;
                    }
                    updateChartsFromPayload(data);
                }

                if (alertsRes.ok) {
                    renderAlerts(await alertsRes.json());
                }

                // Keep current search/severity filters applied while polling
                await fetchFilteredLogs();
            } catch (err) {
                console.error('Polling error:', err);
            } finally {
                polling = false;
            }
        }

        async function resetDatabase() {
            if (!confirm('Are you sure you want to clear all logs, events, and metrics?')) return;
            setBusy(['btnReset', 'btnUpload', 'btnSimulate'], true);
            setStatus('Clearing vault…', 'busy');
            try {
                const res = await fetch('/api/reset', { method: 'POST' });
                if (res.ok) {
                    setStatus('Dashboard reset complete.', 'ok');
                    location.reload();
                    return;
                }
                setStatus('Reset failed.', 'err');
            } catch (err) {
                setStatus('Reset request failed.', 'err');
            } finally {
                setBusy(['btnReset', 'btnUpload', 'btnSimulate'], false);
            }
        }

        async function simulateAttack() {
            setBusy(['btnSimulate'], true);
            setStatus('Queuing auth-failure simulation…', 'busy');
            try {
                const res = await fetch('/simulate', { method: 'POST' });
                if (!res.ok) {
                    setStatus('Simulation failed.', 'err');
                    return;
                }
                await res.json().catch(() => ({}));
                setStatus('Auth-failure burst queued. Sliding-window detector evaluating…', 'ok');
                await updateDashboard();
            } catch (err) {
                setStatus('Simulation request failed.', 'err');
            } finally {
                setBusy(['btnSimulate'], false);
                setTimeout(() => setStatus(''), 3500);
            }
        }

        async function uploadLogFile() {
            const fileInput = document.getElementById('logFileInput');
            if (!fileInput.files.length) {
                setStatus('Please select a valid .log or .txt file first.', 'err');
                return;
            }

            const file = fileInput.files[0];
            if (file.size > 50 * 1024 * 1024) {
                setStatus('File exceeds the 50MB limit.', 'err');
                return;
            }

            const formData = new FormData();
            formData.append('file', file);

            setBusy(['btnUpload', 'btnReset', 'btnSimulate'], true);
            setStatus(`Uploading ${file.name} (${formatBytes(file.size)})…`, 'busy');

            try {
                const res = await fetch('/api/upload', { method: 'POST', body: formData });
                const payload = await res.json().catch(() => ({}));

                if (res.status === 413 || payload.error) {
                    setStatus(payload.error || 'File exceeds the 50MB limit.', 'err');
                    return;
                }

                if (res.ok) {
                    setStatus(payload.message || 'File uploaded. Monitoring thread started.', 'ok');
                    resetFilePicker();
                    await updateDashboard();
                } else {
                    setStatus(payload.error || 'Upload failed.', 'err');
                }
            } catch (err) {
                setStatus('Upload failed. Is the server running?', 'err');
            } finally {
                setBusy(['btnUpload', 'btnReset', 'btnSimulate'], false);
                setTimeout(() => setStatus(''), 4000);
            }
        }

        window.addEventListener('load', () => {
            initCharts();
            wireDropzone();

            const searchInput = document.getElementById('logSearch');
            const severitySelect = document.getElementById('severityFilter');
            searchInput.addEventListener('input', onLogFilterChanged);
            severitySelect.addEventListener('change', onLogFilterChanged);

            updateDashboard();
            setInterval(updateDashboard, 3000);
        });
    </script>
</body>
</html>
```

### `data/sample.log`

```text
2026-09-12 14:00:01 [INFO] web-server: Request served in 40ms
2026-09-12 14:00:02 [ERROR] auth-service: Failed login for user alice
2026-09-12 14:00:03 [ERROR] auth-service: Failed login for user bob
2026-09-12 14:00:04 [ERROR] auth-service: Failed login for user carol
2026-09-12 14:00:05 [ERROR] auth-service: Failed login for user dave
2026-09-12 14:00:06 [ERROR] auth-service: Failed login for user eve
2026-09-12 14:00:07 [INFO] web-server: Request served in 55ms
2026-09-12 14:00:08 [ERROR] db-service: Connection refused to replica-2
2026-09-12 14:00:09 [WARN] web-server: Slow response 900ms
2026-09-12 14:00:10 [INFO] auth-service: Login success for user frank
```

### `data/test_logs.log`

```text
2026-09-12 12:48:00 [INFO] web-server: Server started successfully.
2026-09-12 12:48:02 [INFO] web-server: Request served in 45ms.
2026-09-12 12:48:05 [INFO] db-service: Database connection established securely.
2026-09-12 12:48:07 [INFO] auth-service: Login success for user frank.
2026-09-12 12:48:10 [ERROR] auth-service: Failed login for user admin
2026-09-12 12:48:11 [ERROR] auth-service: Failed login for user admin
2026-09-12 12:48:11 [ERROR] auth-service: Failed login for user root
2026-09-12 12:48:12 [ERROR] auth-service: Failed login for user admin
2026-09-12 12:48:13 [ERROR] auth-service: Failed login for user guest
2026-09-12 12:48:14 [ERROR] auth-service: Failed login for user root
2026-09-12 12:48:15 [WARN] web-server: Slow response time 900ms detected.
2026-09-12 12:48:18 [INFO] web-server: Request served in 55ms.
2026-09-12 12:48:20 [INFO] auth-service: Login success for user sarah.
```

### `data/upload_test.log`

```text
2026-09-12 14:00:01 [INFO] web-server: Request served in 40ms
2026-09-12 14:00:02 [ERROR] auth-service: Failed login for user alice
2026-09-12 14:00:03 [ERROR] auth-service: Failed login for user bob
2026-09-12 14:00:04 [ERROR] auth-service: Failed login for user carol
2026-09-12 14:00:05 [ERROR] auth-service: Failed login for user dave
2026-09-12 14:00:06 [ERROR] auth-service: Failed login for user eve
2026-09-12 14:00:07 [INFO] web-server: Request served in 55ms
2026-09-12 14:00:08 [ERROR] db-service: Connection refused to replica-2
2026-09-12 14:00:09 [WARN] web-server: Slow response 900ms
2026-09-12 14:00:10 [INFO] auth-service: Login success for user frank
```

---
