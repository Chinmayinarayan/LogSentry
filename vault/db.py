"""DBMS Engine — SQLite persistence for events, alerts, users, config, history, and rejected_lines."""

import os
import sqlite3
import threading
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = os.path.join(os.path.dirname(__file__), "logsentry.db")
_lock = threading.Lock()


def get_db_connection():
    """Open a SQLite connection with Row factory enabled, timeout and foreign keys enabled."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    """Create all 6 required tables and indexes, and populate default seed data."""
    conn = get_db_connection()
    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
    with conn:
        if os.path.exists(schema_path):
            with open(schema_path, "r", encoding="utf-8") as f:
                conn.executescript(f.read())
        else:
            conn.executescript(
                """
                PRAGMA journal_mode = WAL;
                PRAGMA foreign_keys = ON;
                PRAGMA busy_timeout = 30000;

                CREATE TABLE IF NOT EXISTS users (
                    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT CHECK(role IN ('ADMIN','OPERATOR','VIEWER')) NOT NULL,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME NOT NULL,
                    source TEXT NOT NULL,
                    log_level TEXT NOT NULL,
                    component_host TEXT,
                    raw_message TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME NOT NULL,
                    source TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    event_count INT NOT NULL,
                    window_duration_sec INT NOT NULL,
                    status TEXT DEFAULT 'ACTIVE',
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_by INTEGER REFERENCES users(user_id)
                );

                CREATE TABLE IF NOT EXISTS config (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_by INTEGER REFERENCES users(user_id)
                );

                CREATE TABLE IF NOT EXISTS history (
                    history_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    table_name TEXT NOT NULL,
                    record_id INTEGER NOT NULL,
                    field_changed TEXT NOT NULL,
                    old_value TEXT,
                    new_value TEXT,
                    changed_by INTEGER REFERENCES users(user_id),
                    changed_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS rejected_lines (
                    rejected_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME NOT NULL,
                    source TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    raw_bytes BLOB NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_events_level ON events(log_level);
                CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
                CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
                CREATE INDEX IF NOT EXISTS idx_history_record ON history(table_name, record_id);
                CREATE INDEX IF NOT EXISTS idx_rejected_source ON rejected_lines(source);
                """
            )

        # Seed default users if empty
        cur = conn.execute("SELECT COUNT(*) AS c FROM users")
        if cur.fetchone()["c"] == 0:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            admin_hash = generate_password_hash("adminpassword")
            operator_hash = generate_password_hash("operatorpassword")
            viewer_hash = generate_password_hash("viewerpassword")
            conn.execute(
                "INSERT INTO users (username, password_hash, role, updated_at) VALUES (?, ?, ?, ?)",
                ("admin", admin_hash, "ADMIN", now),
            )
            conn.execute(
                "INSERT INTO users (username, password_hash, role, updated_at) VALUES (?, ?, ?, ?)",
                ("operator", operator_hash, "OPERATOR", now),
            )
            conn.execute(
                "INSERT INTO users (username, password_hash, role, updated_at) VALUES (?, ?, ?, ?)",
                ("viewer", viewer_hash, "VIEWER", now),
            )

        # Seed default config values
        default_configs = {
            "hdfs_window": "60",
            "hdfs_threshold": "5",
            "nasa_http_window": "60",
            "nasa_http_threshold": "5",
        }
        for k, v in default_configs.items():
            conn.execute(
                "INSERT OR IGNORE INTO config (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
                (k, v),
            )

    conn.close()


# --- USER MANAGEMENT ---

def get_user_by_username(username):
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_id(user_id):
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_users():
    conn = get_db_connection()
    rows = conn.execute("SELECT user_id, username, role, updated_at FROM users ORDER BY user_id ASC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def create_or_update_user(username, password, role, admin_id=None):
    if role not in ('ADMIN', 'OPERATOR', 'VIEWER'):
        raise ValueError("Role must be ADMIN, OPERATOR, or VIEWER")
    pwd_hash = generate_password_hash(password) if password else None
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with _lock:
        conn = get_db_connection()
        with conn:
            existing = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if existing:
                if pwd_hash:
                    conn.execute(
                        "UPDATE users SET password_hash = ?, role = ?, updated_at = ? WHERE username = ?",
                        (pwd_hash, role, now, username),
                    )
                else:
                    conn.execute(
                        "UPDATE users SET role = ?, updated_at = ? WHERE username = ?",
                        (role, now, username),
                    )
                user_id = existing["user_id"]
            else:
                if not pwd_hash:
                    raise ValueError("Password is required for new user")
                cur = conn.execute(
                    "INSERT INTO users (username, password_hash, role, updated_at) VALUES (?, ?, ?, ?)",
                    (username, pwd_hash, role, now),
                )
                user_id = cur.lastrowid
        conn.close()
    return user_id


# --- CONFIG & HISTORY MANAGEMENT ---

def get_all_configs():
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM config").fetchall()
    conn.close()
    return {r["key"]: r["value"] for r in rows}


def update_config(key, new_value, user_id):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _lock:
        conn = get_db_connection()
        with conn:
            existing = conn.execute("SELECT value FROM config WHERE key = ?", (key,)).fetchone()
            old_val = existing["value"] if existing else None

            conn.execute(
                "INSERT INTO config (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by",
                (key, str(new_value), now, user_id),
            )

            conn.execute(
                "INSERT INTO history (table_name, record_id, field_changed, old_value, new_value, changed_by, changed_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("config", 0, key, old_val, str(new_value), user_id, now),
            )
        conn.close()


def get_config_history(limit=100):
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT h.*, u.username AS changed_by_name FROM history h "
        "LEFT JOIN users u ON h.changed_by = u.user_id "
        "WHERE h.table_name = 'config' ORDER BY h.history_id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# --- EVENT PERSISTENCE ---

def save_event(source, log_level, component_host, raw_message, timestamp=None):
    if not timestamp:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _lock:
        conn = get_db_connection()
        with conn:
            cur = conn.execute(
                "INSERT INTO events (timestamp, source, log_level, component_host, raw_message) "
                "VALUES (?, ?, ?, ?, ?)",
                (timestamp, source, log_level, component_host, raw_message),
            )
            event_id = cur.lastrowid
        conn.close()
    return event_id


def save_events_batch(events_list):
    if not events_list:
        return 0
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    records = []
    for item in events_list:
        ts = item.get("timestamp") or now
        records.append((ts, item["source"], item["log_level"], item.get("component_host", ""), item["raw_message"]))

    with _lock:
        conn = get_db_connection()
        with conn:
            conn.executemany(
                "INSERT INTO events (timestamp, source, log_level, component_host, raw_message) "
                "VALUES (?, ?, ?, ?, ?)",
                records,
            )
        conn.close()
    return len(records)


def save_rejected_line(source, reason, raw_bytes, timestamp=None):
    if not timestamp:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(raw_bytes, str):
        raw_bytes = raw_bytes.encode("utf-8", errors="replace")

    with _lock:
        conn = get_db_connection()
        with conn:
            cur = conn.execute(
                "INSERT INTO rejected_lines (timestamp, source, reason, raw_bytes) "
                "VALUES (?, ?, ?, ?)",
                (timestamp, source, reason, sqlite3.Binary(raw_bytes)),
            )
            rejected_id = cur.lastrowid
        conn.close()
    return rejected_id


def get_rejected_lines(limit=100):
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT rejected_id, timestamp, source, reason, raw_bytes FROM rejected_lines ORDER BY rejected_id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    res = []
    for r in rows:
        d = dict(r)
        b = d["raw_bytes"]
        if isinstance(b, bytes):
            d["raw_bytes_preview"] = b.decode("utf-8", errors="replace")[:200]
        else:
            d["raw_bytes_preview"] = str(b)[:200]
        del d["raw_bytes"]
        res.append(d)
    return res


# --- ALERTS PERSISTENCE ---

def save_alert(source, alert_type, event_count, window_duration_sec, timestamp=None):
    if not timestamp:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with _lock:
        conn = get_db_connection()
        with conn:
            cur = conn.execute(
                "INSERT INTO alerts (timestamp, source, alert_type, event_count, window_duration_sec, status, updated_at) "
                "VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?)",
                (timestamp, source, alert_type, event_count, window_duration_sec, now),
            )
            alert_id = cur.lastrowid
        conn.close()
    return alert_id


def resolve_alert(alert_id, user_id):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _lock:
        conn = get_db_connection()
        with conn:
            alert = conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
            if not alert:
                conn.close()
                return False

            old_status = alert["status"]
            if old_status == "RESOLVED":
                conn.close()
                return True

            conn.execute(
                "UPDATE alerts SET status = 'RESOLVED', updated_at = ?, updated_by = ? WHERE alert_id = ?",
                (now, user_id, alert_id),
            )

            conn.execute(
                "INSERT INTO history (table_name, record_id, field_changed, old_value, new_value, changed_by, changed_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("alerts", alert_id, "status", old_status, "RESOLVED", user_id, now),
            )
        conn.close()
    return True


def get_alerts(limit=50, status=None):
    conn = get_db_connection()
    if status:
        rows = conn.execute(
            "SELECT a.*, u.username AS updated_by_name FROM alerts a "
            "LEFT JOIN users u ON a.updated_by = u.user_id "
            "WHERE a.status = ? ORDER BY a.alert_id DESC LIMIT ?",
            (status, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT a.*, u.username AS updated_by_name FROM alerts a "
            "LEFT JOIN users u ON a.updated_by = u.user_id "
            "ORDER BY a.alert_id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_alert_history(alert_id):
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT h.*, u.username AS changed_by_name FROM history h "
        "LEFT JOIN users u ON h.changed_by = u.user_id "
        "WHERE h.table_name = 'alerts' AND h.record_id = ? ORDER BY h.history_id ASC",
        (alert_id,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# --- QUERIES & STATS ---

def get_events(limit=100, offset=0, source=None, level=None, start_time=None, end_time=None):
    conn = get_db_connection()
    clauses = []
    params = []

    if source:
        clauses.append("source = ?")
        params.append(source)
    if level:
        clauses.append("log_level = ?")
        params.append(level.upper())
    if start_time:
        clauses.append("timestamp >= ?")
        params.append(start_time)
    if end_time:
        clauses.append("timestamp <= ?")
        params.append(end_time)

    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    count_sql = f"SELECT COUNT(*) AS total FROM events {where_sql}"
    total = conn.execute(count_sql, params).fetchone()["total"]

    sql = (
        f"SELECT id, timestamp, source, log_level, component_host, raw_message "
        f"FROM events {where_sql} ORDER BY id DESC LIMIT ? OFFSET ?"
    )
    params.extend([limit, offset])
    rows = conn.execute(sql, params).fetchall()
    conn.close()

    return {
        "events": [dict(r) for r in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


def get_event_stats():
    conn = get_db_connection()
    total_events = conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]
    errors = conn.execute(
        "SELECT COUNT(*) AS c FROM events WHERE log_level IN ('WARN', 'WARNING', 'ERROR', 'FATAL')"
    ).fetchone()["c"]
    active_alerts = conn.execute(
        "SELECT COUNT(*) AS c FROM alerts WHERE status = 'ACTIVE'"
    ).fetchone()["c"]
    rejected_count = conn.execute("SELECT COUNT(*) AS c FROM rejected_lines").fetchone()["c"]
    conn.close()
    return {
        "total_events": total_events,
        "errors": errors,
        "active_alerts": active_alerts,
        "rejected_lines": rejected_count,
    }


def get_timeseries():
    conn = get_db_connection()
    rows = conn.execute(
        """
        SELECT
            substr(timestamp, 1, 16) AS minute,
            COUNT(*) AS events,
            SUM(CASE WHEN log_level IN ('WARN', 'WARNING', 'ERROR', 'FATAL') THEN 1 ELSE 0 END) AS errors
        FROM events
        GROUP BY minute
        ORDER BY minute ASC
        """
    ).fetchall()
    conn.close()

    labels = [r["minute"] for r in rows]
    events = [r["events"] for r in rows]
    errors = [int(r["errors"] or 0) for r in rows]

    return {
        "labels": labels,
        "events": events,
        "errors": errors,
    }


def reset_db():
    """Clear all events, alerts, history, and rejected_lines for test isolation."""
    with _lock:
        conn = get_db_connection()
        with conn:
            conn.execute("DELETE FROM events")
            conn.execute("DELETE FROM alerts")
            conn.execute("DELETE FROM history")
            conn.execute("DELETE FROM rejected_lines")
            conn.execute("DELETE FROM sqlite_sequence WHERE name IN ('events', 'alerts', 'history', 'rejected_lines')")
        conn.close()


if __name__ == "__main__":
    init_db()
