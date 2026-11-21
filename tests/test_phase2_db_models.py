"""
Phase 2 Verification Test Suite — Database Schema & Common Models.

Covers:
- Verification of synchronized schema.sql (all 6 tables + indexes)
- Fresh database initialization with WAL mode & foreign keys
- Data models (LogEvent, AlertRecord, QuarantineRecord, UserSession)
- Serialization, deserialization (to_dict, from_dict, from_row)
- Backward compatibility with existing vault/db.py functions
"""

import os
import sqlite3
import tempfile
import pytest

from vault import db
from src.common.models import LogEvent, AlertRecord, QuarantineRecord, UserSession


@pytest.fixture
def fresh_db_path():
    """Create a temporary database file for isolated fresh initialization testing."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError:
        pass


def test_schema_file_synchronized_tables_and_indexes(fresh_db_path):
    """Verify schema.sql executes cleanly and creates all 6 required tables and indexes."""
    schema_path = os.path.join(os.path.dirname(__file__), "..", "vault", "schema.sql")
    assert os.path.exists(schema_path), "vault/schema.sql must exist"

    conn = sqlite3.connect(fresh_db_path)
    with open(schema_path, "r", encoding="utf-8") as f:
        conn.executescript(f.read())

    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = {row[0] for row in cur.fetchall()}

    expected_tables = {"users", "events", "alerts", "config", "history", "rejected_lines"}
    assert expected_tables.issubset(tables), f"Missing tables in schema.sql: {expected_tables - tables}"

    # Verify key indexes
    cur.execute("SELECT name FROM sqlite_master WHERE type='index';")
    indexes = {row[0] for row in cur.fetchall()}
    assert "idx_events_timestamp" in indexes
    assert "idx_alerts_timestamp" in indexes
    assert "idx_history_record" in indexes
    assert "idx_rejected_source" in indexes
    conn.close()


def test_wal_mode_and_foreign_keys_configured(fresh_db_path):
    """Verify WAL journal mode and foreign key enforcement on connections."""
    schema_path = os.path.join(os.path.dirname(__file__), "..", "vault", "schema.sql")
    conn = sqlite3.connect(fresh_db_path)
    with open(schema_path, "r", encoding="utf-8") as f:
        conn.executescript(f.read())

    # Check journal mode
    cur = conn.cursor()
    cur.execute("PRAGMA journal_mode;")
    mode = cur.fetchone()[0]
    assert mode.upper() == "WAL", f"Expected WAL mode, got {mode}"

    # Check foreign keys enforcement
    cur.execute("PRAGMA foreign_keys = ON;")
    with pytest.raises(sqlite3.IntegrityError):
        # Attempt inserting alert referencing non-existent user_id 9999
        conn.execute(
            "INSERT INTO alerts (timestamp, source, alert_type, event_count, window_duration_sec, updated_by) "
            "VALUES ('2026-11-21 12:00:00', 'HDFS', 'TEST', 5, 60, 9999);"
        )
    conn.close()


def test_log_event_model():
    """Verify LogEvent dataclass instantiation, adapters, and roundtrip."""
    ev = LogEvent(
        source="HDFS",
        log_level="WARN",
        component_host="dfs.DataNode",
        raw_message="Got exception while serving block blk_101",
        timestamp="2026-11-21 12:30:00",
        id=42,
    )

    d = ev.to_dict()
    assert d["source"] == "HDFS"
    assert d["log_level"] == "WARN"
    assert d["id"] == 42

    # Roundtrip from dict
    ev_from_d = LogEvent.from_dict(d)
    assert ev_from_d == ev

    # Row adapter
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE events (id INT, timestamp TEXT, source TEXT, log_level TEXT, component_host TEXT, raw_message TEXT);"
    )
    conn.execute(
        "INSERT INTO events VALUES (42, '2026-11-21 12:30:00', 'HDFS', 'WARN', 'dfs.DataNode', 'msg');"
    )
    row = conn.execute("SELECT * FROM events WHERE id=42;").fetchone()
    ev_from_row = LogEvent.from_row(row)
    assert ev_from_row.source == "HDFS"
    assert ev_from_row.component_host == "dfs.DataNode"
    conn.close()


def test_alert_record_model():
    """Verify AlertRecord dataclass, status lifecycle, and adapters."""
    alert = AlertRecord(
        alert_id=10,
        source="NASA-HTTP",
        alert_type="NASA_HTTP_ANOMALY_BURST",
        event_count=8,
        window_duration_sec=60,
        status="ACTIVE",
    )

    d = alert.to_dict()
    assert d["alert_id"] == 10
    assert d["status"] == "ACTIVE"
    assert d["event_count"] == 8

    alert_from_d = AlertRecord.from_dict(d)
    assert alert_from_d.alert_type == "NASA_HTTP_ANOMALY_BURST"


def test_quarantine_record_model():
    """Verify QuarantineRecord dataclass and byte payload handling."""
    raw_bin = b"PK\x03\x04\x00\x00\x00\x00corrupt_bytes"
    q = QuarantineRecord(
        rejected_id=1,
        source="hdfs",
        reason="Binary or null-byte data detected",
        raw_bytes=raw_bin,
    )

    d = q.to_dict()
    assert d["source"] == "hdfs"
    assert d["raw_bytes"] == raw_bin
    assert "PK" in d["raw_text_preview"]

    q_from_d = QuarantineRecord.from_dict(d)
    assert q_from_d.raw_bytes == raw_bin


def test_user_session_model():
    """Verify UserSession dataclass and RBAC helper flags."""
    admin_session = UserSession(user_id=1, username="admin", role="ADMIN")
    assert admin_session.is_admin is True
    assert admin_session.is_operator is True
    assert admin_session.is_viewer is True

    op_session = UserSession(user_id=2, username="operator", role="OPERATOR")
    assert op_session.is_admin is False
    assert op_session.is_operator is True
    assert op_session.is_viewer is True

    viewer_session = UserSession(user_id=3, username="viewer", role="VIEWER")
    assert viewer_session.is_admin is False
    assert viewer_session.is_operator is False
    assert viewer_session.is_viewer is True


def test_db_backward_compatibility_with_existing_vault():
    """Ensure existing db functions work smoothly alongside the updated schema."""
    db.init_db()
    db.reset_db()

    # Save event and fetch
    ev_id = db.save_event(
        source="HDFS",
        log_level="INFO",
        component_host="namenode",
        raw_message="Test message",
    )
    assert ev_id > 0

    events_resp = db.get_events(limit=5)
    assert len(events_resp["events"]) >= 1
    # Verify Model can wrap the row directly
    event_model = LogEvent.from_row(events_resp["events"][0])
    assert event_model.source == "HDFS"
    assert event_model.log_level == "INFO"

    # Save alert and fetch
    alert_id = db.save_alert(
        source="HDFS",
        alert_type="HDFS_BURST",
        event_count=5,
        window_duration_sec=60,
    )
    assert alert_id > 0
    alerts = db.get_alerts()
    assert len(alerts) >= 1
    alert_model = AlertRecord.from_row(alerts[0])
    assert alert_model.alert_type == "HDFS_BURST"
    assert alert_model.status == "ACTIVE"

    # Save rejected line and fetch
    rej_id = db.save_rejected_line(
        source="NASA-HTTP",
        reason="Format violation",
        raw_bytes=b"invalid line",
    )
    assert rej_id > 0
    rejections = db.get_rejected_lines()
    assert len(rejections) >= 1
    q_model = QuarantineRecord.from_row(rejections[0])
    assert q_model.source == "NASA-HTTP"
    assert q_model.reason == "Format violation"
