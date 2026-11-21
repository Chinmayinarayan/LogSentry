"""
Phase 5: E3 VAULT Implementation Verification Test Suite.

Exhaustive verification of Engine 3 (E3 VAULT) persistent storage and audit engine:
1. Valid HDFS event persistence (single & batch, field fidelity).
2. Valid NASA-HTTP event persistence (single & batch, field fidelity).
3. Alert persistence, retrieval, and status filtering.
4. Alert resolution, status transition to RESOLVED, audit history logging.
5. Quarantine record persistence (BLOB raw_bytes) and safe preview generation.
6. User creation, retrieval, password hash verification, and role constraints.
7. Configuration persistence, dynamic update, and audit history logging.
8. Configuration persistence across database re-initialization (restart simulation).
9. Audit history append-only ledger integrity.
10. System restart persistence (all entities intact across connection closure & re-open).
11. Concurrent database writes under single-writer synchronization lock.
12. Transaction rollback on SQL failure (atomic commit guarantee).
13. Foreign key constraint enforcement (PRAGMA foreign_keys = ON).
14. Integration with E4 query interfaces (pagination, filtering, stats, timeseries).
"""

import os
import sqlite3
import tempfile
import threading
from datetime import datetime
import pytest
from werkzeug.security import check_password_hash

from vault import db
from src.common.models import LogEvent, AlertRecord, QuarantineRecord, UserSession


@pytest.fixture(autouse=True)
def isolated_vault_db():
    """Ensure every test runs against an isolated temporary SQLite database."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    orig_path = db.get_db_path()
    db.set_db_path(path)
    db.init_db()

    yield path

    db.set_db_path(orig_path)
    for ext in ("", "-wal", "-shm"):
        f = path + ext
        if os.path.exists(f):
            try:
                os.remove(f)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# 1. HDFS Event Persistence
# ---------------------------------------------------------------------------

def test_hdfs_event_persistence():
    """Verify single and batch HDFS operational log event persistence with full field fidelity."""
    eid1 = db.save_event(
        source="hdfs",
        log_level="WARN",
        component_host="dfs.DataNode$DataXceiver",
        raw_message="Got exception while serving block blk_-1608999687919862906 to /10.251.91.84",
        timestamp="2026-11-21 10:15:30",
    )
    assert isinstance(eid1, int) and eid1 > 0

    batch = [
        {
            "source": "hdfs",
            "log_level": "ERROR",
            "component_host": "dfs.DataNode$PacketResponder",
            "raw_message": "PacketResponder blk_100 Exception",
            "timestamp": "2026-11-21 10:15:31",
        },
        {
            "source": "hdfs",
            "log_level": "INFO",
            "component_host": "dfs.FSNamesystem",
            "raw_message": "BLOCK* NameSystem.allocateBlock",
            "timestamp": "2026-11-21 10:15:32",
        },
    ]
    count = db.save_events_batch(batch)
    assert count == 2

    res = db.get_events(source="hdfs")
    assert res["total"] == 3
    events = res["events"]
    # Verify latest first (ordered by id DESC)
    assert events[0]["log_level"] == "INFO"
    assert events[1]["log_level"] == "ERROR"
    assert events[2]["log_level"] == "WARN"
    assert events[2]["component_host"] == "dfs.DataNode$DataXceiver"
    assert "blk_-1608999687919862906" in events[2]["raw_message"]


# ---------------------------------------------------------------------------
# 2. NASA-HTTP Event Persistence
# ---------------------------------------------------------------------------

def test_nasa_http_event_persistence():
    """Verify single and batch NASA-HTTP event persistence with full field fidelity."""
    eid = db.save_event(
        source="nasa_http",
        log_level="ERROR",
        component_host="199.72.81.55",
        raw_message="GET /history/apollo/ HTTP/1.0 404 1234",
        timestamp="2026-11-21 11:00:00",
    )
    assert isinstance(eid, int) and eid > 0

    batch = [
        {
            "source": "nasa_http",
            "log_level": "INFO",
            "component_host": "unicomp6.unicomp.net",
            "raw_message": "GET /shuttle/countdown/ HTTP/1.0 200 3985",
            "timestamp": "2026-11-21 11:00:01",
        },
        {
            "source": "nasa_http",
            "log_level": "ERROR",
            "component_host": "burger.letters.com",
            "raw_message": "GET /images/NASA-logosmall.gif HTTP/1.0 500 0",
            "timestamp": "2026-11-21 11:00:02",
        },
    ]
    assert db.save_events_batch(batch) == 2

    res = db.get_events(source="nasa_http")
    assert res["total"] == 3
    # Check level filtering
    err_res = db.get_events(source="nasa_http", level="ERROR")
    assert err_res["total"] == 2
    for ev in err_res["events"]:
        assert ev["log_level"] == "ERROR"


# ---------------------------------------------------------------------------
# 3. Alert Persistence and Filtering
# ---------------------------------------------------------------------------

def test_alert_persistence_and_filtering():
    """Verify alert persistence, retrieval, and status filtering."""
    a1 = db.save_alert("hdfs", "ANOMALY_BURST", 5, 60, timestamp="2026-11-21 12:00:00")
    a2 = db.save_alert("nasa_http", "ANOMALY_BURST", 8, 60, timestamp="2026-11-21 12:01:00")

    assert a1 > 0 and a2 > 0

    all_alerts = db.get_alerts()
    assert len(all_alerts) == 2
    for a in all_alerts:
        assert a["status"] == "ACTIVE"

    # Filter by status
    active_alerts = db.get_alerts(status="ACTIVE")
    assert len(active_alerts) == 2
    resolved_alerts = db.get_alerts(status="RESOLVED")
    assert len(resolved_alerts) == 0


# ---------------------------------------------------------------------------
# 4. Alert Resolution and Audit History
# ---------------------------------------------------------------------------

def test_alert_resolution_and_audit_history():
    """Verify alert lifecycle transition to RESOLVED and audit trail logging in history."""
    aid = db.save_alert("hdfs", "ANOMALY_BURST", 5, 60)
    admin_user = db.get_user_by_username("admin")
    assert admin_user is not None

    # Resolve alert
    success = db.resolve_alert(aid, user_id=admin_user["user_id"])
    assert success is True

    # Verify status in database
    alerts = db.get_alerts(status="RESOLVED")
    assert len(alerts) == 1
    assert alerts[0]["alert_id"] == aid
    assert alerts[0]["status"] == "RESOLVED"
    assert alerts[0]["updated_by"] == admin_user["user_id"]
    assert alerts[0]["updated_by_name"] == "admin"

    # Idempotent resolve
    assert db.resolve_alert(aid, user_id=admin_user["user_id"]) is True

    # Resolving non-existent alert returns False
    assert db.resolve_alert(999999, user_id=admin_user["user_id"]) is False

    # Verify audit history entry
    history = db.get_alert_history(aid)
    assert len(history) == 1
    h = history[0]
    assert h["table_name"] == "alerts"
    assert h["record_id"] == aid
    assert h["field_changed"] == "status"
    assert h["old_value"] == "ACTIVE"
    assert h["new_value"] == "RESOLVED"
    assert h["changed_by"] == admin_user["user_id"]
    assert h["changed_by_name"] == "admin"


# ---------------------------------------------------------------------------
# 5. Quarantine Record Persistence and Safe Preview
# ---------------------------------------------------------------------------

def test_quarantine_record_persistence_and_safe_preview():
    """Verify rejected/corrupted inputs stored as BLOBs with safe preview extraction."""
    raw_binary = b"Corrupted \x00\xff binary chunk \xfe\xed"
    rid1 = db.save_rejected_line("hdfs", "CORRUPTED_BYTES", raw_binary)
    assert rid1 > 0

    oversized_str = "A" * 500
    rid2 = db.save_rejected_line("nasa_http", "OVERSIZED_RECORD", oversized_str)
    assert rid2 > 0

    rejected = db.get_rejected_lines()
    assert len(rejected) == 2

    # Latest first
    r2 = rejected[0]
    assert r2["rejected_id"] == rid2
    assert r2["source"] == "nasa_http"
    assert r2["reason"] == "OVERSIZED_RECORD"
    assert len(r2["raw_bytes_preview"]) <= 200
    assert "raw_bytes" not in r2  # Raw binary not leaked in JSON preview

    r1 = rejected[1]
    assert r1["rejected_id"] == rid1
    assert r1["source"] == "hdfs"
    assert r1["reason"] == "CORRUPTED_BYTES"
    assert "Corrupted" in r1["raw_bytes_preview"]


# ---------------------------------------------------------------------------
# 6. User Management, Password Hashing, and Role Constraints
# ---------------------------------------------------------------------------

def test_user_management_password_hashing_and_role_constraints():
    """Verify RBAC user management, secure password hashing, and role checks."""
    # Default seeded users exist
    admin = db.get_user_by_username("admin")
    assert admin is not None
    assert admin["role"] == "ADMIN"
    assert check_password_hash(admin["password_hash"], "adminpassword")

    operator = db.get_user_by_username("operator")
    assert operator is not None
    assert operator["role"] == "OPERATOR"
    assert check_password_hash(operator["password_hash"], "operatorpassword")

    # Create new user with admin_id audit tracking
    uid = db.create_or_update_user("analyst_bob", "Secr3tP@ss!", "OPERATOR", admin_id=admin["user_id"])
    assert uid > 0

    user = db.get_user_by_id(uid)
    assert user["username"] == "analyst_bob"
    assert user["role"] == "OPERATOR"
    assert check_password_hash(user["password_hash"], "Secr3tP@ss!")

    # Verify audit history captured user creation
    audit = db.get_audit_history(table_name="users")
    assert any(h["record_id"] == uid and h["field_changed"] == "user_created" for h in audit)

    # Update role
    db.create_or_update_user("analyst_bob", None, "VIEWER", admin_id=admin["user_id"])
    updated_user = db.get_user_by_id(uid)
    assert updated_user["role"] == "VIEWER"

    # Reject invalid role
    with pytest.raises(ValueError, match="Role must be ADMIN, OPERATOR, or VIEWER"):
        db.create_or_update_user("bad_user", "password", "SUPERUSER")

    # Reject new user without password
    with pytest.raises(ValueError, match="Password is required for new user"):
        db.create_or_update_user("no_pw_user", None, "VIEWER")


# ---------------------------------------------------------------------------
# 7. Configuration Persistence and Audit History
# ---------------------------------------------------------------------------

def test_config_persistence_and_audit_history():
    """Verify dynamic sliding window configuration changes and audit history recording."""
    admin = db.get_user_by_username("admin")
    configs_before = db.get_all_configs()
    assert configs_before["hdfs_threshold"] == "5"

    # Update threshold to 15
    db.update_config("hdfs_threshold", "15", user_id=admin["user_id"])

    configs_after = db.get_all_configs()
    assert configs_after["hdfs_threshold"] == "15"

    # Verify audit history
    history = db.get_config_history()
    assert len(history) >= 1
    h = history[0]
    assert h["field_changed"] == "hdfs_threshold"
    assert h["old_value"] == "5"
    assert h["new_value"] == "15"
    assert h["changed_by"] == admin["user_id"]
    assert h["changed_by_name"] == "admin"


# ---------------------------------------------------------------------------
# 8. Configuration Persistence Across Re-initialization (Restart Simulation)
# ---------------------------------------------------------------------------

def test_config_persistence_across_reinit():
    """Verify updated configs persist across init_db() calls without resetting to seed defaults."""
    admin = db.get_user_by_username("admin")
    db.update_config("nasa_http_window", "120", user_id=admin["user_id"])
    db.update_config("nasa_http_threshold", "20", user_id=admin["user_id"])

    # Re-run init_db (simulating server restart)
    db.init_db()

    cfg = db.get_all_configs()
    assert cfg["nasa_http_window"] == "120"
    assert cfg["nasa_http_threshold"] == "20"


# ---------------------------------------------------------------------------
# 9. Audit History Append-Only Ledger Integrity
# ---------------------------------------------------------------------------

def test_audit_history_append_only_ledger():
    """Verify that audit history is append-only, ordered monotonically, and captures all mutations."""
    admin = db.get_user_by_username("admin")

    # Explicit audit events
    h1 = db.record_audit_event("system", 1, "SYSTEM_START", old_value=None, new_value="ONLINE", changed_by=admin["user_id"])
    h2 = db.record_audit_event("system", 1, "LOG_ROTATION", old_value="DAILY", new_value="HOURLY", changed_by=admin["user_id"])

    assert h2 > h1

    records = db.get_audit_history(table_name="system")
    assert len(records) == 2
    # Ordered by history_id DESC
    assert records[0]["field_changed"] == "LOG_ROTATION"
    assert records[1]["field_changed"] == "SYSTEM_START"


# ---------------------------------------------------------------------------
# 10. System Restart Persistence (Data Retained Across Connections)
# ---------------------------------------------------------------------------

def test_system_restart_data_integrity():
    """Simulate complete process restart by closing all connections and verifying all data remains intact."""
    current_db_path = db.get_db_path()

    # Insert data across all entities
    eid = db.save_event("hdfs", "WARN", "host1", "Restart test event")
    aid = db.save_alert("hdfs", "ANOMALY_BURST", 5, 60)
    rid = db.save_rejected_line("hdfs", "TEST_REASON", b"rejection raw")
    admin = db.get_user_by_username("admin")
    db.update_config("hdfs_window", "300", user_id=admin["user_id"])

    # Disconnect simulation: re-point to the exact same database file and re-open
    db.set_db_path(current_db_path)

    # Verify event
    events = db.get_events()["events"]
    assert any(e["id"] == eid and e["raw_message"] == "Restart test event" for e in events)

    # Verify alert
    alerts = db.get_alerts()
    assert any(a["alert_id"] == aid and a["source"] == "hdfs" for a in alerts)

    # Verify rejected line
    rejected = db.get_rejected_lines()
    assert any(r["rejected_id"] == rid and r["reason"] == "TEST_REASON" for r in rejected)

    # Verify config
    assert db.get_all_configs()["hdfs_window"] == "300"


# ---------------------------------------------------------------------------
# 11. Concurrent Database Writes (Single-Writer Coordination)
# ---------------------------------------------------------------------------

def test_concurrent_database_writes_single_writer():
    """Verify thread-safe database writes under concurrency without 'database is locked' errors."""
    barrier = threading.Barrier(10)
    errors = []

    def event_writer(idx):
        try:
            barrier.wait()
            for i in range(10):
                db.save_event("hdfs", "INFO", f"host_{idx}", f"Concurrent message {idx}_{i}")
        except Exception as ex:
            errors.append(ex)

    def alert_writer(idx):
        try:
            barrier.wait()
            for i in range(5):
                db.save_alert("hdfs", "ANOMALY_BURST", i + 1, 60)
        except Exception as ex:
            errors.append(ex)

    def rejected_writer(idx):
        try:
            barrier.wait()
            for i in range(5):
                db.save_rejected_line("hdfs", "CONCURRENCY_TEST", f"Bad line {idx}_{i}".encode("utf-8"))
        except Exception as ex:
            errors.append(ex)

    threads = []
    # 5 event writers (50 events)
    for i in range(5):
        t = threading.Thread(target=event_writer, args=(i,))
        threads.append(t)
    # 3 alert writers (15 alerts)
    for i in range(3):
        t = threading.Thread(target=alert_writer, args=(i,))
        threads.append(t)
    # 2 rejected line writers (10 rejected)
    for i in range(2):
        t = threading.Thread(target=rejected_writer, args=(i,))
        threads.append(t)

    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10.0)

    assert len(errors) == 0, f"Concurrent database errors: {errors}"

    stats = db.get_event_stats()
    assert stats["total_events"] == 50
    assert stats["active_alerts"] == 15
    assert stats["rejected_lines"] == 10


# ---------------------------------------------------------------------------
# 12. Transaction Rollback on SQL Failure
# ---------------------------------------------------------------------------

def test_transaction_rollback_on_sql_error():
    """Verify that uncommitted partial writes in a transaction roll back cleanly upon exception."""
    events_before = db.get_event_stats()["total_events"]

    conn = db.get_db_connection()
    try:
        with pytest.raises(sqlite3.OperationalError):
            with conn:
                conn.execute(
                    "INSERT INTO events (timestamp, source, log_level, component_host, raw_message) "
                    "VALUES ('2026-11-21 12:00:00', 'hdfs', 'INFO', 'host1', 'Should be rolled back')"
                )
                # Intentional syntax error to trigger transaction abort
                conn.execute("INSERT INTO non_existent_table VALUES (1, 2, 3)")
    finally:
        conn.close()

    # Verify no partial write survived
    events_after = db.get_event_stats()["total_events"]
    assert events_after == events_before


# ---------------------------------------------------------------------------
# 13. Foreign Key Constraint Enforcement
# ---------------------------------------------------------------------------

def test_foreign_key_enforcement():
    """Verify PRAGMA foreign_keys = ON blocks invalid foreign key references."""
    # Attempt to resolve an alert with a non-existent user_id
    aid = db.save_alert("hdfs", "ANOMALY_BURST", 5, 60)
    non_existent_uid = 999999

    conn = db.get_db_connection()
    try:
        # Direct foreign key violation on alerts.updated_by
        with pytest.raises(sqlite3.IntegrityError):
            with conn:
                conn.execute(
                    "UPDATE alerts SET updated_by = ? WHERE alert_id = ?",
                    (non_existent_uid, aid),
                )

        # Direct foreign key violation on history.changed_by
        with pytest.raises(sqlite3.IntegrityError):
            with conn:
                conn.execute(
                    "INSERT INTO history (table_name, record_id, field_changed, changed_by) "
                    "VALUES ('alerts', ?, 'status', ?)",
                    (aid, non_existent_uid),
                )
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 14. Integration with E4 Query Interfaces
# ---------------------------------------------------------------------------

def test_e4_query_interfaces_integration():
    """Verify pagination, time/level filtering, stats aggregation, and timeseries querying."""
    # Insert events across multiple timestamps and log levels
    events_data = [
        {"source": "hdfs", "log_level": "INFO", "component_host": "h1", "raw_message": "Msg 1", "timestamp": "2026-11-21 10:00:10"},
        {"source": "hdfs", "log_level": "WARN", "component_host": "h2", "raw_message": "Msg 2", "timestamp": "2026-11-21 10:00:20"},
        {"source": "hdfs", "log_level": "ERROR", "component_host": "h3", "raw_message": "Msg 3", "timestamp": "2026-11-21 10:01:05"},
        {"source": "nasa_http", "log_level": "INFO", "component_host": "h4", "raw_message": "Msg 4", "timestamp": "2026-11-21 10:01:30"},
        {"source": "nasa_http", "log_level": "ERROR", "component_host": "h5", "raw_message": "Msg 5", "timestamp": "2026-11-21 10:02:15"},
    ]
    db.save_events_batch(events_data)
    db.save_alert("hdfs", "ANOMALY_BURST", 5, 60)
    db.save_rejected_line("hdfs", "TEST", b"bad line")

    # 1. Pagination
    p1 = db.get_events(limit=2, offset=0)
    assert p1["total"] == 5
    assert len(p1["events"]) == 2

    p2 = db.get_events(limit=2, offset=2)
    assert len(p2["events"]) == 2

    p3 = db.get_events(limit=2, offset=4)
    assert len(p3["events"]) == 1

    # 2. Filtering
    warn_err = db.get_events(level="ERROR")
    assert warn_err["total"] == 2

    time_filtered = db.get_events(start_time="2026-11-21 10:01:00", end_time="2026-11-21 10:01:59")
    assert time_filtered["total"] == 2

    # 3. Stats Aggregation
    stats = db.get_event_stats()
    assert stats["total_events"] == 5
    assert stats["errors"] == 3  # 1 WARN + 2 ERROR
    assert stats["active_alerts"] == 1
    assert stats["rejected_lines"] == 1

    # 4. Timeseries Aggregation
    ts = db.get_timeseries()
    assert len(ts["labels"]) >= 3  # '2026-11-21 10:00', '2026-11-21 10:01', '2026-11-21 10:02'
    assert sum(ts["events"]) == 5
    assert sum(ts["errors"]) == 3


# ---------------------------------------------------------------------------
# 15. Transaction Atomicity: Audit Failure Rolls Back Primary Operation
# ---------------------------------------------------------------------------

def test_transaction_atomicity_audit_failure_rolls_back_primary_operation():
    """Verify that if audit history recording fails, the primary operation is atomically rolled back."""
    invalid_admin_id = 999999

    # 1. User Creation: failure in audit log rolls back user table insertion
    with pytest.raises(sqlite3.IntegrityError):
        db.create_or_update_user("ghost_user", "Secr3t!", "OPERATOR", admin_id=invalid_admin_id)
    assert db.get_user_by_username("ghost_user") is None

    # 2. Config Update: failure in audit log rolls back config table update
    orig_val = db.get_all_configs()["hdfs_window"]
    with pytest.raises(sqlite3.IntegrityError):
        db.update_config("hdfs_window", "999", user_id=invalid_admin_id)
    assert db.get_all_configs()["hdfs_window"] == orig_val

    # 3. Alert Resolution: failure in audit log rolls back alert resolution
    aid = db.save_alert("hdfs", "ANOMALY_BURST", 5, 60)
    with pytest.raises(sqlite3.IntegrityError):
        db.resolve_alert(aid, user_id=invalid_admin_id)
    alerts = db.get_alerts(status="ACTIVE")
    assert any(a["alert_id"] == aid for a in alerts)


# ---------------------------------------------------------------------------
# 16. Concurrent Readers and Writers under WAL Mode
# ---------------------------------------------------------------------------

def test_concurrent_readers_and_writers_wal_mode():
    """Verify that WAL mode permits non-blocking concurrent reads while writers synchronize safely."""
    # Seed initial data
    for i in range(10):
        db.save_event("hdfs", "INFO", f"host_{i}", f"Pre-seed event {i}")

    barrier = threading.Barrier(10)
    errors = []

    def reader_worker(idx):
        try:
            barrier.wait()
            for _ in range(20):
                evs = db.get_events(limit=10)
                assert evs["total"] >= 10
                stats = db.get_event_stats()
                assert stats["total_events"] >= 10
        except Exception as ex:
            errors.append(ex)

    def writer_worker(idx):
        try:
            barrier.wait()
            for i in range(10):
                db.save_event("hdfs", "WARN", f"host_w{idx}", f"Live concurrent event {idx}_{i}")
                if i % 3 == 0:
                    db.save_alert("hdfs", "BURST", i + 1, 60)
        except Exception as ex:
            errors.append(ex)

    threads = []
    # 5 concurrent reader threads
    for i in range(5):
        t = threading.Thread(target=reader_worker, args=(i,))
        threads.append(t)
    # 5 concurrent writer threads
    for i in range(5):
        t = threading.Thread(target=writer_worker, args=(i,))
        threads.append(t)

    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15.0)

    assert len(errors) == 0, f"Reader/writer concurrency errors under WAL: {errors}"


# ---------------------------------------------------------------------------
# 17. User Password Update Audit Trail
# ---------------------------------------------------------------------------

def test_user_password_update_audit_trail():
    """Verify that updating user credentials records audit entry without leaking secrets."""
    admin = db.get_user_by_username("admin")
    uid = db.create_or_update_user("analyst_clara", "InitialP@ss1", "VIEWER", admin_id=admin["user_id"])

    # Update password
    db.create_or_update_user("analyst_clara", "UpdatedP@ss2!", "VIEWER", admin_id=admin["user_id"])

    # Verify authentication works with new password and fails with old
    user = db.get_user_by_id(uid)
    assert check_password_hash(user["password_hash"], "UpdatedP@ss2!")
    assert not check_password_hash(user["password_hash"], "InitialP@ss1")

    # Verify audit history
    audit = db.get_audit_history(table_name="users")
    pwd_records = [h for h in audit if h["record_id"] == uid and h["field_changed"] == "password_updated"]
    assert len(pwd_records) == 1
    rec = pwd_records[0]
    assert rec["new_value"] == "[UPDATED]"  # Hash and plain password are not leaked in audit
    assert rec["changed_by"] == admin["user_id"]
    assert rec["changed_by_name"] == "admin"


# ---------------------------------------------------------------------------
# 18. Deadlock Free Lock Acquisition Order
# ---------------------------------------------------------------------------

def test_no_recursive_lock_deadlock_across_vault_operations():
    """Verify that rapid interleaved calls across all database operations execute without deadlock."""
    admin = db.get_user_by_username("admin")

    # Sequence of rapid mixed operations
    eid = db.save_event("hdfs", "INFO", "h1", "Msg")
    aid = db.save_alert("hdfs", "BURST", 5, 60)
    db.resolve_alert(aid, user_id=admin["user_id"])
    db.update_config("hdfs_threshold", "10", user_id=admin["user_id"])
    rid = db.save_rejected_line("hdfs", "REASON", b"data")
    hid = db.record_audit_event("custom", 1, "ACTION", old_value="A", new_value="B", changed_by=admin["user_id"])

    assert eid > 0 and aid > 0 and rid > 0 and hid > 0

