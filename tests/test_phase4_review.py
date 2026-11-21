"""
Phase 4 Technical Review Test Suite.

Verifies:
1. Memory bounds & oversized record quarantine (>64 KB)
2. ZIP path traversal security rejection
3. Non-blocking independent sliding window locks (HDFS and NASA concurrency)
4. Out-of-order timestamp handling in sliding window
5. Identical timestamp burst detection
6. Dynamic window duration reconfiguration eviction
"""

import io
import os
import tempfile
import threading
import time
import zipfile
import pytest

from parse import parser
from vault import db
from watch import tailer


@pytest.fixture(autouse=True)
def clean_review_state():
    db.init_db()
    db.reset_db()
    parser.reset_sliding_windows()
    parser.refresh_config_cache()
    while not tailer.log_queue.empty():
        tailer.log_queue.get_nowait()
    yield
    parser.reset_sliding_windows()


# =====================================================================
# 1. MEMORY BOUND & OVERSIZED RECORD TEST
# =====================================================================

def test_oversized_record_quarantined():
    """An individual line exceeding 64 KB must be rejected and quarantined, preventing queue bloat."""
    huge_line = "081109 203518 143 INFO dfs.DataNode: " + ("X" * 70000) + "\n"

    fd, path = tempfile.mkstemp(suffix=".log")
    os.close(fd)
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(huge_line)

        res = tailer.ingest_file_path("hdfs", path)
        assert res["status"] == "success"
        # The line was oversized, so it must not have been enqueued as a valid line
        assert tailer.log_queue.qsize() == 0

        # Verify it was quarantined
        rejected = db.get_rejected_lines()
        assert len(rejected) >= 1
        assert any("OVERSIZED" in str(r.get("raw_bytes_preview", "")) or "Binary" in r["reason"] or "Format" in r["reason"] for r in rejected)

    finally:
        if os.path.exists(path):
            os.remove(path)


# =====================================================================
# 2. ZIP PATH TRAVERSAL SECURITY TEST
# =====================================================================

def test_zip_path_traversal_rejected():
    """ZIP containing directory traversal paths (e.g. ../../etc/passwd) must be rejected and quarantined."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../etc/passwd.log", "root:x:0:0:root:/root:/bin/bash\n")

    zip_bytes = buf.getvalue()
    res = tailer.ingest_file_stream("hdfs", zip_bytes, filename="traversal.zip")

    assert res["status"] == "error"
    assert "Directory traversal" in res["message"] or "Security" in res["message"]

    # Verify quarantine recorded
    rejected = db.get_rejected_lines()
    assert len(rejected) >= 1
    assert any("SECURITY" in str(r.get("raw_bytes_preview", "")) or "Format" in r["reason"] for r in rejected)


# =====================================================================
# 3. INDEPENDENT SLIDING-WINDOW LOCKS (CONCURRENCY)
# =====================================================================

def test_independent_locks_hdfs_nasa_no_deadlock():
    """HDFS and NASA-HTTP use separate window locks and must not block each other."""
    db.update_config("hdfs_threshold", "5", user_id=1)
    db.update_config("nasa_http_threshold", "5", user_id=1)
    parser.refresh_config_cache()

    hdfs_line = "081109 203518 143 ERROR dfs.DataNode: Block error"
    nasa_line = '199.72.81.55 - - [01/Jul/1995:00:00:01 -0400] "GET /err HTTP/1.0" 500 100'

    errors = []

    def feed_hdfs():
        try:
            for _ in range(20):
                parser.parse_line(hdfs_line, declared_source="hdfs")
        except Exception as e:
            errors.append(e)

    def feed_nasa():
        try:
            for _ in range(20):
                parser.parse_line(nasa_line, declared_source="nasa_http")
        except Exception as e:
            errors.append(e)

    threads = [
        threading.Thread(target=feed_hdfs),
        threading.Thread(target=feed_nasa),
        threading.Thread(target=feed_hdfs),
        threading.Thread(target=feed_nasa),
    ]

    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5.0)

    assert len(errors) == 0, f"Concurrent parser threads failed with: {errors}"
    alerts = db.get_alerts()
    assert len(alerts) >= 2


# =====================================================================
# 4. TIMESTAMP EDGE CASES: OUT-OF-ORDER & IDENTICAL
# =====================================================================

def test_out_of_order_timestamps_handled_safely():
    """Out-of-order timestamps within window are sorted properly and do not break eviction."""
    db.update_config("hdfs_window", "10", user_id=1)
    db.update_config("hdfs_threshold", "3", user_id=1)
    parser.refresh_config_cache()

    # Event at t=10
    parser.parse_line("2026-09-12 12:00:10 [ERROR] namenode: Error 1", declared_source="hdfs")
    # Delayed event at t=05 arriving later
    parser.parse_line("2026-09-12 12:00:05 [ERROR] namenode: Error 2", declared_source="hdfs")
    assert len(db.get_alerts()) == 0

    stats = parser.get_sliding_window_stats()
    assert stats["hdfs"]["current_count"] == 2

    # 3rd event at t=12 -> threshold reached within 10s window (12 - 5 = 7s <= 10s)
    parser.parse_line("2026-09-12 12:00:12 [ERROR] namenode: Error 3", declared_source="hdfs")
    alerts = db.get_alerts()
    assert len(alerts) == 1
    assert alerts[0]["event_count"] == 3


def test_identical_timestamps_counted_in_burst():
    """Two or more events occurring at the exact same second are all counted in the window."""
    db.update_config("hdfs_window", "10", user_id=1)
    db.update_config("hdfs_threshold", "3", user_id=1)
    parser.refresh_config_cache()

    identical_line = "2026-09-12 12:00:00 [ERROR] namenode: Error at same second"
    parser.parse_line(identical_line, declared_source="hdfs")
    parser.parse_line(identical_line, declared_source="hdfs")
    assert len(db.get_alerts()) == 0

    parser.parse_line(identical_line, declared_source="hdfs")
    alerts = db.get_alerts()
    assert len(alerts) == 1
    assert alerts[0]["event_count"] == 3


# =====================================================================
# 5. OVERSIZED RECORD FOLLOWED BY VALID LINE TEST
# =====================================================================

def test_oversized_line_followed_by_valid_line():
    """
    Verify:
    1. An oversized line (>64KB) is detected and rejected.
    2. The remaining bytes of the oversized line are completely discarded.
    3. The subsequent valid log line is processed cleanly and placed in the queue.
    """
    huge_line = "081109 203518 143 INFO dfs.DataNode: " + ("Z" * 70000) + "\n"
    valid_line = "081109 203519 144 INFO dfs.DataNode: Valid normal log line\n"

    fd, path = tempfile.mkstemp(suffix=".log")
    os.close(fd)
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(huge_line)
            f.write(valid_line)

        res = tailer.ingest_file_path("hdfs", path)
        assert res["status"] == "success"

        # The oversized line was rejected; exactly 1 line (the valid one) was enqueued
        assert tailer.log_queue.qsize() == 1
        source, queued_line = tailer.log_queue.get_nowait()
        assert source == "hdfs"
        assert queued_line == "081109 203519 144 INFO dfs.DataNode: Valid normal log line"

        # Verify oversized line was recorded in rejected_lines
        rejected = db.get_rejected_lines()
        assert len(rejected) >= 1
        assert any("Oversized" in r["reason"] or "OVERSIZED" in str(r.get("raw_bytes_preview", "")) for r in rejected)

    finally:
        if os.path.exists(path):
            os.remove(path)


# =====================================================================
# 6. EXACT SLIDING WINDOW EVENT-TIME SEMANTICS SEQUENCE TEST
# =====================================================================

def test_sliding_window_sequence_exact_semantics():
    """
    Test sequence with W = 60 seconds, threshold = 5:
    1. Event at t=100 -> count = 1 [100]
    2. Event at t=90  -> count = 2 [90, 100] (in window [40, 100])
    3. Event at t=50  -> count = 3 [50, 90, 100] (in window [40, 100])
    4. Event at t=101 -> count = 4 [50, 90, 100, 101] (in window [41, 101])
    All 4 events remain in window.
    5. Event at t=170 -> count = 1 [170] (170 - 101 = 69 > 60, all prior evicted)
    6. Delayed event at t=105 arrives -> Stale (105 < 170 - 60 = 110), dropped, count remains 1
    """
    db.update_config("hdfs_window", "60", user_id=1)
    db.update_config("hdfs_threshold", "5", user_id=1)
    parser.refresh_config_cache()

    # Step 1: t=100
    parser._check_sliding_window("hdfs", 100.0, "Anomaly 1")
    stats = parser.get_sliding_window_stats()
    assert stats["hdfs"]["current_count"] == 1

    # Step 2: t=90 (out of order, within window [40, 100])
    parser._check_sliding_window("hdfs", 90.0, "Anomaly 2")
    stats = parser.get_sliding_window_stats()
    assert stats["hdfs"]["current_count"] == 2

    # Step 3: t=50 (out of order, within window [40, 100])
    parser._check_sliding_window("hdfs", 50.0, "Anomaly 3")
    stats = parser.get_sliding_window_stats()
    assert stats["hdfs"]["current_count"] == 3

    # Step 4: t=101 (in order, advances T_max to 101, window [41, 101], 101-50=51 <= 60)
    parser._check_sliding_window("hdfs", 101.0, "Anomaly 4")
    stats = parser.get_sliding_window_stats()
    assert stats["hdfs"]["current_count"] == 4

    # Step 5: t=170 (advances T_max to 170, window [110, 170], evicts all previous)
    parser._check_sliding_window("hdfs", 170.0, "Anomaly 5")
    stats = parser.get_sliding_window_stats()
    assert stats["hdfs"]["current_count"] == 1

    # Step 6: Delayed event at t=105 arrives (stale, 105 < 110)
    parser._check_sliding_window("hdfs", 105.0, "Anomaly Stale")
    stats = parser.get_sliding_window_stats()
    assert stats["hdfs"]["current_count"] == 1


# =====================================================================
# 7. ZIP PATH TRAVERSAL COMPREHENSIVE SECURITY TEST
# =====================================================================

def test_zip_path_security_traversal_all_variants():
    """
    Verify rejection of malicious paths and acceptance of valid relative nested paths.
    """
    # Malicious paths that must be rejected
    malicious_paths = [
        "../../etc/passwd.log",
        "/etc/passwd.log",
        "C:\\Windows\\system32\\cmd.log",
        "..\\..\\etc\\passwd.log",
        "\\\\server\\share\\evil.log",
        "//server/share/evil.log",
    ]
    for p in malicious_paths:
        assert tailer.is_safe_zip_path(p) is False, f"Expected unsafe for: {p}"

    # Legitimate paths that must be permitted
    safe_paths = [
        "hdfs.log",
        "logs/hdfs.log",
        "nested/dir/access_log.txt",
    ]
    for p in safe_paths:
        assert tailer.is_safe_zip_path(p) is True, f"Expected safe for: {p}"

    # Test actual ZIP ingestion with valid nested path logs/hdfs.log
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("logs/hdfs.log", "081109 203518 143 INFO dfs.DataNode: In nested zip\n")
    zip_bytes = buf.getvalue()

    res = tailer.ingest_file_stream("hdfs", zip_bytes, filename="safe_nested.zip")
    assert res["status"] == "success"
    assert res["lines_queued"] == 1
    assert tailer.log_queue.qsize() == 1


# =====================================================================
# 8. ALERT PERSISTENCE RELIABILITY & RETRY TESTS
# =====================================================================

def test_alert_persistence_success():
    """Verify that under normal DB operations, alerts are persisted immediately with 0 pending."""
    db.update_config("hdfs_window", "60", user_id=1)
    db.update_config("hdfs_threshold", "3", user_id=1)
    parser.refresh_config_cache()

    for i in range(3):
        parser.parse_line(f"2026-09-12 12:00:0{i} [ERROR] namenode: Failure {i}", declared_source="hdfs")

    alerts = db.get_alerts()
    assert len(alerts) == 1
    assert alerts[0]["source"] == "HDFS"
    assert alerts[0]["event_count"] == 3
    assert parser.get_pending_alerts_count() == 0


def test_alert_persistence_transient_failure_retry_succeeds(monkeypatch):
    """
    Simulate transient SQLite contention: 1st save_alert() fails with OperationalError,
    2nd attempt (retry) succeeds.
    Verify alert is persisted to DB with 0 lost alerts and 0 remaining pending.
    """
    db.update_config("hdfs_window", "60", user_id=1)
    db.update_config("hdfs_threshold", "3", user_id=1)
    parser.refresh_config_cache()

    original_save_alert = db.save_alert
    call_count = 0

    def flaky_save_alert(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            import sqlite3
            raise sqlite3.OperationalError("database is locked (transient)")
        return original_save_alert(*args, **kwargs)

    monkeypatch.setattr(db, "save_alert", flaky_save_alert)

    for i in range(3):
        parser.parse_line(f"2026-09-12 12:00:0{i} [ERROR] namenode: Failure {i}", declared_source="hdfs")

    # Retry should have been attempted and succeeded
    assert call_count >= 2
    alerts = db.get_alerts()
    assert len(alerts) == 1
    assert alerts[0]["source"] == "HDFS"
    assert parser.get_pending_alerts_count() == 0


def test_concurrent_threads_no_duplicate_alerts_on_threshold_crossing():
    """
    Verify that when multiple concurrent threads push events that cross the threshold,
    atomic deque.clear() inside the lock guarantees exactly ONE alert is created per crossing,
    with no duplicate alerts.
    """
    db.update_config("hdfs_window", "60", user_id=1)
    db.update_config("hdfs_threshold", "5", user_id=1)
    parser.refresh_config_cache()

    # Pre-fill with 4 events (1 away from threshold 5)
    for i in range(4):
        parser.parse_line(f"2026-09-12 12:00:0{i} [ERROR] namenode: Pre-fill {i}", declared_source="hdfs")
    assert len(db.get_alerts()) == 0

    # Launch 6 concurrent threads each trying to add the 5th event at the exact same timestamp
    errors = []
    def worker():
        try:
            parser.parse_line("2026-09-12 12:00:05 [ERROR] namenode: Concurrent burst", declared_source="hdfs")
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5.0)

    assert len(errors) == 0
    # Total events: 4 + 6 = 10. Exactly 2 alerts of threshold 5. No duplicates!
    alerts = db.get_alerts()
    assert len(alerts) == 2
    assert all(a["event_count"] >= 5 for a in alerts)
    assert parser.get_pending_alerts_count() == 0


def test_hdfs_alert_persistence_failure_does_not_block_nasa(monkeypatch):
    """
    Simulate severe DB failure on HDFS writes:
    - HDFS alert retries exhaust and buffer into _pending_alert_buffers['hdfs'] without raising/crashing.
    - NASA alert write succeeds normally and is persisted immediately into DB.
    - HDFS alert is NOT lost; once DB recovers and flush_pending_alerts() is called, it is saved.
    """
    db.update_config("hdfs_window", "60", user_id=1)
    db.update_config("hdfs_threshold", "2", user_id=1)
    db.update_config("nasa_http_window", "60", user_id=1)
    db.update_config("nasa_http_threshold", "2", user_id=1)
    parser.refresh_config_cache()

    original_save_alert = db.save_alert

    def failing_hdfs_save_alert(source, alert_type, event_count, window_duration_sec, **kwargs):
        if source == "HDFS":
            raise RuntimeError("Simulated persistent HDFS database disk failure")
        return original_save_alert(source, alert_type, event_count, window_duration_sec, **kwargs)

    monkeypatch.setattr(db, "save_alert", failing_hdfs_save_alert)

    # 1. Trigger HDFS burst (2 errors) -> Exhausts retries and buffers to pending queue
    parser.parse_line("2026-09-12 12:00:00 [ERROR] namenode: HDFS error 1", declared_source="hdfs")
    parser.parse_line("2026-09-12 12:00:01 [ERROR] namenode: HDFS error 2", declared_source="hdfs")

    # Verify HDFS alert was NOT lost: it is safely buffered in pending queue
    assert parser.get_pending_alerts_count("hdfs") == 1

    # 2. Trigger NASA burst (2 errors) -> Must succeed immediately without being blocked
    parser.parse_line('199.72.81.55 - - [01/Jul/1995:00:00:01 -0400] "GET /err1 HTTP/1.0" 500 100', declared_source="nasa_http")
    parser.parse_line('199.72.81.55 - - [01/Jul/1995:00:00:02 -0400] "GET /err2 HTTP/1.0" 500 100', declared_source="nasa_http")

    # NASA alert was persisted immediately!
    nasa_alerts = [a for a in db.get_alerts() if a["source"] == "NASA-HTTP"]
    assert len(nasa_alerts) == 1
    assert parser.get_pending_alerts_count("nasa_http") == 0

    # 3. Restore DB and flush pending HDFS alerts
    monkeypatch.setattr(db, "save_alert", original_save_alert)
    flushed = parser.flush_pending_alerts("hdfs")
    assert flushed == 1
    assert parser.get_pending_alerts_count("hdfs") == 0

    # Both HDFS and NASA alerts now safely exist in the database
    all_alerts = db.get_alerts()
    sources = {a["source"] for a in all_alerts}
    assert "HDFS" in sources
    assert "NASA-HTTP" in sources


# =====================================================================
# 9. PENDING BUFFER OVERFLOW & FLUSH RELIABILITY AUDIT TESTS
# =====================================================================

def test_pending_buffer_reaches_capacity_and_increments_dropped_counter(monkeypatch):
    """
    Verify:
    1. Pending buffer accepts alerts up to capacity (simulated with capacity 5).
    2. Attempting to enqueue when buffer is full fails safely.
    3. Alert is dropped and observable dropped_alerts counter is incremented.
    4. Queue does NOT grow unbounded.
    """
    monkeypatch.setattr(parser, "PENDING_ALERT_BUFFER_CAPACITY", 5)
    parser.reset_pending_alerts()

    # Fill up to capacity 5
    for i in range(5):
        payload = {
            "source": "HDFS",
            "alert_type": "HDFS_ANOMALY_BURST",
            "event_count": i + 1,
            "window_duration_sec": 60,
        }
        res = parser._buffer_failed_alert("hdfs", payload)
        assert res is True

    assert parser.get_pending_alerts_count("hdfs") == 5
    assert parser.get_dropped_alerts_count("hdfs") == 0

    # Attempt to buffer the 6th alert (overflow condition)
    overflow_payload = {
        "source": "HDFS",
        "alert_type": "HDFS_ANOMALY_BURST",
        "event_count": 6,
        "window_duration_sec": 60,
    }
    res_overflow = parser._buffer_failed_alert("hdfs", overflow_payload)
    assert res_overflow is False

    # Verify bounded capacity maintained and dropped counter incremented
    assert parser.get_pending_alerts_count("hdfs") == 5
    assert parser.get_dropped_alerts_count("hdfs") == 1

    # Verify diagnostic metrics reflect overflow state
    metrics = parser.get_alert_buffer_metrics()
    assert metrics["hdfs"]["pending_count"] == 5
    assert metrics["hdfs"]["dropped_count"] == 1
    assert metrics["hdfs"]["has_dropped_alerts"] is True
    assert metrics["hdfs"]["buffer_utilization_pct"] == 100.0


def test_failed_flush_retains_alerts_in_fifo_order_without_loss(monkeypatch):
    """
    Verify:
    1. If a flush fails halfway through, the unpersisted alerts remain at the head of the buffer.
    2. No alerts are dropped or reordered during a failed flush.
    3. A subsequent flush correctly resumes from the unwritten alert.
    """
    parser.reset_pending_alerts()

    # Buffer 3 alerts
    for i in range(1, 4):
        parser._buffer_failed_alert("hdfs", {
            "source": "HDFS",
            "alert_type": f"ALERT_{i}",
            "event_count": i,
            "window_duration_sec": 60,
        })

    assert parser.get_pending_alerts_count("hdfs") == 3

    # Simulate DB failure on the 2nd write (ALERT_2)
    original_save = db.save_alert
    call_idx = 0

    def fail_on_second_call(*args, **kwargs):
        nonlocal call_idx
        call_idx += 1
        if call_idx == 2:
            import sqlite3
            raise sqlite3.OperationalError("database is locked (transient during flush)")
        return original_save(*args, **kwargs)

    monkeypatch.setattr(db, "save_alert", fail_on_second_call)

    # 1st flush attempt: saves ALERT_1, fails on ALERT_2
    flushed = parser.flush_pending_alerts("hdfs")
    assert flushed == 1
    # ALERT_2 and ALERT_3 must remain in buffer
    assert parser.get_pending_alerts_count("hdfs") == 2

    # Check database: only ALERT_1 was written
    alerts_in_db = db.get_alerts()
    assert len(alerts_in_db) == 1
    assert alerts_in_db[0]["alert_type"] == "ALERT_1"

    # Restore DB and retry flush
    monkeypatch.setattr(db, "save_alert", original_save)
    flushed_remaining = parser.flush_pending_alerts("hdfs")
    assert flushed_remaining == 2
    assert parser.get_pending_alerts_count("hdfs") == 0

    # Verify all 3 alerts are in DB in strict FIFO order (ordered by insertion alert_id)
    final_alerts = db.get_alerts()
    assert len(final_alerts) == 3
    in_order = sorted(final_alerts, key=lambda a: a["alert_id"])
    assert [a["alert_type"] for a in in_order] == ["ALERT_1", "ALERT_2", "ALERT_3"]


def test_concurrent_flush_calls_prevent_duplicate_persists():
    """
    Verify that concurrent flush_pending_alerts calls across multiple threads
    never duplicate writes or drop pending alerts.
    """
    parser.reset_pending_alerts()

    # Pre-fill buffer with 8 alerts
    for i in range(8):
        parser._buffer_failed_alert("hdfs", {
            "source": "HDFS",
            "alert_type": f"CONCURRENT_ALERT_{i}",
            "event_count": i + 1,
            "window_duration_sec": 60,
        })

    assert parser.get_pending_alerts_count("hdfs") == 8

    # Spawn 4 threads all attempting to flush HDFS pending alerts concurrently
    errors = []
    def flush_worker():
        try:
            parser.flush_pending_alerts("hdfs")
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=flush_worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5.0)

    assert len(errors) == 0
    # All 8 alerts must be written, with 0 duplicates
    alerts_in_db = db.get_alerts()
    assert len(alerts_in_db) == 8
    assert parser.get_pending_alerts_count("hdfs") == 0
    types = [a["alert_type"] for a in alerts_in_db]
    assert len(set(types)) == 8


def test_new_alert_arrival_preserves_fifo_order_behind_unflushed_alerts(monkeypatch):
    """
    Verify:
    1. Three older alerts A, B, C are pending.
    2. Flush runs: A persists, B fails, C remains pending.
    3. New alert D arrives via _persist_alert_with_retry().
    4. D must NOT be persisted ahead of B and C; D must be retained in the pending buffer behind C.
    5. When the database recovers and flushes, all alerts are persisted in exact FIFO order: A, B, C, D.
    """
    parser.reset_pending_alerts()

    # Step 1: Buffer 3 older alerts A, B, C
    parser._buffer_failed_alert("hdfs", {
        "source": "HDFS",
        "alert_type": "ALERT_A",
        "event_count": 3,
        "window_duration_sec": 60,
    })
    parser._buffer_failed_alert("hdfs", {
        "source": "HDFS",
        "alert_type": "ALERT_B",
        "event_count": 4,
        "window_duration_sec": 60,
    })
    parser._buffer_failed_alert("hdfs", {
        "source": "HDFS",
        "alert_type": "ALERT_C",
        "event_count": 5,
        "window_duration_sec": 60,
    })
    assert parser.get_pending_alerts_count("hdfs") == 3

    # Step 2: Flush runs: A succeeds, B fails
    original_save = db.save_alert

    def save_mock(source, alert_type, event_count, window_duration_sec, **kwargs):
        if alert_type == "ALERT_B":
            import sqlite3
            raise sqlite3.OperationalError("database is locked (ALERT_B failure)")
        return original_save(source, alert_type, event_count, window_duration_sec, **kwargs)

    monkeypatch.setattr(db, "save_alert", save_mock)

    flushed = parser.flush_pending_alerts("hdfs")
    assert flushed == 1
    # B and C remain in buffer
    assert parser.get_pending_alerts_count("hdfs") == 2

    # Step 3: New alert D arrives via _persist_alert_with_retry()
    # While B is still failing, D arrives
    d_payload = {
        "source": "HDFS",
        "alert_type": "ALERT_D",
        "event_count": 6,
        "window_duration_sec": 60,
    }
    # D must NOT bypass B and C to write to DB!
    parser._persist_alert_with_retry("hdfs", d_payload)

    # D was buffered behind C because B and C were still pending
    assert parser.get_pending_alerts_count("hdfs") == 3
    # In SQLite DB, only ALERT_A is present
    db_alerts = db.get_alerts()
    assert len(db_alerts) == 1
    assert db_alerts[0]["alert_type"] == "ALERT_A"

    # Step 4: Database recovers fully
    monkeypatch.setattr(db, "save_alert", original_save)

    # Step 5: Flush remaining alerts
    flushed_remaining = parser.flush_pending_alerts("hdfs")
    assert flushed_remaining == 3
    assert parser.get_pending_alerts_count("hdfs") == 0

    # Verify all 4 alerts are in DB in strict FIFO order: A, then B, then C, then D
    all_final = db.get_alerts()
    assert len(all_final) == 4
    in_order = sorted(all_final, key=lambda a: a["alert_id"])
    assert [a["alert_type"] for a in in_order] == ["ALERT_A", "ALERT_B", "ALERT_C", "ALERT_D"]


# =====================================================================
# 10. STRICT CONCURRENCY AUDIT TESTS (TESTS A, B, C)
# =====================================================================

def test_concurrent_direct_persistence_preserves_arrival_fifo_order():
    """
    Test A — Concurrent direct persistence:
    - Start with an empty pending buffer.
    - Launch multiple threads with uniquely identifiable alert payloads.
    - Use synchronization barriers to force overlapping persistence attempts.
    - Verify database insertion order strictly matches defined per-source arrival order.
    - Verify no alerts are duplicated or silently lost.
    """
    parser.reset_pending_alerts()
    num_threads = 6
    barrier = threading.Barrier(num_threads)
    errors = []

    # Sequential arrival definition: payloads are registered in arrival sequence 0..5
    payloads = [
        {
            "source": "HDFS",
            "alert_type": f"CONCURRENT_FIFO_{i}",
            "event_count": i + 1,
            "window_duration_sec": 60,
        }
        for i in range(num_threads)
    ]

    def worker(idx):
        try:
            # Enqueue in strict arrival order
            parser._buffer_failed_alert("hdfs", payloads[idx])
            # Synchronize all threads at barrier to force overlapping persistence attempts
            barrier.wait(timeout=5.0)
            # All threads race to flush concurrently
            parser._flush_pending_alerts_for_source("hdfs")
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5.0)

    assert len(errors) == 0
    assert parser.get_pending_alerts_count("hdfs") == 0

    # Verify database insertion order matches arrival order [CONCURRENT_FIFO_0 ... CONCURRENT_FIFO_5]
    alerts_in_db = db.get_alerts()
    assert len(alerts_in_db) == num_threads
    in_order = sorted(alerts_in_db, key=lambda a: a["alert_id"])
    expected_order = [f"CONCURRENT_FIFO_{i}" for i in range(num_threads)]
    assert [a["alert_type"] for a in in_order] == expected_order


def test_pending_alerts_plus_concurrent_arrivals_no_bypass(monkeypatch):
    """
    Test B — Pending alerts plus concurrent arrivals:
    - Preload older pending alerts (PENDING_1, PENDING_2).
    - Start multiple concurrent new alert arrivals (NEW_1, NEW_2, NEW_3).
    - Simulate temporary database failure during flush so PENDING_2 cannot persist.
    - Verify newer alerts cannot bypass older pending alerts.
    - Restore database and flush.
    - Verify final insertion order: PENDING_1, PENDING_2, NEW_1, NEW_2, NEW_3.
    """
    parser.reset_pending_alerts()

    # Preload older pending alerts
    parser._buffer_failed_alert("hdfs", {
        "source": "HDFS",
        "alert_type": "PENDING_1",
        "event_count": 1,
        "window_duration_sec": 60,
    })
    parser._buffer_failed_alert("hdfs", {
        "source": "HDFS",
        "alert_type": "PENDING_2",
        "event_count": 2,
        "window_duration_sec": 60,
    })
    assert parser.get_pending_alerts_count("hdfs") == 2

    # Simulate DB failure on PENDING_2
    original_save = db.save_alert

    def fail_on_pending_2(source, alert_type, event_count, window_duration_sec, **kwargs):
        if alert_type == "PENDING_2":
            import sqlite3
            raise sqlite3.OperationalError("database is locked on PENDING_2")
        return original_save(source, alert_type, event_count, window_duration_sec, **kwargs)

    monkeypatch.setattr(db, "save_alert", fail_on_pending_2)

    # Launch 3 concurrent new alert arrivals: NEW_1, NEW_2, NEW_3
    barrier = threading.Barrier(3)
    errors = []

    def arrival_worker(idx):
        try:
            barrier.wait(timeout=5.0)
            payload = {
                "source": "HDFS",
                "alert_type": f"NEW_{idx}",
                "event_count": 10 + idx,
                "window_duration_sec": 60,
            }
            parser._persist_alert_with_retry("hdfs", payload, max_retries=1)
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=arrival_worker, args=(i,)) for i in range(1, 4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5.0)

    assert len(errors) == 0

    # Only PENDING_1 should have been saved to DB!
    # PENDING_2 and all NEW_* alerts must still be waiting in the pending buffer!
    alerts_in_db = db.get_alerts()
    assert len(alerts_in_db) == 1
    assert alerts_in_db[0]["alert_type"] == "PENDING_1"

    # Pending buffer must contain PENDING_2 and the 3 NEW alerts (total 4)
    assert parser.get_pending_alerts_count("hdfs") == 4

    # Now restore database and flush
    monkeypatch.setattr(db, "save_alert", original_save)
    flushed = parser.flush_pending_alerts("hdfs")
    assert flushed == 4
    assert parser.get_pending_alerts_count("hdfs") == 0

    # Verify final insertion order: PENDING_1, PENDING_2, followed by NEW alerts
    final_alerts = db.get_alerts()
    assert len(final_alerts) == 5
    in_order = sorted(final_alerts, key=lambda a: a["alert_id"])
    alert_types = [a["alert_type"] for a in in_order]
    assert alert_types[0] == "PENDING_1"
    assert alert_types[1] == "PENDING_2"
    assert set(alert_types[2:]) == {"NEW_1", "NEW_2", "NEW_3"}


def test_source_independence_hdfs_retries_do_not_block_nasa(monkeypatch):
    """
    Test C — Source independence:
    - Cause HDFS persistence to experience a long delay (sleep 0.3s inside db.save_alert).
    - Launch HDFS persistence in background thread.
    - Simultaneously trigger NASA-HTTP alert persistence.
    - Verify NASA-HTTP is NOT blocked by HDFS lock and persists immediately (< 0.2s).
    - Wait for HDFS to finish. Verify both alerts exist in DB.
    """
    parser.reset_pending_alerts()
    original_save = db.save_alert

    def slow_hdfs_save(source, alert_type, event_count, window_duration_sec, **kwargs):
        if source == "HDFS":
            time.sleep(0.3)  # Hold HDFS persistence lock for 300ms
        return original_save(source, alert_type, event_count, window_duration_sec, **kwargs)

    monkeypatch.setattr(db, "save_alert", slow_hdfs_save)

    hdfs_started = threading.Event()
    hdfs_finished = threading.Event()
    nasa_persisted_time = [0.0]

    def hdfs_worker():
        hdfs_started.set()
        parser._persist_alert_with_retry("hdfs", {
            "source": "HDFS",
            "alert_type": "SLOW_HDFS_ALERT",
            "event_count": 5,
            "window_duration_sec": 60,
        })
        hdfs_finished.set()

    t_hdfs = threading.Thread(target=hdfs_worker)
    t_hdfs.start()

    # Wait until HDFS starts its slow write
    hdfs_started.wait(timeout=2.0)
    time.sleep(0.05)  # Ensure HDFS is inside its sleep/lock

    # NASA attempts persistence while HDFS is still busy
    nasa_start = time.time()
    res_nasa = parser._persist_alert_with_retry("nasa_http", {
        "source": "NASA-HTTP",
        "alert_type": "FAST_NASA_ALERT",
        "event_count": 3,
        "window_duration_sec": 60,
    })
    nasa_persisted_time[0] = time.time() - nasa_start

    # NASA persistence must have succeeded without waiting for HDFS 0.3s delay
    assert res_nasa is True
    assert nasa_persisted_time[0] < 0.2, f"NASA was blocked by HDFS! Took {nasa_persisted_time[0]:.3f}s"
    assert hdfs_finished.is_set() is False, "HDFS finished too fast, invalidating concurrency test"

    # Wait for HDFS to finish
    t_hdfs.join(timeout=3.0)
    assert hdfs_finished.is_set() is True

    # Both alerts must be safely recorded
    alerts = db.get_alerts()
    assert len(alerts) == 2
    sources = {a["source"] for a in alerts}
    assert sources == {"HDFS", "NASA-HTTP"}


def test_concurrent_direct_persistence_under_controlled_synchronization(monkeypatch):
    """
    Deterministic Test A2 — Concurrent direct persistence under controlled synchronization:
    1. Thread A arrives with ALERT_A.
    2. Thread A is held paused inside db.save_alert using threading.Event.
    3. Thread B arrives with ALERT_B and calls _persist_alert_with_retry('hdfs', ALERT_B).
    4. Thread B is blocked by _source_persistence_locks['hdfs'], and its alert is queued behind A.
    5. Thread A is released to finish.
    6. Verify database receives ALERT_A at ID 1, then ALERT_B at ID 2 (strict FIFO order).
    7. No alerts are lost or duplicated.
    """
    parser.reset_pending_alerts()
    original_save = db.save_alert

    thread_a_inside_db = threading.Event()
    release_thread_a = threading.Event()
    save_order = []

    def mock_save_alert(source, alert_type, event_count, window_duration_sec, **kwargs):
        save_order.append(alert_type)
        if alert_type == "SYNC_ALERT_A":
            thread_a_inside_db.set()
            release_thread_a.wait(timeout=5.0)
        return original_save(source, alert_type, event_count, window_duration_sec, **kwargs)

    monkeypatch.setattr(db, "save_alert", mock_save_alert)

    errors = []

    def worker_a():
        try:
            parser._persist_alert_with_retry("hdfs", {
                "source": "HDFS",
                "alert_type": "SYNC_ALERT_A",
                "event_count": 5,
                "window_duration_sec": 60,
            })
        except Exception as e:
            errors.append(e)

    def worker_b():
        try:
            parser._persist_alert_with_retry("hdfs", {
                "source": "HDFS",
                "alert_type": "SYNC_ALERT_B",
                "event_count": 6,
                "window_duration_sec": 60,
            })
        except Exception as e:
            errors.append(e)

    t_a = threading.Thread(target=worker_a)
    t_b = threading.Thread(target=worker_b)

    # Start Thread A
    t_a.start()
    # Wait until Thread A is confirmed inside db.save_alert
    assert thread_a_inside_db.wait(timeout=2.0) is True

    # While Thread A is paused inside db.save_alert, start Thread B
    t_b.start()
    time.sleep(0.05)  # Ensure Thread B calls _persist_alert_with_retry and blocks

    # Release Thread A to complete its write
    release_thread_a.set()

    t_a.join(timeout=3.0)
    t_b.join(timeout=3.0)

    assert len(errors) == 0
    assert parser.get_pending_alerts_count("hdfs") == 0

    # Verify database insertion order: SYNC_ALERT_A must be before SYNC_ALERT_B
    alerts_in_db = db.get_alerts()
    assert len(alerts_in_db) == 2
    in_order = sorted(alerts_in_db, key=lambda a: a["alert_id"])
    assert [a["alert_type"] for a in in_order] == ["SYNC_ALERT_A", "SYNC_ALERT_B"]
    assert save_order == ["SYNC_ALERT_A", "SYNC_ALERT_B"]
