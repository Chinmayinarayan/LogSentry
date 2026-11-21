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
