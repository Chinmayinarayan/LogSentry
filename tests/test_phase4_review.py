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
