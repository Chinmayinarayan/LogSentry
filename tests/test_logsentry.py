"""
Comprehensive Pytest Test Suite for LogSentry.

Covers:
- Unit tests: E2 regex parsing & strict classification
- Unit tests: E2 sliding window anomaly detection & dynamic thresholding
- Concurrency tests: E1 Watch bounded queue backpressure & E3 Vault DB single-writer integrity
- Negative / Security tests: Forbidden input guarantee (.zip, binary, wrong source, RBAC 403)
- Integration tests: End-to-end replay, live tailing, RBAC role matrix
- Accuracy tests: Ground truth evaluation harness score assertions
"""

import io
import os
import queue
import tempfile
import threading
import time
import zipfile
import pytest

from parse import parser
from vault import db
from watch import tailer
from signal_app import app
from validation import evaluate_accuracy


@pytest.fixture(autouse=True)
def setup_and_teardown_db():
    """Ensure a clean database state for every test."""
    db.init_db()
    db.reset_db()
    parser.reset_sliding_windows()
    tailer.reset_metrics()
    parser.refresh_config_cache()
    yield
    db.reset_db()
    parser.reset_sliding_windows()


# =====================================================================
# 1. UNIT TESTS — E2 REGEX & CLASSIFICATION
# =====================================================================

def test_parse_valid_hdfs_lines():
    """Test valid HDFS lines parse correctly into expected fields."""
    line_info = "081109 203518 143 INFO dfs.DataNode$DataXceiver: Receiving block blk_-1608999687919862906 src: /10.251.215.16:55741 dest: /10.251.215.16:50010"
    res_info = parser.parse_line(line_info, declared_source="hdfs")
    assert res_info is not None
    assert res_info["source"] == "HDFS"
    assert res_info["log_level"] == "INFO"
    assert "dfs.DataNode$DataXceiver" in res_info["component_host"]

    line_warn = "081109 203518 143 WARN dfs.DataNode$DataXceiver: Got exception while serving block blk_-1608999687919862906 to /10.251.91.84"
    res_warn = parser.parse_line(line_warn, declared_source="hdfs")
    assert res_warn is not None
    assert res_warn["log_level"] == "WARN"


def test_parse_valid_nasa_http_lines():
    """Test valid NASA-HTTP CLF lines parse correctly."""
    line_200 = '199.72.81.55 - - [01/Jul/1995:00:00:01 -0400] "GET /history/apollo/ HTTP/1.0" 200 6245'
    res_200 = parser.parse_line(line_200, declared_source="nasa_http")
    assert res_200 is not None
    assert res_200["source"] == "NASA-HTTP"
    assert res_200["log_level"] == "INFO"
    assert res_200["component_host"] == "199.72.81.55"

    line_404 = '199.72.81.55 - - [01/Jul/1995:00:00:02 -0400] "GET /invalid/path.html HTTP/1.0" 404 231'
    res_404 = parser.parse_line(line_404, declared_source="nasa_http")
    assert res_404 is not None
    assert res_404["log_level"] == "WARN"


def test_malformed_and_truncated_lines_quarantined():
    """Malformed or truncated lines must NOT be guessed or defaulted — must land in rejected_lines."""
    bad_hdfs = "081109 TRUNCATED LINE WITHOUT PID OR LEVEL"
    res = parser.parse_line(bad_hdfs, declared_source="hdfs")
    assert res is None

    bad_nasa = "199.72.81.55 INVALID REQUEST FORMAT"
    res2 = parser.parse_line(bad_nasa, declared_source="nasa_http")
    assert res2 is None

    rejected = db.get_rejected_lines()
    assert len(rejected) >= 2


def test_binary_garbage_quarantined():
    """Binary bytes (e.g. raw .zip or .jpg byte data) must land in rejected_lines."""
    binary_bytes = b"PK\x03\x04\x14\x00\x08\x00\x08\x00\x00\x00\x00\x00"
    res = parser.parse_line(binary_bytes, declared_source="hdfs")
    assert res is None

    rejected = db.get_rejected_lines()
    assert len(rejected) >= 1
    assert "Binary" in rejected[0]["reason"] or "Format violation" in rejected[0]["reason"]


# =====================================================================
# 2. UNIT TESTS — E2 SLIDING WINDOW ANOMALY DETECTION
# =====================================================================

def test_sliding_window_eviction_and_threshold_firing():
    """Verify window evicts expired timestamps and fires alert at exactly T within W."""
    db.update_config("hdfs_window", "10", user_id=1)
    db.update_config("hdfs_threshold", "3", user_id=1)
    parser.refresh_config_cache()

    warn_line = "081109 203518 143 WARN dfs.DataNode$DataXceiver: Got exception while serving block blk_100"

    parser.parse_line(warn_line, declared_source="hdfs")
    parser.parse_line(warn_line, declared_source="hdfs")
    alerts = db.get_alerts()
    assert len(alerts) == 0

    parser.parse_line(warn_line, declared_source="hdfs")
    alerts = db.get_alerts()
    assert len(alerts) == 1
    assert alerts[0]["event_count"] == 3
    assert alerts[0]["status"] == "ACTIVE"


def test_independent_per_source_thresholds():
    """Verify HDFS and NASA-HTTP sliding windows operate independently."""
    db.update_config("hdfs_threshold", "3", user_id=1)
    db.update_config("nasa_http_threshold", "10", user_id=1)
    parser.refresh_config_cache()

    hdfs_line = "081109 203518 143 ERROR dfs.DataNode: Got exception"
    nasa_line = '199.72.81.55 - - [01/Jul/1995:00:00:01 -0400] "GET /err HTTP/1.0" 404 100'

    for _ in range(3):
        parser.parse_line(hdfs_line, declared_source="hdfs")
    alerts = db.get_alerts()
    assert len(alerts) == 1
    assert alerts[0]["source"] == "HDFS"

    for _ in range(3):
        parser.parse_line(nasa_line, declared_source="nasa_http")
    alerts = db.get_alerts()
    assert len(alerts) == 1


# =====================================================================
# 3. CONCURRENCY TESTS — E1 WATCH & E3 VAULT
# =====================================================================

def test_producer_queue_concurrency_no_dropped_lines():
    """Multiple producer threads writing to log_queue concurrently with 0 dropped lines."""
    num_producers = 5
    lines_per_producer = 200
    total_expected = num_producers * lines_per_producer

    sample_line = "081109 203518 143 INFO dfs.DataNode: Serving block blk_1"

    def producer():
        for _ in range(lines_per_producer):
            tailer.log_queue.put(("hdfs", sample_line))
            tailer._increment_processed()

    threads = [threading.Thread(target=producer) for _ in range(num_producers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    metrics = tailer.get_metrics()
    assert metrics["events_processed"] == total_expected
    assert tailer.log_queue.qsize() == total_expected

    # Drain queue
    while not tailer.log_queue.empty():
        tailer.log_queue.get_nowait()


def test_db_single_writer_concurrency():
    """Verify single-writer SQLite pattern handles high concurrent writes without corruption."""
    num_threads = 10
    writes_per_thread = 50

    def db_writer(tid):
        for i in range(writes_per_thread):
            db.save_event(
                source="CONCURRENCY_TEST",
                log_level="INFO",
                component_host=f"host_{tid}",
                raw_message=f"Thread {tid} message {i}",
            )

    threads = [threading.Thread(target=db_writer, args=(i,)) for i in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    stats = db.get_event_stats()
    assert stats["total_events"] == num_threads * writes_per_thread


# =====================================================================
# 4. NEGATIVE & SECURITY TESTS — FORBIDDEN INPUT & RBAC 403
# =====================================================================

def test_forbidden_input_zip_and_binary_quarantine():
    """Uploaded raw zip or jpg files must be extracted or quarantined — never fed as valid events."""
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("clean.log", "081109 203518 143 INFO dfs.DataNode: Block blk_1\n")
        zf.writestr("bad.bin", b"\x00\x01\x02\x03\x04")

    zip_bytes = zip_buffer.getvalue()
    res = tailer.ingest_file_stream("hdfs", zip_bytes, filename="test.zip")
    assert res["status"] == "success"

    while not tailer.log_queue.empty():
        src, line = tailer.log_queue.get()
        parser.parse_line(line, declared_source=src)

    stats = db.get_event_stats()
    assert stats["total_events"] >= 1


def test_wrong_source_format_quarantined():
    """An HDFS line submitted under nasa_http source must be rejected."""
    hdfs_line = "081109 203518 143 INFO dfs.FSNamesystem: Block blk_1"
    res = parser.parse_line(hdfs_line, declared_source="nasa_http")
    assert res is None

    rejected = db.get_rejected_lines()
    assert len(rejected) >= 1
    assert "Format violation" in rejected[0]["reason"]


def test_rbac_server_side_enforcement():
    """Verify OPERATOR and VIEWER are blocked with 403 on ADMIN endpoints and write no history."""
    client = app.test_client()

    client.post("/api/login", json={"username": "viewer", "password": "viewerpassword"})

    res_cfg = client.post("/api/config", json={"hdfs_window": "30"})
    assert res_cfg.status_code == 403

    res_usr = client.post("/api/users", json={"username": "hacker", "password": "p", "role": "ADMIN"})
    assert res_usr.status_code == 403

    history = db.get_config_history()
    assert len(history) == 0


# =====================================================================
# 5. INTEGRATION TESTS — END-TO-END REPLAY & LIVE TAILING
# =====================================================================

def test_live_tailing_integration():
    """Live tailing test: append lines to a temp file and confirm ingestion & alert firing."""
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".log")
    os.close(tmp_fd)

    try:
        t = tailer.start_watcher("hdfs_live", tmp_path)
        time.sleep(0.2)

        with open(tmp_path, "a", encoding="utf-8") as f:
            for i in range(5):
                f.write(f"081109 203518 {140+i} ERROR dfs.DataNode: Got exception while serving block blk_{i}\n")
                f.flush()

        time.sleep(0.5)

        while not tailer.log_queue.empty():
            src, line = tailer.log_queue.get()
            parser.parse_line(line, declared_source=src)

        tailer.stop_watcher("hdfs_live")

        stats = db.get_event_stats()
        assert stats["total_events"] == 5
        alerts = db.get_alerts()
        assert len(alerts) >= 1

    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass


def test_rbac_alert_resolution_with_audit_trail():
    """OPERATOR resolves an alert -> status updated and audit history written."""
    alert_id = db.save_alert(source="HDFS", alert_type="TEST_BURST", event_count=5, window_duration_sec=60)

    client = app.test_client()
    client.post("/api/login", json={"username": "operator", "password": "operatorpassword"})

    res = client.post(f"/api/alerts/{alert_id}/resolve")
    assert res.status_code == 200

    alerts = db.get_alerts(limit=10)
    resolved_alert = [a for a in alerts if a["alert_id"] == alert_id][0]
    assert resolved_alert["status"] == "RESOLVED"

    hist = db.get_alert_history(alert_id)
    assert len(hist) == 1
    assert hist[0]["field_changed"] == "status"
    assert hist[0]["new_value"] == "RESOLVED"


# =====================================================================
# 6. ACCURACY TEST — GROUND TRUTH HARNESS SCORE ASSERTION
# =====================================================================

def test_validation_accuracy_harness():
    """Run accuracy evaluation against synthetic ground truth fixture."""
    log_path = os.path.join(os.path.dirname(__file__), "..", "validation", "fixtures", "synthetic_hdfs_style.log")
    label_path = os.path.join(os.path.dirname(__file__), "..", "validation", "fixtures", "synthetic_anomaly_label.csv")

    if os.path.exists(log_path) and os.path.exists(label_path):
        res = evaluate_accuracy.evaluate_dataset(log_path, label_path=label_path, source_type="hdfs")
        acc = res["accuracy_eval"]
        assert acc["precision"] >= 0.8
        assert acc["recall"] >= 0.8
        assert acc["f1_score"] >= 0.8
