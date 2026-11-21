"""
Phase 4 Verification Test Suite — Engine 2 (E2 PARSE).

Covers FR-03, FR-04, FR-05, FR-06, NFR-03, NFR-04:
- Source-specific HDFS & NASA-HTTP validation
- Malformed, truncated, wrong-source, and binary record quarantine
- Severity level classification
- Independent source sliding-window deques (zero cross-source contamination)
- Dynamic threshold and window expiration
- Runtime configuration reload
- Integration with E1 bounded queue
"""

import time
import pytest

from parse import parser
from vault import db
from watch import tailer
from src.common.models import LogEvent


@pytest.fixture(autouse=True)
def clean_parser_state():
    """Ensure clean parser sliding windows and fresh DB state."""
    db.init_db()
    db.reset_db()
    parser.reset_sliding_windows()
    parser.refresh_config_cache()
    while not tailer.log_queue.empty():
        tailer.log_queue.get_nowait()
    yield
    parser.reset_sliding_windows()


# =====================================================================
# 1. SOURCE-SPECIFIC VALIDATION (FR-03)
# =====================================================================

def test_valid_hdfs_loghub_and_iso_formats():
    """FR-03: Validate both standard Loghub HDFS format and ISO datetime HDFS format."""
    # Standard Loghub format
    loghub_line = "081109 203518 143 INFO dfs.DataNode$DataXceiver: Receiving block blk_-1608999687919862906 src: /10.251.215.16:55741 dest: /10.251.215.16:50010"
    res1 = parser.parse_line(loghub_line, declared_source="hdfs")
    assert res1 is not None
    assert res1["source"] == "HDFS"
    assert res1["log_level"] == "INFO"
    assert "dfs.DataNode$DataXceiver" in res1["component_host"]
    assert "2008-11-09" in res1["timestamp"]

    # ISO datetime format
    iso_line = "2026-09-12 12:00:01 [WARN] namenode: Re-replication needed for block blk_9999"
    res2 = parser.parse_line(iso_line, declared_source="hdfs")
    assert res2 is not None
    assert res2["source"] == "HDFS"
    assert res2["log_level"] == "WARN"
    assert res2["component_host"] == "namenode"
    assert res2["timestamp"] == "2026-09-12 12:00:01"


def test_valid_nasa_http_clf_records():
    """FR-03, FR-05: Validate NASA Common Log Format with various HTTP status codes."""
    line_200 = '199.72.81.55 - - [01/Jul/1995:00:00:01 -0400] "GET /history/apollo/ HTTP/1.0" 200 6245'
    res_200 = parser.parse_line(line_200, declared_source="nasa_http")
    assert res_200 is not None
    assert res_200["source"] == "NASA-HTTP"
    assert res_200["log_level"] == "INFO"
    assert res_200["component_host"] == "199.72.81.55"

    line_404 = 'unicomp6.unicomp.net - - [01/Jul/1995:00:00:06 -0400] "GET /shuttle/countdown/count.gif HTTP/1.0" 404 231'
    res_404 = parser.parse_line(line_404, declared_source="nasa_http")
    assert res_404 is not None
    assert res_404["log_level"] == "WARN"

    line_500 = 'burger.letters.com - - [01/Jul/1995:00:00:15 -0400] "POST /cgi-bin/test HTTP/1.0" 500 0'
    res_500 = parser.parse_line(line_500, declared_source="nasa_http")
    assert res_500 is not None
    assert res_500["log_level"] == "ERROR"


# =====================================================================
# 2. QUARANTINE: MALFORMED, TRUNCATED, WRONG-SOURCE, BINARY (FR-04)
# =====================================================================

def test_malformed_and_truncated_records_quarantined():
    """FR-04, NFR-03: Incomplete, truncated, or unparseable lines must be quarantined."""
    truncated_hdfs = "081109 203518 INCOMPLETE LINE"
    res1 = parser.parse_line(truncated_hdfs, declared_source="hdfs")
    assert res1 is None

    truncated_nasa = '199.72.81.55 - - MISSING REQUEST AND STATUS'
    res2 = parser.parse_line(truncated_nasa, declared_source="nasa_http")
    assert res2 is None

    rejections = db.get_rejected_lines()
    assert len(rejections) >= 2
    assert all("Format violation" in r["reason"] for r in rejections[:2])


def test_wrong_source_mismatch_quarantined():
    """FR-04, NFR-03: Submitting an HDFS log line under nasa_http source must be rejected."""
    hdfs_line = "081109 203518 143 INFO dfs.DataNode: Block served"
    res = parser.parse_line(hdfs_line, declared_source="nasa_http")
    assert res is None

    rejections = db.get_rejected_lines()
    assert len(rejections) >= 1
    assert "NASA-HTTP" in rejections[0]["reason"]


def test_binary_and_null_byte_quarantined():
    """FR-04, NFR-03: Lines with null bytes or raw binary payloads must be quarantined."""
    null_byte_input = b"081109 203518 \x00\x00 MALICIOUS_BINARY_PAYLOAD"
    res = parser.parse_line(null_byte_input, declared_source="hdfs")
    assert res is None

    rejections = db.get_rejected_lines()
    assert len(rejections) >= 1
    assert "Binary" in rejections[0]["reason"] or "null-byte" in rejections[0]["reason"]


# =====================================================================
# 3. INDEPENDENT SLIDING-WINDOW ANOMALY BURST DETECTION (FR-06, NFR-04)
# =====================================================================

def test_independent_sliding_windows_no_cross_contamination():
    """
    FR-06, NFR-04: Sliding windows for HDFS and NASA-HTTP must be completely independent.
    HDFS anomaly bursts must never increment NASA count or trigger NASA alerts.
    """
    db.update_config("hdfs_window", "60", user_id=1)
    db.update_config("hdfs_threshold", "3", user_id=1)
    db.update_config("nasa_http_window", "60", user_id=1)
    db.update_config("nasa_http_threshold", "5", user_id=1)
    parser.refresh_config_cache()

    hdfs_error = "081109 203518 143 ERROR dfs.DataNode: Got exception while serving block"
    nasa_404 = '199.72.81.55 - - [01/Jul/1995:00:00:01 -0400] "GET /404 HTTP/1.0" 404 100'

    # Feed 2 HDFS errors (threshold is 3) -> No alert
    parser.parse_line(hdfs_error, declared_source="hdfs")
    parser.parse_line(hdfs_error, declared_source="hdfs")
    assert len(db.get_alerts()) == 0

    # Feed 2 NASA errors -> Neither window should trigger
    parser.parse_line(nasa_404, declared_source="nasa_http")
    parser.parse_line(nasa_404, declared_source="nasa_http")
    assert len(db.get_alerts()) == 0

    stats = parser.get_sliding_window_stats()
    assert stats["hdfs"]["current_count"] == 2
    assert stats["nasa_http"]["current_count"] == 2

    # 3rd HDFS error triggers HDFS alert
    parser.parse_line(hdfs_error, declared_source="hdfs")
    alerts = db.get_alerts()
    assert len(alerts) == 1
    assert alerts[0]["source"] == "HDFS"
    assert alerts[0]["event_count"] == 3

    # NASA count remains unaffected at 2
    stats_after = parser.get_sliding_window_stats()
    assert stats_after["nasa_http"]["current_count"] == 2


def test_window_expiration_evicts_old_events():
    """
    FR-06: Events older than window W must expire and not contribute to burst threshold T.
    """
    # 5-second window with threshold 3
    db.update_config("hdfs_window", "5", user_id=1)
    db.update_config("hdfs_threshold", "3", user_id=1)
    parser.refresh_config_cache()

    err_t0 = "2026-09-12 12:00:00 [ERROR] namenode: Got exception"
    err_t1 = "2026-09-12 12:00:02 [ERROR] namenode: Got exception"
    err_t_later = "2026-09-12 12:00:10 [ERROR] namenode: Got exception"  # 10s later > 5s window

    # Add 2 events within window
    parser.parse_line(err_t0, declared_source="hdfs")
    parser.parse_line(err_t1, declared_source="hdfs")
    assert len(db.get_alerts()) == 0

    # Add event 10 seconds later: t0 and t1 are evicted (> 5s window), leaving only 1 event
    parser.parse_line(err_t_later, declared_source="hdfs")
    assert len(db.get_alerts()) == 0

    stats = parser.get_sliding_window_stats()
    assert stats["hdfs"]["current_count"] == 1


def test_dynamic_config_reload_affects_detection():
    """
    FR-12: Updating thresholds in database dynamically changes anomaly firing behavior.
    """
    db.update_config("hdfs_threshold", "2", user_id=1)
    parser.refresh_config_cache()

    cache = parser.get_config_cache()
    assert cache["hdfs_threshold"] == 2

    hdfs_error = "081109 203518 143 ERROR dfs.DataNode: Got exception"
    parser.parse_line(hdfs_error, declared_source="hdfs")
    parser.parse_line(hdfs_error, declared_source="hdfs")

    # With threshold 2, 2 events fire an alert
    alerts = db.get_alerts()
    assert len(alerts) == 1
    assert alerts[0]["event_count"] == 2


# =====================================================================
# 4. INTEGRATION: E1 BOUNDED QUEUE TO E2 PARSE PIPELINE
# =====================================================================

def test_e1_to_e2_queue_consumption_pipeline():
    """
    Verify full ingestion pipeline: E1 enqueues -> consumer dequeues -> E2 parses & classifies.
    """
    sample_hdfs = "081109 203518 143 INFO dfs.DataNode: Pipeline test block blk_100"
    tailer.log_queue.put(("hdfs", sample_hdfs))

    # Consumer dequeues
    source, line = tailer.log_queue.get(timeout=1.0)
    event_model = parser.parse_to_model(line, declared_source=source)

    assert isinstance(event_model, LogEvent)
    assert event_model.source == "HDFS"
    assert event_model.log_level == "INFO"

    # Verify event was persisted into E3 VAULT events table
    events_resp = db.get_events(limit=5)
    assert len(events_resp["events"]) >= 1
    assert events_resp["events"][0]["raw_message"] == sample_hdfs
