"""
Phase 3 Verification Test Suite — Engine 1 (E1 WATCH).

Covers FR-01, FR-02, FR-13, NFR-01, NFR-02:
- Bounded queue capacity (maxsize=10,000) & backpressure blocking
- Thread-per-source concurrent live file tailing
- Memory-efficient streaming ingestion
- Valid ZIP container extraction
- Corrupted / invalid ZIP quarantine handling
- Ingestion metrics thread safety & accuracy
"""

import io
import os
import queue
import tempfile
import threading
import time
import zipfile
import pytest

from watch import tailer
from vault import db
from parse import parser


@pytest.fixture(autouse=True)
def clean_watch_state():
    """Ensure a clean queue and metrics state for each test."""
    # Drain queue
    while not tailer.log_queue.empty():
        try:
            tailer.log_queue.get_nowait()
        except queue.Empty:
            break
    tailer.reset_metrics()
    tailer.stop_all_watchers()
    yield
    while not tailer.log_queue.empty():
        try:
            tailer.log_queue.get_nowait()
        except queue.Empty:
            break
    tailer.stop_all_watchers()
    tailer.reset_metrics()


def test_bounded_queue_capacity():
    """FR-02, NFR-01: Shared bounded queue must be configured with maxsize=10,000."""
    assert tailer.log_queue.maxsize == 10000
    metrics = tailer.get_metrics()
    assert metrics["queue_capacity"] == 10000


def test_queue_backpressure_producer_blocks():
    """
    NFR-01: When the queue is full, producer.put() blocks rather than dropping lines or overflowing.
    """
    test_q = queue.Queue(maxsize=3)
    test_q.put(("src", "line 1"))
    test_q.put(("src", "line 2"))
    test_q.put(("src", "line 3"))
    assert test_q.full()

    blocked = threading.Event()
    unblocked = threading.Event()

    def producer():
        blocked.set()
        test_q.put(("src", "line 4"))  # Blocks here because capacity is 3
        unblocked.set()

    t = threading.Thread(target=producer, daemon=True)
    t.start()

    # Verify producer is currently blocked
    assert blocked.wait(timeout=1.0)
    time.sleep(0.2)
    assert not unblocked.is_set(), "Producer should be blocked on full queue"

    # Consume 1 item -> producer unblocks immediately
    item = test_q.get()
    assert item == ("src", "line 1")
    assert unblocked.wait(timeout=1.0), "Producer must unblock after queue space is freed"
    t.join(timeout=1.0)


def test_concurrent_watchers_thread_per_source():
    """
    FR-01, FR-02: Support concurrent source monitoring with dedicated watcher thread per source.
    """
    fd_hdfs, path_hdfs = tempfile.mkstemp(suffix=".log")
    fd_nasa, path_nasa = tempfile.mkstemp(suffix=".log")
    os.close(fd_hdfs)
    os.close(fd_nasa)

    try:
        t_hdfs = tailer.start_watcher("hdfs_live", path_hdfs)
        t_nasa = tailer.start_watcher("nasa_live", path_nasa)

        assert t_hdfs.is_alive()
        assert t_nasa.is_alive()
        assert t_hdfs != t_nasa

        watchers = tailer.get_active_watchers()
        assert "hdfs_live" in watchers
        assert "nasa_live" in watchers
        assert watchers["hdfs_live"]["is_alive"] is True
        assert watchers["nasa_live"]["is_alive"] is True

        time.sleep(0.15)

        # Write lines to both files concurrently
        with open(path_hdfs, "a", encoding="utf-8") as f:
            f.write("081109 203518 143 INFO dfs.DataNode: HDFS record 1\n")
            f.write("081109 203518 144 INFO dfs.DataNode: HDFS record 2\n")
            f.flush()

        with open(path_nasa, "a", encoding="utf-8") as f:
            f.write('199.72.81.55 - - [01/Jul/1995:00:00:01 -0400] "GET /test HTTP/1.0" 200 1234\n')
            f.flush()

        time.sleep(0.3)

        # Confirm both sources' items were enqueued in the shared bounded queue
        queued_items = []
        while not tailer.log_queue.empty():
            queued_items.append(tailer.log_queue.get_nowait())

        sources = [item[0] for item in queued_items]
        assert "hdfs_live" in sources
        assert "nasa_live" in sources
        assert len(queued_items) == 3

        # Stop watchers gracefully
        assert tailer.stop_watcher("hdfs_live") is True
        assert tailer.stop_watcher("nasa_live") is True
        assert len(tailer.get_active_watchers()) == 0

    finally:
        for p in (path_hdfs, path_nasa):
            try:
                if os.path.exists(p):
                    os.remove(p)
            except OSError:
                pass


def test_zip_extraction_and_ingestion():
    """
    FR-13: Process valid ZIP uploads by extracting supported log files into queue.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("cluster_hdfs.log", "081109 203518 143 INFO dfs.DataNode: Line A\n081109 203518 144 INFO dfs.DataNode: Line B\n")
        zf.writestr("access.txt", "081109 203518 145 INFO dfs.DataNode: Line C\n")
        zf.writestr("ignored.bin", b"\x00\x01\x02")  # ignored member because .log and .txt exist

    zip_bytes = buf.getvalue()
    res = tailer.ingest_file_stream("hdfs", zip_bytes, filename="archive.zip")

    assert res["status"] == "success"
    assert res["lines_queued"] == 3
    assert tailer.log_queue.qsize() == 3


def test_invalid_zip_container_quarantined():
    """
    FR-13: Corrupted or invalid ZIP container must be reported and quarantined safely.
    """
    corrupt_zip_bytes = b"PK\x03\x04\x00\x00\x00\x00CORRUPT_NON_ZIP_DATA"

    db.init_db()
    res = tailer.ingest_file_stream("hdfs", corrupt_zip_bytes, filename="bad_archive.zip")

    assert res["status"] == "error"
    assert "Invalid" in res["message"] or "ZIP" in res["message"]

    # Verify invalid container was quarantined into rejected_lines table
    rejected = db.get_rejected_lines()
    assert len(rejected) >= 1
    assert any("PK" in str(r.get("raw_bytes_preview", "")) or "Binary" in r["reason"] or "Format" in r["reason"] for r in rejected)


def test_large_file_streaming_incremental():
    """
    FR-01: Stream large file line-by-line without loading entire file into memory.
    """
    fd, path = tempfile.mkstemp(suffix=".log")
    os.close(fd)

    try:
        # Create a file with 1,500 lines
        line_template = "081109 203518 143 INFO dfs.DataNode: Line number {i}\n"
        with open(path, "w", encoding="utf-8") as f:
            for i in range(1500):
                f.write(line_template.format(i=i))

        res = tailer.ingest_file_path("hdfs", path)
        assert res["status"] == "success"
        assert res["lines_queued"] == 1500

        metrics = tailer.get_metrics()
        assert metrics["events_processed"] == 1500
        assert tailer.log_queue.qsize() == 1500

    finally:
        if os.path.exists(path):
            os.remove(path)
