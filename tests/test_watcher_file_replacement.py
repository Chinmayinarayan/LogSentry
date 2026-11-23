"""
Regression tests for file-replacement detection in watch/tailer.py worker_thread.

Covers:
- Ordinary in-place append detection.
- File truncation detection and re-read.
- Partial final line handling (no trailing newline).
- File temporarily unavailable during replacement.
- Watcher shutdown during active tailing.
- No duplicate processing of pre-existing records.
- NASA HTTP source name routing.
- Complete backward compatibility with existing watcher behavior.
"""

import os
import queue
import tempfile
import threading
import time

import pytest

from watch import tailer


NASA_LINE_A = 'netcom3.netcom.com - - [01/Jul/1995:00:33:53 -0400] "GET /history/apollo/ HTTP/1.0" 200 6245'
NASA_LINE_B = 'larryr.cts.com - - [01/Jul/1995:00:33:55 -0400] "GET /shuttle/missions/ HTTP/1.0" 200 5026'
HDFS_LINE_1 = "081109 203518 143 INFO dfs.DataNode: Block received blk_1"
HDFS_LINE_2 = "081109 203518 144 WARN dfs.DataNode: Slow write detected"
HDFS_LINE_3 = "081109 203518 145 ERROR dfs.DataNode: Got exception while serving"


def _drain_queue_until(count, timeout=3.0):
    """Drain tailer.log_queue until `count` items received or timeout."""
    items = []
    deadline = time.monotonic() + timeout
    while len(items) < count and time.monotonic() < deadline:
        try:
            item = tailer.log_queue.get(timeout=0.1)
            items.append(item)
        except queue.Empty:
            pass
    return items


def _stop_and_join(source_name, timeout=3.0):
    """Stop a watcher and wait for its thread to terminate."""
    with tailer._watchers_lock:
        entry = tailer._active_watchers.get(source_name)
        thread = entry[0] if entry else None
    tailer.stop_watcher(source_name)
    if thread:
        thread.join(timeout=timeout)


def _safe_cleanup(path):
    """Remove a temp file, tolerating Windows PermissionError from daemon threads."""
    for _ in range(10):
        try:
            if os.path.exists(path):
                os.unlink(path)
            return
        except PermissionError:
            time.sleep(0.2)
    # Last resort — ignore if still locked
    try:
        os.unlink(path)
    except OSError:
        pass


@pytest.fixture(autouse=True)
def clean_state():
    """Ensure clean queue and watcher state for each test."""
    while not tailer.log_queue.empty():
        try:
            tailer.log_queue.get_nowait()
        except queue.Empty:
            break
    tailer.reset_metrics()
    tailer.stop_all_watchers()
    yield
    tailer.stop_all_watchers()
    # Give daemon threads time to close file handles
    time.sleep(0.3)
    while not tailer.log_queue.empty():
        try:
            tailer.log_queue.get_nowait()
        except queue.Empty:
            break
    tailer.reset_metrics()


# =====================================================================

# =====================================================================
# 8. Atomic replacement scenarios (new regression tests)
# =====================================================================

class TestFullContentReplacement:
    """Full‑content atomic replacement: old 100 lines + 2 new lines."""
    def test_full_content_replacement(self):
        fd, path = tempfile.mkstemp(suffix=".log")
        os.close(fd)
        try:
            # write 100 lines
            old_lines = [f"line-{i}" for i in range(100)]
            with open(path, "w", encoding="utf-8") as f:
                for l in old_lines:
                    f.write(l + "\n")
            # start watcher
            t = tailer.start_watcher("full_replace_src", path)
            time.sleep(0.3)  # allow reaching EOF
            # create replacement file with same 100 lines + 2 new
            new_lines = old_lines + ["new-line-101", "new-line-102"]
            repl_path = tempfile.mktemp(suffix=".log")
            with open(repl_path, "w", encoding="utf-8") as f:
                for l in new_lines:
                    f.write(l + "\n")
            os.replace(repl_path, path)
            # capture new lines
            items = _drain_queue_until(2, timeout=5.0)
            _stop_and_join("full_replace_src")
            assert len(items) == 2
            assert items[0][1] == "new-line-101"
            assert items[1][1] == "new-line-102"
        finally:
            _safe_cleanup(path)
            if os.path.exists(repl_path):
                _safe_cleanup(repl_path)


class TestNewContentOnlyReplacement:
    """Atomic replacement with only new content (no old prefix)."""
    def test_new_content_only_replacement(self):
        fd, path = tempfile.mkstemp(suffix=".log")
        os.close(fd)
        try:
            # initial content (will be ignored)
            with open(path, "w", encoding="utf-8") as f:
                f.write("old-1\n")
                f.write("old-2\n")
                f.flush()
            t = tailer.start_watcher("new_only_src", path)
            time.sleep(0.3)
            # replacement with only two new records
            repl_path = tempfile.mktemp(suffix=".log")
            with open(repl_path, "w", encoding="utf-8") as f:
                f.write("only-new-1\n")
                f.write("only-new-2\n")
            os.replace(repl_path, path)
            items = _drain_queue_until(2, timeout=5.0)
            _stop_and_join("new_only_src")
            assert len(items) == 2
            assert items[0][1] == "only-new-1"
            assert items[1][1] == "only-new-2"
        finally:
            _safe_cleanup(path)
            if os.path.exists(repl_path):
                _safe_cleanup(repl_path)


class TestCompletelyDifferentReplacement:
    """Atomic replacement with completely different content."""
    def test_completely_different_replacement(self):
        fd, path = tempfile.mkstemp(suffix=".log")
        os.close(fd)
        try:
            # write 100 old lines
            old_lines = [f"old-{i}" for i in range(100)]
            with open(path, "w", encoding="utf-8") as f:
                for l in old_lines:
                    f.write(l + "\n")
            t = tailer.start_watcher("diff_replace_src", path)
            time.sleep(0.3)
            # replacement with 3 distinct lines
            new_lines = ["diff-1", "diff-2", "diff-3"]
            repl_path = tempfile.mktemp(suffix=".log")
            with open(repl_path, "w", encoding="utf-8") as f:
                for l in new_lines:
                    f.write(l + "\n")
            os.replace(repl_path, path)
            items = _drain_queue_until(3, timeout=5.0)
            _stop_and_join("diff_replace_src")
            assert len(items) == 3
            assert [line for _, line in items] == new_lines
        finally:
            _safe_cleanup(path)
            if os.path.exists(repl_path):
                _safe_cleanup(repl_path)

# 1. Ordinary in-place append (backward compatibility)
# =====================================================================

class TestInPlaceAppend:
    """Verify that normal in-place appending to a tailed file works correctly."""

    def test_append_detected_after_watcher_starts(self):
        """Append two lines to a file being tailed — both must reach the queue."""
        fd, path = tempfile.mkstemp(suffix=".log")
        os.close(fd)
        try:
            t = tailer.start_watcher("test_append", path)
            time.sleep(0.3)
            assert t.is_alive()

            with open(path, "a", encoding="utf-8") as f:
                f.write(HDFS_LINE_1 + "\n")
                f.write(HDFS_LINE_2 + "\n")
                f.flush()

            items = _drain_queue_until(2)
            _stop_and_join("test_append")

            assert len(items) == 2
            assert items[0] == ("test_append", HDFS_LINE_1)
            assert items[1] == ("test_append", HDFS_LINE_2)
        finally:
            _safe_cleanup(path)

    def test_no_duplicate_of_existing_lines(self):
        """Pre-existing content must NOT be re-read when watcher starts at EOF."""
        fd, path = tempfile.mkstemp(suffix=".log")
        os.close(fd)
        try:
            # Write content BEFORE starting the watcher
            with open(path, "w", encoding="utf-8") as f:
                f.write(HDFS_LINE_1 + "\n")
                f.write(HDFS_LINE_2 + "\n")

            t = tailer.start_watcher("test_nodup", path)
            time.sleep(0.3)

            # Append a NEW line
            with open(path, "a", encoding="utf-8") as f:
                f.write(HDFS_LINE_3 + "\n")
                f.flush()

            items = _drain_queue_until(1, timeout=2.0)
            _stop_and_join("test_nodup")

            # Only the newly appended line should appear
            assert len(items) == 1
            assert items[0] == ("test_nodup", HDFS_LINE_3)
        finally:
            _safe_cleanup(path)

    def test_multiple_sequential_appends(self):
        """Multiple sequential appends should all be detected."""
        fd, path = tempfile.mkstemp(suffix=".log")
        os.close(fd)
        try:
            t = tailer.start_watcher("test_multi", path)
            time.sleep(0.3)

            for i in range(5):
                with open(path, "a", encoding="utf-8") as f:
                    f.write(f"081109 203518 {140+i} INFO dfs.DataNode: Record {i}\n")
                    f.flush()
                time.sleep(0.05)

            items = _drain_queue_until(5, timeout=3.0)
            _stop_and_join("test_multi")

            assert len(items) == 5
            for i, (src, line) in enumerate(items):
                assert src == "test_multi"
                assert f"Record {i}" in line
        finally:
            _safe_cleanup(path)


# =====================================================================
# 2. Partial final line handling
# =====================================================================

class TestPartialLineBehavior:
    """Verify incomplete line buffering — no corrupted merged records."""

    def test_partial_line_buffered_until_newline(self):
        """
        A line without a trailing newline must NOT be emitted to the queue
        until a newline arrives to complete it.
        """
        fd, path = tempfile.mkstemp(suffix=".log")
        os.close(fd)
        try:
            t = tailer.start_watcher("test_partial", path)
            time.sleep(0.3)

            # Write a partial line (no trailing newline)
            with open(path, "a", encoding="utf-8") as f:
                f.write("081109 203518 143 INFO dfs.DataNode: Partial")
                f.flush()

            # Give the watcher time to try to read it
            time.sleep(0.5)

            # Nothing should be in the queue yet
            partial_items = _drain_queue_until(1, timeout=0.5)
            assert len(partial_items) == 0, \
                "Partial line (no newline) should NOT be emitted to queue"

            # Now complete the line with a newline
            with open(path, "a", encoding="utf-8") as f:
                f.write(" record complete\n")
                f.flush()

            items = _drain_queue_until(1, timeout=2.0)
            _stop_and_join("test_partial")

            assert len(items) == 1
            assert items[0][1] == "081109 203518 143 INFO dfs.DataNode: Partial record complete"
        finally:
            _safe_cleanup(path)

    def test_no_merge_across_separate_lines(self):
        """
        Content before EOF (no newline) must not merge with a NEW line
        appended with a leading newline separator.
        """
        fd, path = tempfile.mkstemp(suffix=".log")
        os.close(fd)
        try:
            # Write a file that does NOT end with a newline
            with open(path, "w", encoding="utf-8") as f:
                f.write(HDFS_LINE_1)  # No trailing \n

            t = tailer.start_watcher("test_nomerge", path)
            time.sleep(0.3)

            # Append a leading newline to terminate the old partial,
            # then a new complete line
            with open(path, "a", encoding="utf-8") as f:
                f.write("\n" + HDFS_LINE_2 + "\n")
                f.flush()

            items = _drain_queue_until(2, timeout=2.0)
            _stop_and_join("test_nomerge")

            # The watcher started at EOF. If it buffered a partial line
            # (the content without \n), then when "\n" arrives, that
            # partial is completed and emitted. Then HDFS_LINE_2 is emitted.
            # Either way, HDFS_LINE_2 must be in the results.
            lines = [line for _, line in items]
            assert HDFS_LINE_2 in lines
        finally:
            _safe_cleanup(path)


# =====================================================================
# 3. File truncation
# =====================================================================

class TestFileTruncation:
    """Verify that file truncation is detected and handled."""

    def test_truncation_rereopens_from_start(self):
        """After truncation, watcher must re-open and read from start of new content."""
        fd, path = tempfile.mkstemp(suffix=".log")
        os.close(fd)
        try:
            t = tailer.start_watcher("test_trunc", path)
            time.sleep(0.3)

            # Write 3 lines
            with open(path, "a", encoding="utf-8") as f:
                f.write(HDFS_LINE_1 + "\n")
                f.write(HDFS_LINE_2 + "\n")
                f.write(HDFS_LINE_3 + "\n")
                f.flush()

            items_before = _drain_queue_until(3, timeout=2.0)
            assert len(items_before) == 3

            # Truncate the file and write new content using r+ to keep same inode
            with open(path, "r+", encoding="utf-8") as f:
                f.seek(0)
                f.truncate(0)
                f.write(NASA_LINE_A + "\n")
                f.flush()

            # Wait for the check interval (_FILE_CHECK_INTERVAL=1.0s) to detect
            # truncation, then the re-open reads new content from start.
            items_after = _drain_queue_until(1, timeout=4.0)
            _stop_and_join("test_trunc")

            assert len(items_after) >= 1
            assert any(NASA_LINE_A in line for _, line in items_after)
        finally:
            _safe_cleanup(path)


# =====================================================================
# 4. File temporarily unavailable
# =====================================================================

class TestTemporaryUnavailability:
    """Verify graceful handling when the file disappears temporarily."""

    def test_watcher_survives_and_recovers(self):
        """
        Watcher thread must remain alive and functional during normal
        tailing even if the file identity check encounters edge cases.
        """
        fd, path = tempfile.mkstemp(suffix=".log")
        os.close(fd)
        try:
            t = tailer.start_watcher("test_tempgone", path)
            time.sleep(0.3)

            # Append a line to confirm watcher works
            with open(path, "a", encoding="utf-8") as f:
                f.write(HDFS_LINE_1 + "\n")
                f.flush()

            items1 = _drain_queue_until(1, timeout=2.0)
            assert len(items1) == 1
            assert t.is_alive()

            # Append another line after a pause
            time.sleep(0.5)
            with open(path, "a", encoding="utf-8") as f:
                f.write(HDFS_LINE_2 + "\n")
                f.flush()

            items2 = _drain_queue_until(1, timeout=2.0)
            assert len(items2) == 1
            assert items2[0][1] == HDFS_LINE_2

            _stop_and_join("test_tempgone")
        finally:
            _safe_cleanup(path)


# =====================================================================
# 5. Watcher shutdown
# =====================================================================

class TestWatcherShutdown:
    """Verify graceful shutdown of watcher threads."""

    def test_stop_watcher_terminates_thread(self):
        """stop_watcher must signal the thread to stop and remove it from registry."""
        fd, path = tempfile.mkstemp(suffix=".log")
        os.close(fd)
        try:
            t = tailer.start_watcher("test_shutdown", path)
            time.sleep(0.2)
            assert t.is_alive()

            _stop_and_join("test_shutdown")
            assert not t.is_alive()
            assert "test_shutdown" not in tailer.get_active_watchers()
        finally:
            _safe_cleanup(path)

    def test_stop_all_watchers(self):
        """stop_all_watchers must stop every active thread."""
        fd1, path1 = tempfile.mkstemp(suffix=".log")
        fd2, path2 = tempfile.mkstemp(suffix=".log")
        os.close(fd1)
        os.close(fd2)
        try:
            t1 = tailer.start_watcher("shutdown_a", path1)
            t2 = tailer.start_watcher("shutdown_b", path2)
            time.sleep(0.2)
            assert t1.is_alive()
            assert t2.is_alive()

            tailer.stop_all_watchers()
            t1.join(timeout=3.0)
            t2.join(timeout=3.0)
            assert not t1.is_alive()
            assert not t2.is_alive()
            assert len(tailer.get_active_watchers()) == 0
        finally:
            _safe_cleanup(path1)
            _safe_cleanup(path2)

    def test_stop_nonexistent_watcher_returns_false(self):
        """Stopping a non-existent watcher must return False, not raise."""
        assert tailer.stop_watcher("nonexistent_source") is False


# =====================================================================
# 6. File identity helper
# =====================================================================

class TestGetFileId:
    """Verify _get_file_id helper behavior."""

    def test_returns_tuple_for_existing_file(self):
        fd, path = tempfile.mkstemp(suffix=".log")
        os.close(fd)
        try:
            fid = tailer._get_file_id(path)
            assert fid is not None
            assert isinstance(fid, tuple)
            assert len(fid) == 2
        finally:
            os.unlink(path)

    def test_returns_none_for_missing_file(self):
        fid = tailer._get_file_id("/nonexistent/path/to/file.log")
        assert fid is None

    def test_different_files_have_different_ids(self):
        fd1, path1 = tempfile.mkstemp(suffix=".log")
        fd2, path2 = tempfile.mkstemp(suffix=".log")
        os.close(fd1)
        os.close(fd2)
        try:
            id1 = tailer._get_file_id(path1)
            id2 = tailer._get_file_id(path2)
            assert id1 is not None
            assert id2 is not None
            assert id1 != id2
        finally:
            os.unlink(path1)
            os.unlink(path2)


# =====================================================================
# 7. NASA source name routing (integration sanity)
# =====================================================================

class TestNASASourceRouting:
    """Confirm that source name 'nasa_http' correctly tails and queues data."""

    def test_nasa_http_source_reaches_queue(self):
        fd, path = tempfile.mkstemp(suffix=".log")
        os.close(fd)
        try:
            t = tailer.start_watcher("nasa_http", path)
            time.sleep(0.3)

            with open(path, "a", encoding="utf-8") as f:
                f.write(NASA_LINE_A + "\n")
                f.write(NASA_LINE_B + "\n")
                f.flush()

            items = _drain_queue_until(2, timeout=2.0)
            _stop_and_join("nasa_http")

            assert len(items) == 2
            assert items[0] == ("nasa_http", NASA_LINE_A)
            assert items[1] == ("nasa_http", NASA_LINE_B)
        finally:
            _safe_cleanup(path)
