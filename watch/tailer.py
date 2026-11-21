"""OS Engine — Multithreaded log file tailers feeding a bounded queue feeding E2 Parse."""

import io
import os
import queue
import threading
import time
import zipfile
from parse import parser

# Thread-safe bounded queue (maxsize=10000) feeding E2 Parse
log_queue = queue.Queue(maxsize=10000)

_events_processed = 0
_events_lock = threading.Lock()
_active_watchers = {}  # source_name -> (thread, stop_event)
_watchers_lock = threading.Lock()


def _increment_processed():
    global _events_processed
    with _events_lock:
        _events_processed += 1


def reset_metrics():
    global _events_processed
    with _events_lock:
        _events_processed = 0


def get_metrics():
    """Expose queue size, active watcher thread count, and events processed."""
    with _watchers_lock:
        active = len(_active_watchers)
    with _events_lock:
        processed = _events_processed
    return {
        "queue_size": log_queue.qsize(),
        "active_threads": active,
        "events_processed": processed,
    }


def worker_thread(source_name, file_path, stop_event):
    """
    Tail a live log file like `tail -f` and put (source_name, line) onto log_queue.
    Zero-dropped-lines guarantee: log_queue.put() blocks when maxsize=10000 is reached.
    """
    try:
        directory = os.path.dirname(file_path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
        if not os.path.exists(file_path):
            open(file_path, "a", encoding="utf-8").close()

        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            # Move to EOF to catch new continuous lines
            fh.seek(0, os.SEEK_END)
            while not stop_event.is_set():
                line = fh.readline()
                if line:
                    log_queue.put((source_name, line))  # Blocks if queue is full (backpressure)
                    _increment_processed()
                else:
                    time.sleep(0.1)
    except Exception as exc:
        print(f"[worker_thread] watcher '{source_name}' error: {exc}")


def start_watcher(source_name, file_path):
    """Spawn a daemon thread that continuously tails file_path."""
    with _watchers_lock:
        if source_name in _active_watchers:
            print(f"[start_watcher] Watcher for '{source_name}' is already running.")
            return _active_watchers[source_name][0]

        stop_event = threading.Event()
        t = threading.Thread(
            target=worker_thread,
            args=(source_name, file_path, stop_event),
            name=f"tailer-{source_name}",
            daemon=True,
        )
        _active_watchers[source_name] = (t, stop_event)
        t.start()
        return t


def stop_watcher(source_name):
    """Stop an active tailer thread."""
    with _watchers_lock:
        if source_name in _active_watchers:
            t, stop_event = _active_watchers[source_name]
            stop_event.set()
            del _active_watchers[source_name]
            return True
    return False


def ingest_file_stream(source_name, file_stream_or_bytes, filename=""):
    """
    Ingest a full file (Replay mode or File-upload mode).
    Detects .zip archives, extracts contained .log/.txt members, and enqueues lines.
    Quarantines unauthorized / unparseable lines via E2 Parser.
    """
    if isinstance(file_stream_or_bytes, bytes):
        raw_bytes = file_stream_or_bytes
    else:
        raw_bytes = file_stream_or_bytes.read()

    # Check if the uploaded file is a ZIP archive
    is_zip = False
    if filename.lower().endswith(".zip") or raw_bytes.startswith(b"PK\x03\x04"):
        is_zip = True

    lines_to_process = []
    if is_zip:
        try:
            with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
                # Find log or txt files inside zip
                log_members = [m for m in zf.namelist() if m.endswith((".log", ".txt"))]
                if not log_members:
                    log_members = zf.namelist()  # fallback to first member
                for member in log_members:
                    content = zf.read(member).decode("utf-8", errors="replace")
                    lines_to_process.extend(content.splitlines())
        except Exception as exc:
            # Malformed zip file -> send to E2 parser to be rejected
            parser.parse_line(raw_bytes, source_name)
            return {"status": "error", "message": f"Invalid zip file: {exc}"}
    else:
        try:
            content = raw_bytes.decode("utf-8", errors="replace")
            lines_to_process = content.splitlines()
        except Exception:
            # Binary non-text file -> pass directly to E2 parser for rejection
            parser.parse_line(raw_bytes, source_name)
            return {"status": "rejected", "lines": 1}

    processed_count = 0
    for line in lines_to_process:
        log_queue.put((source_name, line))
        _increment_processed()
        processed_count += 1

    return {"status": "success", "lines_queued": processed_count}
