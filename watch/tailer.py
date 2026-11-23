"""
Engine 1: E1 WATCH — Concurrent Log Ingestion and Monitoring Engine.

Responsibilities (FR-01, FR-02, FR-13, NFR-01, NFR-02):
- Bounded shared queue (maxsize=10,000) with blocking backpressure.
- Thread-per-source concurrent live file tailing (`tail -f` equivalent).
- Memory-efficient streaming ingestion for large log files (e.g. 205 MB NASA HTTP log).
- ZIP archive container validation, safe member extraction, and invalid container quarantine.
- Thread-safe ingestion statistics and active watcher registry.
"""

import io
import os
import queue
import threading
import time
import zipfile
from typing import Dict, Any, Union, Optional

from parse import parser

# FR-02, NFR-01: Shared bounded queue (maxsize=10,000 records)
QUEUE_MAXSIZE = 10000
log_queue: queue.Queue = queue.Queue(maxsize=QUEUE_MAXSIZE)

# Memory Bound Constraint: Max individual record size (64 KB).
# With QUEUE_MAXSIZE=10,000, worst-case memory ceiling for the queue buffer is <= 640 MB.
MAX_RECORD_SIZE = 65536


def is_safe_zip_path(path: str) -> bool:
    r"""
    Verify whether a ZIP member path is a safe relative path.
    Rejects:
    - Directory traversal ('..' components, e.g. '../../etc/passwd', r'..\..\file')
    - Absolute Unix paths (starts with '/')
    - Windows drive letters (e.g. 'C:', 'D:\...')
    - UNC network share paths (e.g. r'\\server\share\file' or '//server/share/file')
    - Null bytes or control characters in path
    Permits:
    - Safe relative filenames (e.g. 'hdfs.log')
    - Safe nested relative paths (e.g. 'logs/hdfs.log', 'nested/dir/app.log')
    """
    if not path or not isinstance(path, str):
        return False
    if "\x00" in path:
        return False
    # Check for UNC network share prefix
    if path.startswith("\\\\") or path.startswith("//"):
        return False
    # Check Windows drive letter (e.g. C:, D:)
    if len(path) >= 2 and path[1] == ":" and path[0].isalpha():
        return False
    # Normalize slashes
    norm = path.replace("\\", "/")
    if norm.startswith("/"):
        return False
    if ":" in norm:
        return False
    # Check path components
    parts = [p for p in norm.split("/") if p]
    if ".." in parts:
        return False
    return True


def _safe_readline(stream: Any, max_size: int = MAX_RECORD_SIZE):
    """
    Safely reads a single line up to max_size characters/bytes.

    If the line exceeds max_size without a terminating newline, discards the remainder
    in 8KB chunks until a newline ('\\n' or '\\r') or EOF is encountered.
    This prevents memory exhaustion from giant lines and ensures the remainder is not
    accidentally parsed as a subsequent log line.

    Returns:
        (line_str_or_bytes, is_oversized)
        - If EOF: ("", False) or (b"", False)
        - If valid line: (line_content, False)
        - If oversized line: (preview, True)
    """
    line = stream.readline(max_size + 1)
    if not line:
        return ("", False)

    is_binary = isinstance(line, bytes)
    newline_chars = (b"\n", b"\r") if is_binary else ("\n", "\r")

    if len(line) > max_size:
        # Line exceeds max_size. Discard remaining chunks until next newline or EOF.
        while True:
            chunk = stream.readline(8192)
            if not chunk:
                break
            if any(nc in chunk for nc in newline_chars):
                break
        return (line[:512], True)

    return (line, False)

# Thread synchronization primitives (NFR-02)
_events_processed = 0
_events_lock = threading.Lock()
_active_watchers: Dict[str, Any] = {}  # source_name -> (Thread, threading.Event, file_path)
_watchers_lock = threading.Lock()


def _increment_processed(count: int = 1):
    """Thread-safe increment of ingested lines counter."""
    global _events_processed
    with _events_lock:
        _events_processed += count


def reset_metrics():
    """Reset ingestion metrics for test isolation."""
    global _events_processed
    with _events_lock:
        _events_processed = 0


def get_metrics() -> Dict[str, Any]:
    """
    Expose queue size, active watcher thread count, events queued/processed, and queue capacity.
    Called by E4 SIGNAL /api/stats endpoint.
    """
    with _watchers_lock:
        active = len(_active_watchers)
    with _events_lock:
        processed = _events_processed
    return {
        "queue_size": log_queue.qsize(),
        "queue_capacity": QUEUE_MAXSIZE,
        "active_threads": active,
        "events_queued": processed,
        "events_processed": processed,  # Backward compatibility alias
    }


def get_active_watchers() -> Dict[str, Dict[str, Any]]:
    """Return status metadata for all active watcher threads."""
    with _watchers_lock:
        result = {}
        for name, (thread, stop_event, path) in _active_watchers.items():
            result[name] = {
                "source": name,
                "file_path": path,
                "is_alive": thread.is_alive(),
                "stopped": stop_event.is_set(),
            }
        return result




def _get_file_id(path: str):
    """Return a tuple (device, inode) identifying the file, or None if unavailable."""
    try:
        st = os.stat(path)
        return (st.st_dev, st.st_ino)
    except OSError:
        return None


def worker_thread(source_name: str, file_path: str, stop_event: threading.Event):
    """Tail a file without holding a persistent Windows handle.

    The watcher tracks the file identity via `_get_file_id` and a byte offset.
    It opens the file *only* for the short period needed to read any newly
    appended data, then closes it. This avoids the `GENERIC_READ | DELETE`
    lock that previously prevented other processes from appending to the log.
    """
    # Ensure directory and file exist.
    directory = os.path.dirname(file_path)
    if directory and not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)
    if not os.path.exists(file_path):
        open(file_path, "a", encoding="utf-8").close()

    # Initial state – start at the end of the existing file.
    prev_id = _get_file_id(file_path)
    offset = os.path.getsize(file_path) if os.path.exists(file_path) else 0
    partial = ""

    # Initialise SHA‑256 digest for processed prefix.
    _digest = hashlib.sha256()
    _digest_valid = True
    if offset > 0:
        try:
            with open(file_path, "rb") as bf:
                data = bf.read(offset)
                if len(data) < offset:
                    _digest_valid = False
                else:
                    _digest.update(data)
        except OSError:
            _digest_valid = False

    def _open_file():
        """Open the file with Windows sharing flags (short‑lived)."""
        if os.name == "nt":
            import msvcrt
            import ctypes
            from ctypes import wintypes

            GENERIC_READ = 0x80000000
            DELETE = 0x00010000
            FILE_SHARE_READ = 0x00000001
            FILE_SHARE_WRITE = 0x00000002
            FILE_SHARE_DELETE = 0x00000004
            OPEN_EXISTING = 3

            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            CreateFileW = kernel32.CreateFileW
            CreateFileW.argtypes = [
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.LPVOID,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.HANDLE,
            ]
            CreateFileW.restype = wintypes.HANDLE

            handle = CreateFileW(
                file_path,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                0,
                None,
            )
            if handle == wintypes.HANDLE(-1).value:
                raise OSError(ctypes.get_last_error(), f"CreateFileW failed for {file_path}")
            try:
                fd = msvcrt.open_osfhandle(handle, os.O_RDONLY)
            except Exception:
                ctypes.windll.kernel32.CloseHandle(handle)
                raise
            return os.fdopen(fd, "r", encoding="utf-8", errors="replace")
        else:
            return open(file_path, "r", encoding="utf-8", errors="replace")

    while not stop_event.is_set():
        # Detect temporary unavailability.
        cur_id = _get_file_id(file_path)
        if cur_id is None:
            time.sleep(0.1)
            continue

        # ----- Same‑inode truncation detection (every cycle) -----
        try:
            cur_size = os.path.getsize(file_path)
        except OSError:
            cur_size = offset
        if cur_size < offset:
            offset = 0
            partial = ""
            _digest = hashlib.sha256()
            _digest_valid = True
            time.sleep(0.1)
            continue

        # ----- Replacement detection (inode change) -----
        if cur_id != prev_id:
            prev_id = cur_id
            try:
                new_size = os.path.getsize(file_path)
            except OSError:
                new_size = 0

            prefix_matches = False
            if _digest_valid and new_size >= offset:
                try:
                    with open(file_path, "rb") as bf:
                        new_prefix = bf.read(offset)
                        if len(new_prefix) == offset and hashlib.sha256(new_prefix).digest() == _digest.digest():
                            prefix_matches = True
                except OSError:
                    pass

            if not prefix_matches:
                offset = 0
                partial = ""
                _digest = hashlib.sha256()
                _digest_valid = True
            else:
                partial = ""

        # Remember start offset for incremental digest update.
        cycle_start_offset = offset

        # Open, seek, and read any new data.
        try:
            with _open_file() as fh:
                fh.seek(offset)
                while not stop_event.is_set():
                    line, is_oversized = _safe_readline(fh, MAX_RECORD_SIZE)
                    if not line:
                        break
                    if is_oversized:
                        parser.parse_line(b"OVERSIZED_RECORD: Line exceeds 64KB limit", declared_source=source_name)
                        partial = ""
                        offset = fh.tell()
                        continue
                    if line.endswith("\n") or line.endswith("\r"):
                        full_line = partial + line
                        partial = ""
                        clean_line = full_line.rstrip("\r\n")
                        while not stop_event.is_set():
                            try:
                                log_queue.put((source_name, clean_line), timeout=0.2)
                                _increment_processed(1)
                                break
                            except queue.Full:
                                continue
                    else:
                        partial += line
                    offset = fh.tell()
            # Incremental digest update for bytes read this cycle.
            if _digest_valid:
                try:
                    with open(file_path, "rb") as bf:
                        bf.seek(cycle_start_offset)
                        new_bytes = bf.read(offset - cycle_start_offset)
                        if len(new_bytes) != (offset - cycle_start_offset):
                            _digest_valid = False
                        else:
                            _digest.update(new_bytes)
                except OSError:
                    _digest_valid = False
        except Exception as exc:
            print(f"[worker_thread] Watcher '{source_name}' error on file '{file_path}': {exc}")
            time.sleep(0.1)
            continue

        # No new data – pause briefly.
        time.sleep(0.1)



def start_watcher(source_name: str, file_path: str) -> threading.Thread:
    """
    Spawn a dedicated daemon thread that continuously tails file_path for source_name.
    Re-uses existing thread if source_name is already active on the same file.
    """
    with _watchers_lock:
        if source_name in _active_watchers:
            t, stop_event, existing_path = _active_watchers[source_name]
            if t.is_alive():
                print(f"[start_watcher] Watcher for '{source_name}' already active.")
                return t

        stop_event = threading.Event()
        t = threading.Thread(
            target=worker_thread,
            args=(source_name, file_path, stop_event),
            name=f"tailer-{source_name}",
            daemon=True,
        )
        _active_watchers[source_name] = (t, stop_event, file_path)
        t.start()
        return t


def stop_watcher(source_name: str) -> bool:
    """Stop an active tailer thread gracefully by setting its stop event."""
    with _watchers_lock:
        if source_name in _active_watchers:
            t, stop_event, _ = _active_watchers[source_name]
            stop_event.set()
            del _active_watchers[source_name]
            return True
    return False


def stop_all_watchers():
    """Stop all running watcher threads."""
    with _watchers_lock:
        for name, (thread, stop_event, _) in list(_active_watchers.items()):
            stop_event.set()
        _active_watchers.clear()


def ingest_file_stream(source_name: str, file_stream_or_bytes: Union[bytes, io.BytesIO, Any], filename: str = "") -> Dict[str, Any]:
    """
    Ingest a log file stream or raw bytes into the bounded queue.
    FR-01, FR-13:
    - Auto-detects and extracts ZIP containers.
    - Streams lines into log_queue with backpressure.
    - Quarantines invalid ZIP files or binary records via E2 PARSE.
    - Retains full backward compatibility with existing tests and API callers.
    """
    # 1. Determine if input is ZIP archive by extension or PK magic number
    is_zip = False
    raw_head = b""

    if isinstance(file_stream_or_bytes, bytes):
        raw_bytes = file_stream_or_bytes
        raw_head = raw_bytes[:4]
        is_zip = filename.lower().endswith(".zip") or raw_head.startswith(b"PK\x03\x04")
        bio = io.BytesIO(raw_bytes)
    elif hasattr(file_stream_or_bytes, "read"):
        stream = file_stream_or_bytes
        # Read small sample to probe for ZIP header without buffering entire file in memory
        raw_head = stream.read(4)
        stream.seek(0)
        is_zip = filename.lower().endswith(".zip") or raw_head.startswith(b"PK\x03\x04")
        bio = stream
    else:
        return {"status": "error", "message": "Invalid file input type"}

    # 2. Handle ZIP Archives (FR-13)
    if is_zip:
        return _ingest_zip_container(source_name, bio, filename=filename)

    # 3. Handle Standard Text / Log Stream with Streaming (Memory-Efficient)
    return _ingest_text_stream(source_name, bio)


def _ingest_zip_container(source_name: str, stream: Any, filename: str = "") -> Dict[str, Any]:
    """Extract and enqueue log members from a ZIP container. Quarantines invalid archives."""
    try:
        if not zipfile.is_zipfile(stream):
            # Probe failed — invalid or corrupt ZIP
            stream.seek(0)
            corrupt_bytes = stream.read(512)
            parser.parse_line(corrupt_bytes, declared_source=source_name)
            return {"status": "error", "message": "Invalid ZIP container: Corrupted or not a valid archive"}

        stream.seek(0)
        with zipfile.ZipFile(stream) as zf:
            members = [m for m in zf.namelist() if not m.endswith("/")]

            # Security: Path traversal protection
            for m in members:
                if not is_safe_zip_path(m):
                    parser.parse_line(f"SECURITY_VIOLATION: Directory traversal path in ZIP: {m}".encode("utf-8"), declared_source=source_name)
                    return {"status": "error", "message": f"Security restriction: Directory traversal detected in ZIP member '{m}'"}

            # Resource exhaustion protections (zip bomb mitigation)
            if len(members) > 100:
                return {"status": "error", "message": f"Security restriction: ZIP archive contains {len(members)} files (max limit 100)"}

            total_uncompressed = sum(zf.getinfo(m).file_size for m in members)
            if total_uncompressed > 100 * 1024 * 1024:
                return {"status": "error", "message": f"Security restriction: ZIP uncompressed size {total_uncompressed / (1024*1024):.1f}MB exceeds limit of 100MB"}

            log_members = [m for m in members if m.lower().endswith((".log", ".txt", ".csv"))]
            if not log_members and members:
                log_members = [members[0]]  # Fallback to first non-directory member

            if not log_members:
                return {"status": "error", "message": "ZIP archive contains no readable log files"}

            processed_count = 0
            for member in log_members:
                with zf.open(member, "r") as member_file:
                    text_stream = io.TextIOWrapper(member_file, encoding="utf-8", errors="replace")
                    while True:
                        line, is_oversized = _safe_readline(text_stream, MAX_RECORD_SIZE)
                        if is_oversized:
                            parser.parse_line(b"OVERSIZED_RECORD: Line in ZIP exceeds 64KB limit", declared_source=source_name)
                            continue
                        if not line:
                            break
                        clean_line = line.rstrip("\r\n")
                        if clean_line:
                            log_queue.put((source_name, clean_line))
                            _increment_processed(1)
                            processed_count += 1

            return {"status": "success", "lines_queued": processed_count}

    except Exception as exc:
        # Quarantine invalid zip data via E2 Parser
        try:
            stream.seek(0)
            corrupt_bytes = stream.read(512)
        except Exception:
            corrupt_bytes = b"CORRUPTED_ZIP_STREAM"
        parser.parse_line(corrupt_bytes, declared_source=source_name)
        return {"status": "error", "message": f"Invalid zip file: {exc}"}


def _ingest_text_stream(source_name: str, stream: Any) -> Dict[str, Any]:
    """Stream text lines line-by-line into the queue without loading whole file into memory."""
    try:
        # Wrap stream in TextIOWrapper if binary
        if isinstance(stream, io.BytesIO):
            # Check for binary null-byte probe
            stream.seek(0)
            probe = stream.read(1024)
            if b"\x00" in probe:
                stream.seek(0)
                parser.parse_line(stream.read(), declared_source=source_name)
                return {"status": "rejected", "lines": 1}
            stream.seek(0)
            text_stream = io.TextIOWrapper(stream, encoding="utf-8", errors="replace")
        elif hasattr(stream, "read"):
            text_stream = io.TextIOWrapper(stream, encoding="utf-8", errors="replace")
        else:
            text_stream = stream

        processed_count = 0
        while True:
            line, is_oversized = _safe_readline(text_stream, MAX_RECORD_SIZE)
            if is_oversized:
                parser.parse_line(b"OVERSIZED_RECORD: Line exceeds 64KB limit", declared_source=source_name)
                continue
            if not line:
                break
            clean_line = line.rstrip("\r\n")
            if clean_line and not clean_line.startswith("#"):
                log_queue.put((source_name, clean_line))
                _increment_processed(1)
                processed_count += 1

        return {"status": "success", "lines_queued": processed_count}

    except Exception as exc:
        return {"status": "error", "message": f"Text stream ingestion error: {exc}"}


def ingest_file_path(source_name: str, file_path: str) -> Dict[str, Any]:
    """
    Ingest a file from disk line-by-line (e.g. 205 MB NASA HTTP log or HDFS_2k.log).
    Guarantees $O(1)$ memory usage via line-by-line streaming generator.
    """
    if not os.path.exists(file_path):
        return {"status": "error", "message": f"File not found: {file_path}"}

    # If ZIP, use ingest_file_stream
    if file_path.lower().endswith(".zip"):
        with open(file_path, "rb") as f:
            return ingest_file_stream(source_name, f, filename=os.path.basename(file_path))

    processed_count = 0
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            while True:
                line, is_oversized = _safe_readline(f, MAX_RECORD_SIZE)
                if is_oversized:
                    parser.parse_line(b"OVERSIZED_RECORD: Line exceeds 64KB limit", declared_source=source_name)
                    continue
                if not line:
                    break
                clean_line = line.rstrip("\r\n")
                if clean_line and not clean_line.startswith("#"):
                    log_queue.put((source_name, clean_line))
                    _increment_processed(1)
                    processed_count += 1
        return {"status": "success", "lines_queued": processed_count}
    except Exception as exc:
        return {"status": "error", "message": f"Disk ingestion error: {exc}"}
