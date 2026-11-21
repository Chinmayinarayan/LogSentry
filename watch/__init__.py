"""
E1 WATCH Package — Ingestion, Live Monitoring, and Bounded Queue Buffering.
"""

from watch.tailer import (
    log_queue,
    QUEUE_MAXSIZE,
    worker_thread,
    start_watcher,
    stop_watcher,
    stop_all_watchers,
    ingest_file_stream,
    ingest_file_path,
    get_metrics,
    get_active_watchers,
    reset_metrics,
)

__all__ = [
    "log_queue",
    "QUEUE_MAXSIZE",
    "worker_thread",
    "start_watcher",
    "stop_watcher",
    "stop_all_watchers",
    "ingest_file_stream",
    "ingest_file_path",
    "get_metrics",
    "get_active_watchers",
    "reset_metrics",
]
