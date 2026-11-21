"""
LogSentry — Standalone accuracy validation (does not modify live app code).

Supports two modes:
  --mode time-based   : replays a log through the real detector's time-based
                         sliding window, reports unvalidated counts (or, if
                         you also had line-level ground truth, could be
                         extended to score them — not used for HDFS).
  --mode block-level   : evaluates against HDFS's per-BlockId ground truth
                         (anomaly_label.csv), which is what HDFS's labels
                         actually measure.

This script reuses the exact category/severity rules from the live
parse/parser.py (copied here verbatim, not imported, so this tool has zero
side effects on the live app or its database).
"""

import re
import csv
import json
import argparse
import sys
from collections import deque, defaultdict
from datetime import datetime, timezone

# ---- Exact copy of live detection rules (parse/parser.py) ----
WINDOW_SECONDS = 10
THRESHOLD = 5

SEVERITY_PATTERN = re.compile(r"\[(INFO|WARN|WARNING|ERROR|FATAL)\]", re.I)
CATEGORY_RULES = [
    (re.compile(r"failed login|authentication failed|auth.?fail", re.I), "auth_failure"),
    (re.compile(r"connection refused|timeout|unreachable", re.I), "network_failure"),
    (re.compile(r"disk full|no space left", re.I), "storage_failure"),
    (re.compile(r"outofmemory|heap space", re.I), "resource_exhaustion"),
]

BLOCK_ID_PATTERN = re.compile(r"(blk_-?\d+)")


def extract_severity(line: str) -> str:
    match = SEVERITY_PATTERN.search(line)
    return match.group(1).upper() if match else "INFO"


def extract_category(line: str) -> str:
    for pattern, category in CATEGORY_RULES:
        if pattern.search(line):
            return category
    return "uncategorized"


def extract_block_id(line: str) -> str:
    match = BLOCK_ID_PATTERN.search(line)
    return match.group(1) if match else None


def run_time_based(log_path: str) -> dict:
    """Reproduces the live app's time-based sliding-window behavior,
    entirely in-memory — no DB writes."""
    sliding_windows = {"auth_failure": deque()}
    event_categories = defaultdict(int)
    alert_categories = defaultdict(int)
    alerts = []
    lines_processed = 0
    lines_skipped_blank = 0

    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line:
                lines_skipped_blank += 1
                continue
            lines_processed += 1

            category = extract_category(line)
            event_categories[category] += 1

            if category in sliding_windows:
                import time
                now = time.time()
                window = sliding_windows[category]
                window.append(now)
                while window and now - window[0] > WINDOW_SECONDS:
                    window.popleft()
                if len(window) >= THRESHOLD:
                    alert_categories[category] += 1
                    alerts.append({
                        "category": category,
                        "matched_line": line,
                    })
                    window.clear()

    return {
        "lines_processed": lines_processed,
        "lines_skipped_blank": lines_skipped_blank,
        "event_categories": dict(event_categories),
        "alert_categories": dict(alert_categories),
        "alerts": alerts,
    }


def run_block_level(log_path: str, labels_path: str) -> dict:
    """
    Evaluates per-BlockId: a block is 'flagged' by our system if ANY of its
    lines were classified as non-uncategorized OR had WARN/ERROR/FATAL
    severity. Compared against HDFS's ground-truth Normal/Anomaly labels.
    """
    flagged_blocks = set()
    all_seen_blocks = set()
    lines_processed = 0
    lines_with_no_block_id = 0

    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line:
                continue
            lines_processed += 1

            block_id = extract_block_id(line)
            if block_id is None:
                lines_with_no_block_id += 1
                continue

            all_seen_blocks.add(block_id)
            severity = extract_severity(line)
            category = extract_category(line)

            if category != "uncategorized" or severity in ("WARN", "WARNING", "ERROR", "FATAL"):
                flagged_blocks.add(block_id)

    # Load ground truth
    ground_truth = {}
    with open(labels_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            block_id = row.get("BlockId") or row.get("blockid") or row.get("blk_id")
            label = (row.get("Label") or row.get("label") or "").strip().lower()
            if block_id:
                ground_truth[block_id.strip()] = label

    tp = fp = fn = tn = 0
    example_fp = None
    example_fn = None

    for block_id, label in ground_truth.items():
        is_anomaly = (label == "anomaly")
        is_flagged = block_id in flagged_blocks

        if is_anomaly and is_flagged:
            tp += 1
        elif not is_anomaly and is_flagged:
            fp += 1
            if example_fp is None:
                example_fp = block_id
        elif is_anomaly and not is_flagged:
            fn += 1
            if example_fn is None:
                example_fn = block_id
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    warning = None
    total_blocks_scored = tp + fp + fn + tn
    if total_blocks_scored == 0:
        warning = "No overlap between blocks found in the log and blocks in the labels file — check both inputs."
    elif (tp + fp) == 0:
        warning = "Our system flagged zero blocks that also appear in the ground truth — category rules likely don't match this dataset's real anomaly patterns."

    return {
        "lines_processed": lines_processed,
        "lines_with_no_block_id": lines_with_no_block_id,
        "unique_blocks_seen_in_log": len(all_seen_blocks),
        "unique_blocks_flagged_by_system": len(flagged_blocks),
        "unique_blocks_in_ground_truth": len(ground_truth),
        "confusion_matrix": {"TP": tp, "FP": fp, "FN": fn, "TN": tn},
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "example_false_positive_block": example_fp,
        "example_false_negative_block": example_fn,
        "warning": warning,
    }


def main():
    parser = argparse.ArgumentParser(description="LogSentry accuracy validation")
    parser.add_argument("--log", required=True, help="Path to log file")
    parser.add_argument("--labels", help="Path to anomaly_label.csv (required for block-level mode)")
    parser.add_argument("--mode", choices=["time-based", "block-level"], default="time-based")
    parser.add_argument("--json-out", help="Optional path to write JSON results")
    args = parser.parse_args()

    if args.mode == "block-level" and not args.labels:
        print("ERROR: --mode block-level requires --labels <anomaly_label.csv>", file=sys.stderr)
        sys.exit(1)

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    result = {
        "generated_at": generated_at,
        "project": "LogSentry",
        "mode": args.mode,
        "log_path": args.log,
        "labels_path": args.labels,
    }

    print("=" * 72)
    print("LogSentry accuracy validation")
    print("=" * 72)
    print(f"Mode         : {args.mode}")
    print(f"Log file     : {args.log}")
    print(f"Labels file  : {args.labels or '(none)'}")
    print("-" * 72)

    if args.mode == "time-based":
        r = run_time_based(args.log)
        result["time_based_evaluation"] = r
        print(f"Lines processed : {r['lines_processed']}")
        print(f"Event categories : {r['event_categories']}")
        print(f"Alert categories : {r['alert_categories']}")
        print("-" * 72)
        print("RESULT TYPE: UNVALIDATED COUNTS (no per-line ground truth used in this mode)")

    else:
        r = run_block_level(args.log, args.labels)
        result["block_level_evaluation"] = r
        print(f"Lines processed              : {r['lines_processed']}")
        print(f"Unique blocks seen in log    : {r['unique_blocks_seen_in_log']}")
        print(f"Unique blocks flagged by us  : {r['unique_blocks_flagged_by_system']}")
        print(f"Unique blocks in ground truth: {r['unique_blocks_in_ground_truth']}")
        cm = r["confusion_matrix"]
        print(f"Confusion matrix — TP:{cm['TP']} FP:{cm['FP']} FN:{cm['FN']} TN:{cm['TN']}")
        print(f"Precision : {r['precision']}")
        print(f"Recall    : {r['recall']}")
        print(f"F1        : {r['f1']}")
        if r["warning"]:
            print(f"\n*** WARNING: {r['warning']} ***")
        print("-" * 72)
        print("RESULT TYPE: BLOCK-LEVEL EVALUATION (real ground truth from anomaly_label.csv)")

    print("=" * 72)

    if args.json_out:
        with open(args.json_out, "w") as f:
            json.dump(result, f, indent=2)
        print(f"\nJSON results written to: {args.json_out}")
    else:
        print("\n--- JSON ---")
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
