#!/usr/bin/env python3
"""
LogSentry Accuracy Validation Harness.

Replays HDFS / NASA-HTTP datasets, joins on HDFS block IDs with `anomaly_label.csv`,
and evaluates Precision, Recall, F1 score, and status code distributions.
"""

import argparse
import csv
import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

# Add project root to sys.path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from parse import parser
from vault import db

BLOCK_ID_RE = re.compile(r"blk_-?\d+")


def extract_block_ids(text):
    if not text:
        return set()
    return set(BLOCK_ID_RE.findall(text))


def load_anomaly_labels(label_path):
    """
    Load Loghub anomaly_label.csv (BlockId, Label).
    Returns dict: block_id -> 'anomaly' | 'normal'.
    """
    path = Path(label_path)
    if not path.is_file():
        raise FileNotFoundError(f"Label file not found: {label_path}")

    mapping = {}
    with path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames:
            raise ValueError(f"Empty CSV file: {label_path}")

        field_map = {n.lower().strip(): n for n in reader.fieldnames}
        block_key = field_map.get("blockid") or field_map.get("block_id")
        label_key = field_map.get("label")
        if not block_key or not label_key:
            raise ValueError("CSV must contain BlockId and Label columns")

        for row in reader:
            bid = (row.get(block_key) or "").strip()
            lbl = (row.get(label_key) or "").strip().lower()
            if not bid:
                continue
            if lbl in ("anomaly", "anomalous", "1", "true", "yes"):
                mapping[bid] = "anomaly"
            elif lbl in ("normal", "0", "false", "no"):
                mapping[bid] = "normal"
    return mapping


def evaluate_dataset(log_path, label_path=None, source_type="hdfs"):
    """Replay log dataset through E2 parser, tracking events, rejections, and block anomalies."""
    db.init_db()
    db.reset_db()
    parser.reset_sliding_windows()
    parser.refresh_config_cache()

    path = Path(log_path)
    if not path.is_file():
        raise FileNotFoundError(f"Log file not found: {log_path}")

    total_lines = 0
    classified_events = 0
    quarantined_rejections = 0
    detected_block_anomalies = set()
    level_counts = Counter()

    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            total_lines += 1
            res = parser.parse_line(line, declared_source=source_type)
            if res:
                classified_events += 1
                level_counts[res["log_level"]] += 1

                # Extract block IDs for HDFS evaluation
                bids = extract_block_ids(res["raw_message"])
                if res["log_level"] in ("WARN", "WARNING", "ERROR", "FATAL") or "got exception while serving block" in res["raw_message"].lower():
                    detected_block_anomalies.update(bids)
            else:
                if line.strip():
                    quarantined_rejections += 1

    metrics = {
        "log_file": str(path),
        "total_lines": total_lines,
        "classified_events": classified_events,
        "quarantined_rejections": quarantined_rejections,
        "log_level_distribution": dict(level_counts),
        "detected_anomaly_blocks_count": len(detected_block_anomalies),
    }

    # Evaluate against ground truth labels if provided
    if label_path:
        labels = load_anomaly_labels(label_path)
        ground_truth_anomalies = {bid for bid, lbl in labels.items() if lbl == "anomaly"}
        ground_truth_normals = {bid for bid, lbl in labels.items() if lbl == "normal"}

        tp = len(detected_block_anomalies & ground_truth_anomalies)
        fp = len(detected_block_anomalies & ground_truth_normals)
        fn = len(ground_truth_anomalies - detected_block_anomalies)
        tn = len(ground_truth_normals - detected_block_anomalies)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

        metrics["accuracy_eval"] = {
            "ground_truth_anomalies": len(ground_truth_anomalies),
            "ground_truth_normals": len(ground_truth_normals),
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "true_negatives": tn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
        }

    return metrics


def main():
    argp = argparse.ArgumentParser(description="LogSentry Validation Harness")
    argp.add_argument("--log", required=True, help="Path to log file (HDFS or NASA-HTTP)")
    argp.add_argument("--labels", help="Path to ground truth anomaly_label.csv")
    argp.add_argument("--source", default="hdfs", choices=["hdfs", "nasa_http"], help="Log source format")
    argp.add_argument("--json-out", help="Path to save evaluation metrics JSON")
    args = argp.parse_args()

    res = evaluate_dataset(args.log, label_path=args.labels, source_type=args.source)

    print("\n================ LOGSENTRY VALIDATION RESULTS ================")
    print(f"Log File:               {res['log_file']}")
    print(f"Total Lines Ingested:   {res['total_lines']}")
    print(f"Classified Events:      {res['classified_events']}")
    print(f"Quarantined Rejections: {res['quarantined_rejections']}")
    print(f"Level Distribution:     {res['log_level_distribution']}")

    if "accuracy_eval" in res:
        acc = res["accuracy_eval"]
        print("\n--- GROUND TRUTH ACCURACY METRICS ---")
        print(f"True Positives:  {acc['true_positives']}")
        print(f"False Positives: {acc['false_positives']}")
        print(f"False Negatives: {acc['false_negatives']}")
        print(f"Precision:       {acc['precision'] * 100:.2f}%")
        print(f"Recall:          {acc['recall'] * 100:.2f}%")
        print(f"F1 Score:        {acc['f1_score'] * 100:.2f}%")
    print("===============================================================\n")

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(res, f, indent=2)
        print(f"Saved results JSON to {args.json_out}")


if __name__ == "__main__":
    main()
