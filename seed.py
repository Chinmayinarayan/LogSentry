"""
LogSentry Seed Script — Populates initial database with sample logs.
Updated for 4-engine architecture and active database schema.
"""

import os
import sys

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vault import db
from parse import parser


def seed():
    print("Initializing database schema...")
    db.init_db()
    parser.refresh_config_cache()

    sample_log = os.path.join(os.path.dirname(__file__), "data", "sample.log")
    if not os.path.exists(sample_log):
        print(f"Sample log file not found at {sample_log}")
        return

    print(f"Seeding sample log from {sample_log}...")
    count = 0
    with open(sample_log, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line_str = line.strip()
            if line_str and not line_str.startswith("#"):
                res = parser.parse_line(line_str, declared_source="hdfs")
                if res:
                    count += 1

    print(f"Seeded {count} valid events successfully.")


if __name__ == "__main__":
    seed()
