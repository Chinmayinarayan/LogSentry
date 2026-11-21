import re

CATEGORY_RULES = [
    (re.compile(r"failed login|authentication failed", re.I), "auth_failure"),
    (re.compile(r"connection refused|timeout|unreachable", re.I), "network_failure"),
    (re.compile(r"disk full|no space left", re.I), "storage_failure"),
    (re.compile(r"outofmemory|heap space", re.I), "resource_exhaustion"),
]

SEVERITY_PATTERN = re.compile(r"\[(INFO|WARN|WARNING|ERROR|FATAL)\]", re.I)
TIMESTAMP_PATTERN = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")


def categorize(message: str) -> str:
    for pattern, category in CATEGORY_RULES:
        if pattern.search(message):
            return category
    return "uncategorized"


def extract_severity(line: str) -> str:
    match = SEVERITY_PATTERN.search(line)
    return match.group(1).upper() if match else "INFO"


def extract_timestamp(line: str) -> str:
    match = TIMESTAMP_PATTERN.search(line)
    return match.group(1) if match else ""
