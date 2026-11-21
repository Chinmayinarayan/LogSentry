"""
Pytest Configuration & Fixtures for LogSentry.

Ensures test isolation:
- Redirects DB_PATH to a temporary SQLite database file for the test session.
- Prevents tests from modifying or resetting the production vault/logsentry.db file.
"""

import os
import tempfile
import pytest

from vault import db


@pytest.fixture(scope="session", autouse=True)
def isolate_test_database():
    """Redirect all tests to an isolated temporary SQLite database."""
    fd, tmp_db = tempfile.mkstemp(suffix="_test_logsentry.db")
    os.close(fd)

    original_db = db.get_db_path()
    db.set_db_path(tmp_db)
    db.init_db()

    yield tmp_db

    db.set_db_path(original_db)
    try:
        if os.path.exists(tmp_db):
            os.remove(tmp_db)
    except OSError:
        pass
