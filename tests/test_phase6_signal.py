"""
Phase 6: E4 SIGNAL Implementation & System Integration Test Suite.

Exhaustive verification of Engine 4 (E4 SIGNAL):
1. REST API responses and status codes.
2. Event filtering and pagination.
3. Alert filtering by status.
4. ADMIN role permissions (full management, configuration, reset).
5. OPERATOR role permissions (monitoring, alert resolution, blocked from admin/config).
6. VIEWER role read-only restrictions (blocked from resolution, configuration, user creation).
7. Unauthorized request rejection (401 for unauthenticated, 403 for insufficient role).
8. Alert resolution lifecycle and E3 audit history tracking.
9. Configuration updates, positive integer validation, and error rejection.
10. Configuration persistence in SQLite and dynamic reload in E2 cache.
11. Pending alert persistence buffer metrics API (/api/metrics/pending-alerts & /api/stats).
12. Dashboard route, authentication lifecycle, and zero password exposure.
13. End-to-end ingestion-to-dashboard pipeline (E1 -> E2 -> E3 -> E4).
14. Error handling, invalid payloads, and boundary conditions.
"""

import io
import json
import os
import sqlite3
import tempfile
import time
import pytest
from werkzeug.security import check_password_hash

from signal_app import app, start_consumer
from vault import db
from parse import parser
from watch import tailer


@pytest.fixture(autouse=True)
def isolated_signal_environment():
    """Ensure every test runs against an isolated SQLite database and fresh runtime state."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    orig_path = db.get_db_path()
    db.set_db_path(path)
    db.init_db()
    parser.refresh_config_cache()
    parser.reset_sliding_windows()
    parser.reset_pending_alerts()
    tailer.reset_metrics()

    yield path

    db.set_db_path(orig_path)
    for ext in ("", "-wal", "-shm"):
        f = path + ext
        if os.path.exists(f):
            try:
                os.remove(f)
            except OSError:
                pass


@pytest.fixture
def client():
    """Create a configured Flask test client."""
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


# ---------------------------------------------------------------------------
# 1. REST API Responses and Status Codes
# ---------------------------------------------------------------------------

def test_rest_api_responses_and_status_codes(client):
    """Verify core REST API endpoints return 200 OK and expected JSON schema."""
    # Stats endpoint
    res = client.get("/api/stats")
    assert res.status_code == 200
    data = res.get_json()
    assert "total_events" in data
    assert "errors" in data
    assert "active_alerts" in data
    assert "rejected_lines" in data
    assert "alert_buffer_metrics" in data

    # Events endpoint
    res = client.get("/api/events")
    assert res.status_code == 200
    data = res.get_json()
    assert "events" in data
    assert "total" in data

    # Alerts endpoint
    res = client.get("/api/alerts")
    assert res.status_code == 200
    data = res.get_json()
    assert "alerts" in data

    # Timeseries endpoint
    res = client.get("/api/metrics/timeseries")
    assert res.status_code == 200
    data = res.get_json()
    assert "labels" in data
    assert "events" in data
    assert "errors" in data

    # Rejected records endpoint
    res = client.get("/api/rejected")
    assert res.status_code == 200
    data = res.get_json()
    assert "rejected" in data
    assert "count" in data

    # Me (unauthenticated)
    res = client.get("/api/me")
    assert res.status_code == 200
    assert res.get_json()["authenticated"] is False


# ---------------------------------------------------------------------------
# 2. Event Filtering and Pagination
# ---------------------------------------------------------------------------

def test_event_filtering_and_pagination(client):
    """Verify events can be filtered by source, severity, and paginated correctly."""
    events = [
        {"source": "hdfs", "log_level": "INFO", "component_host": "h1", "raw_message": "HDFS info 1", "timestamp": "2026-11-21 12:00:01"},
        {"source": "hdfs", "log_level": "WARN", "component_host": "h2", "raw_message": "HDFS warn 2", "timestamp": "2026-11-21 12:00:02"},
        {"source": "hdfs", "log_level": "ERROR", "component_host": "h3", "raw_message": "HDFS error 3", "timestamp": "2026-11-21 12:00:03"},
        {"source": "nasa_http", "log_level": "INFO", "component_host": "n1", "raw_message": "NASA info 4", "timestamp": "2026-11-21 12:00:04"},
        {"source": "nasa_http", "log_level": "ERROR", "component_host": "n2", "raw_message": "NASA error 5", "timestamp": "2026-11-21 12:00:05"},
    ]
    db.save_events_batch(events)

    # 1. Pagination: 2 items per page
    res_p1 = client.get("/api/events?page=1&limit=2")
    assert res_p1.status_code == 200
    d1 = res_p1.get_json()
    assert d1["total"] == 5
    assert len(d1["events"]) == 2
    assert d1["page"] == 1

    res_p2 = client.get("/api/events?page=2&limit=2")
    assert res_p2.status_code == 200
    d2 = res_p2.get_json()
    assert len(d2["events"]) == 2

    # 2. Source filtering (case-insensitive)
    res_hdfs = client.get("/api/events?source=HDFS")
    assert res_hdfs.status_code == 200
    assert res_hdfs.get_json()["total"] == 3

    res_nasa = client.get("/api/events?source=NASA-HTTP")
    assert res_nasa.status_code == 200
    assert res_nasa.get_json()["total"] == 2

    # 3. Severity filtering
    res_err = client.get("/api/events?level=ERROR")
    assert res_err.status_code == 200
    assert res_err.get_json()["total"] == 2

    # 4. Source + Severity combined
    res_comb = client.get("/api/events?source=hdfs&level=WARN")
    assert res_comb.status_code == 200
    assert res_comb.get_json()["total"] == 1


# ---------------------------------------------------------------------------
# 3. Alert Filtering by Status
# ---------------------------------------------------------------------------

def test_alert_filtering(client):
    """Verify alerts can be retrieved and filtered by status (ACTIVE / RESOLVED)."""
    a1 = db.save_alert("hdfs", "ANOMALY_BURST", 5, 60)
    a2 = db.save_alert("nasa_http", "ANOMALY_BURST", 6, 60)
    admin = db.get_user_by_username("admin")
    db.resolve_alert(a1, user_id=admin["user_id"])

    # All alerts
    res_all = client.get("/api/alerts")
    assert res_all.status_code == 200
    assert len(res_all.get_json()["alerts"]) == 2

    # Active only
    res_act = client.get("/api/alerts?status=ACTIVE")
    assert res_act.status_code == 200
    alerts_act = res_act.get_json()["alerts"]
    assert len(alerts_act) == 1
    assert alerts_act[0]["alert_id"] == a2

    # Resolved only
    res_res = client.get("/api/alerts?status=RESOLVED")
    assert res_res.status_code == 200
    alerts_res = res_res.get_json()["alerts"]
    assert len(alerts_res) == 1
    assert alerts_res[0]["alert_id"] == a1


# ---------------------------------------------------------------------------
# 4. ADMIN Role Permissions
# ---------------------------------------------------------------------------

def test_admin_permissions(client):
    """Verify ADMIN role has full authority over config, users, alerts, and live monitoring."""
    # Login as admin
    login_res = client.post("/api/login", json={"username": "admin", "password": "adminpassword"})
    assert login_res.status_code == 200

    # 1. Update config
    cfg_res = client.post("/api/config", json={"hdfs_threshold": "10"})
    assert cfg_res.status_code == 200
    assert "hdfs_threshold" in cfg_res.get_json()["updated_keys"]

    # 2. View users
    users_res = client.get("/api/users")
    assert users_res.status_code == 200
    assert len(users_res.get_json()["users"]) >= 3

    # 3. Create user
    new_user_res = client.post("/api/users", json={"username": "op_test", "password": "pwd", "role": "OPERATOR"})
    assert new_user_res.status_code == 200

    # 4. Resolve alert
    aid = db.save_alert("hdfs", "BURST", 5, 60)
    resolve_res = client.post(f"/api/alerts/{aid}/resolve")
    assert resolve_res.status_code == 200

    # 5. Reset system
    reset_res = client.post("/api/reset")
    assert reset_res.status_code == 200


# ---------------------------------------------------------------------------
# 5. OPERATOR Role Permissions
# ---------------------------------------------------------------------------

def test_operator_permissions(client):
    """Verify OPERATOR can monitor and resolve alerts, but is forbidden from config and user management."""
    login_res = client.post("/api/login", json={"username": "operator", "password": "operatorpassword"})
    assert login_res.status_code == 200

    # 1. Allowed: Resolve alert
    aid = db.save_alert("hdfs", "BURST", 5, 60)
    res_alert = client.post(f"/api/alerts/{aid}/resolve")
    assert res_alert.status_code == 200

    # 2. Forbidden: Modify configuration
    res_cfg = client.post("/api/config", json={"hdfs_threshold": "20"})
    assert res_cfg.status_code == 403

    # 3. Forbidden: Manage users
    res_usr = client.post("/api/users", json={"username": "hacker", "password": "p", "role": "ADMIN"})
    assert res_usr.status_code == 403

    res_get_usr = client.get("/api/users")
    assert res_get_usr.status_code == 403

    # 4. Forbidden: Reset system
    res_rst = client.post("/api/reset")
    assert res_rst.status_code == 403


# ---------------------------------------------------------------------------
# 6. VIEWER Role Read-Only Restrictions
# ---------------------------------------------------------------------------

def test_viewer_read_only_restrictions(client):
    """Verify VIEWER role has read-only access and is blocked from any mutations."""
    login_res = client.post("/api/login", json={"username": "viewer", "password": "viewerpassword"})
    assert login_res.status_code == 200

    # 1. Allowed: Read operations
    assert client.get("/api/events").status_code == 200
    assert client.get("/api/alerts").status_code == 200
    assert client.get("/api/stats").status_code == 200
    assert client.get("/api/config").status_code == 200

    # 2. Forbidden: Resolve alert
    aid = db.save_alert("hdfs", "BURST", 5, 60)
    assert client.post(f"/api/alerts/{aid}/resolve").status_code == 403

    # 3. Forbidden: Update config
    assert client.post("/api/config", json={"hdfs_window": "30"}).status_code == 403

    # 4. Forbidden: Create users
    assert client.post("/api/users", json={"username": "u", "password": "p", "role": "ADMIN"}).status_code == 403

    # 5. Forbidden: Ingestion controls
    assert client.post("/api/ingest/live/start", json={"source": "hdfs", "file_path": "/var/log"}).status_code == 403
    assert client.post("/api/ingest/live/stop", json={"source": "hdfs"}).status_code == 403


# ---------------------------------------------------------------------------
# 7. Unauthorized Access Rejection (401 Status)
# ---------------------------------------------------------------------------

def test_unauthorized_access_rejection(client):
    """Verify unauthenticated requests to protected endpoints receive 401 Unauthorized."""
    # No login performed
    aid = db.save_alert("hdfs", "BURST", 5, 60)

    assert client.post(f"/api/alerts/{aid}/resolve").status_code == 401
    assert client.post("/api/config", json={"hdfs_threshold": "10"}).status_code == 401
    assert client.get("/api/users").status_code == 401
    assert client.post("/api/users", json={"username": "u", "password": "p", "role": "ADMIN"}).status_code == 401
    assert client.post("/api/ingest/live/start", json={"source": "hdfs", "file_path": "/tmp/a.log"}).status_code == 401
    assert client.post("/api/ingest/live/stop", json={"source": "hdfs"}).status_code == 401
    assert client.post("/api/reset").status_code == 401


# ---------------------------------------------------------------------------
# 8. Alert Resolution and Audit History Tracking
# ---------------------------------------------------------------------------

def test_alert_resolution_and_audit_history(client):
    """Verify alert resolution updates status and logs immutable audit trail."""
    aid = db.save_alert("hdfs", "ANOMALY_BURST", 5, 60)

    # Resolve as operator
    client.post("/api/login", json={"username": "operator", "password": "operatorpassword"})
    res = client.post(f"/api/alerts/{aid}/resolve")
    assert res.status_code == 200

    # Check alert history endpoint
    res_hist = client.get(f"/api/alerts/{aid}/history")
    assert res_hist.status_code == 200
    hist = res_hist.get_json()["history"]
    assert len(hist) == 1
    assert hist[0]["field_changed"] == "status"
    assert hist[0]["old_value"] == "ACTIVE"
    assert hist[0]["new_value"] == "RESOLVED"
    assert hist[0]["changed_by_name"] == "operator"

    # Non-existent alert returns 404
    res_404 = client.post("/api/alerts/999999/resolve")
    assert res_404.status_code == 404


# ---------------------------------------------------------------------------
# 9. Configuration Updates and Input Validation
# ---------------------------------------------------------------------------

def test_configuration_updates_and_validation(client):
    """Verify configuration validation rejects non-positive or invalid inputs with 400 Bad Request."""
    client.post("/api/login", json={"username": "admin", "password": "adminpassword"})

    # Valid update
    res_ok = client.post("/api/config", json={"hdfs_threshold": "12", "hdfs_window": "90"})
    assert res_ok.status_code == 200

    # Negative integer rejected
    res_neg = client.post("/api/config", json={"hdfs_threshold": "-5"})
    assert res_neg.status_code == 400
    assert "positive integer" in res_neg.get_json()["error"]

    # Zero rejected
    res_zero = client.post("/api/config", json={"hdfs_window": "0"})
    assert res_zero.status_code == 400

    # Non-integer string rejected
    res_str = client.post("/api/config", json={"hdfs_window": "not_a_number"})
    assert res_str.status_code == 400

    # Empty payload rejected
    res_empty = client.post("/api/config", json={})
    assert res_empty.status_code == 400


# ---------------------------------------------------------------------------
# 10. Configuration Persistence and E2 Dynamic Reload
# ---------------------------------------------------------------------------

def test_configuration_persistence_and_e2_reload(client):
    """Verify config updates persist in SQLite and are dynamically reloaded into E2 parser cache."""
    client.post("/api/login", json={"username": "admin", "password": "adminpassword"})

    # Update threshold to 8
    client.post("/api/config", json={"hdfs_threshold": "8", "hdfs_window": "45"})

    # 1. Verified in database
    configs = db.get_all_configs()
    assert configs["hdfs_threshold"] == "8"
    assert configs["hdfs_window"] == "45"

    # 2. Verified in E2 live cache
    cache = parser.get_config_cache()
    assert cache["hdfs_threshold"] == 8
    assert cache["hdfs_window"] == 45


# ---------------------------------------------------------------------------
# 11. Pending Alert Buffer Metrics API
# ---------------------------------------------------------------------------

def test_pending_alert_buffer_metrics_api(client):
    """Verify /api/metrics/pending-alerts accurately reports E2 pending buffer metrics."""
    res = client.get("/api/metrics/pending-alerts")
    assert res.status_code == 200
    data = res.get_json()

    assert "hdfs" in data and "nasa_http" in data
    hdfs_m = data["hdfs"]
    assert hdfs_m["pending_count"] == 0
    assert hdfs_m["buffer_capacity"] == 1000
    assert hdfs_m["dropped_count"] == 0
    assert hdfs_m["has_pending_alerts"] is False
    assert hdfs_m["has_dropped_alerts"] is False

    # Also verified in /api/stats
    stats_res = client.get("/api/stats")
    assert "alert_buffer_metrics" in stats_res.get_json()


# ---------------------------------------------------------------------------
# 12. Dashboard Route and Authentication Lifecycle
# ---------------------------------------------------------------------------

def test_dashboard_route_and_authentication(client):
    """Verify dashboard UI route, login/logout flow, and zero password exposure."""
    # 1. Dashboard HTML route
    res_dash = client.get("/")
    assert res_dash.status_code == 200
    assert b"LogSentry" in res_dash.data

    # 2. Login lifecycle
    res_login = client.post("/api/login", json={"username": "admin", "password": "adminpassword"})
    assert res_login.status_code == 200
    user_data = res_login.get_json()["user"]
    assert user_data["username"] == "admin"
    assert "password" not in user_data
    assert "password_hash" not in user_data

    # 3. Check /api/me
    res_me = client.get("/api/me")
    assert res_me.status_code == 200
    assert res_me.get_json()["authenticated"] is True

    # 4. Logout
    res_logout = client.post("/api/logout")
    assert res_logout.status_code == 200

    res_me_after = client.get("/api/me")
    assert res_me_after.get_json()["authenticated"] is False


# ---------------------------------------------------------------------------
# 13. End-to-End Ingestion-to-Dashboard Integration
# ---------------------------------------------------------------------------

def test_end_to_end_ingestion_to_dashboard_integration(client):
    """Verify E1 -> E2 -> E3 -> E4 end-to-end data flow: upload -> parse -> vault -> dashboard stats."""
    # Representative sample of HDFS logs (3 valid lines)
    sample_hdfs_content = (
        "081109 203518 143 INFO dfs.DataNode$DataXceiver: Receiving block blk_-1608999687919862906 src: /10.250.19.102:54106 dest: /10.250.19.102:50010\n"
        "081109 203519 144 WARN dfs.DataNode$DataXceiver: Got exception while serving block blk_-1608999687919862906 to /10.251.91.84\n"
        "081109 203520 145 ERROR dfs.DataNode$DataXceiver: Serving block blk_-1608999687919862906 to /10.251.91.84 failed\n"
    ).encode("utf-8")

    # Ingest file stream
    data = {"source": "hdfs", "file": (io.BytesIO(sample_hdfs_content), "sample_hdfs.log")}
    res_ingest = client.post("/api/ingest/file", data=data, content_type="multipart/form-data")
    assert res_ingest.status_code == 200
    assert res_ingest.get_json()["lines_queued"] == 3

    # Drain queue into parser (simulating background consumer)
    while not tailer.log_queue.empty():
        source, line = tailer.log_queue.get()
        parser.parse_line(line, declared_source=source)

    # Verify dashboard reflects persisted state
    res_stats = client.get("/api/stats")
    stats = res_stats.get_json()
    assert stats["total_events"] == 3
    assert stats["hdfs_events"] == 3
    assert stats["errors"] == 2  # 1 WARN + 1 ERROR

    # Verify events listing API contains parsed records
    res_events = client.get("/api/events?source=hdfs")
    evs = res_events.get_json()["events"]
    assert len(evs) == 3
    assert any("blk_-1608999687919862906" in e["raw_message"] for e in evs)


# ---------------------------------------------------------------------------
# 14. Error Handling and Boundary Conditions
# ---------------------------------------------------------------------------

def test_error_handling_and_invalid_inputs(client):
    """Verify robust error responses for missing parameters, bad credentials, and non-existent resources."""
    # 1. Missing file parameter
    res = client.post("/api/ingest/file", data={})
    assert res.status_code == 400

    # 2. Login with missing username or password
    assert client.post("/api/login", json={"username": ""}).status_code == 400
    assert client.post("/api/login", json={"password": ""}).status_code == 400

    # 3. Login with bad credentials
    res_bad = client.post("/api/login", json={"username": "admin", "password": "wrongpassword"})
    assert res_bad.status_code == 401

    # 4. Live tail start missing file_path
    client.post("/api/login", json={"username": "admin", "password": "adminpassword"})
    res_lp = client.post("/api/ingest/live/start", json={"source": "hdfs"})
    assert res_lp.status_code == 400

    # 5. Live tail stop on inactive source returns 404
    res_stop = client.post("/api/ingest/live/stop", json={"source": "non_existent_source"})
    assert res_stop.status_code == 404
