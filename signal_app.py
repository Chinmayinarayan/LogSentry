"""Engine 4: E4 SIGNAL — Flask RESTful API server with RBAC, Live Tailing Ingestion, Audit Logging, and Dashboard."""

import functools
import os
import sys
import threading
from flask import Flask, jsonify, render_template, request, session
from werkzeug.security import check_password_hash

sys.path.insert(0, os.path.dirname(__file__))

from parse import parser
from vault import db
from watch import tailer

app = Flask(
    __name__,
    template_folder="signal/templates",
    static_folder="signal/static",
)
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024  # 500MB file upload limit
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.secret_key = os.urandom(24)

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
os.makedirs(DATA_DIR, exist_ok=True)


# --- QUEUE CONSUMER THREAD ---

def process_queue():
    """Continuous background consumer pulling lines from log_queue and feeding E2 Parser."""
    while True:
        try:
            item = tailer.log_queue.get()
            if item is None:
                break
            source, line = item
            parser.parse_line(line, declared_source=source)
            tailer.log_queue.task_done()
        except Exception as exc:
            print(f"[process_queue] error: {exc}")


_consumer_thread = None


def start_consumer():
    global _consumer_thread
    if _consumer_thread is None or not _consumer_thread.is_alive():
        _consumer_thread = threading.Thread(target=process_queue, name="queue-consumer", daemon=True)
        _consumer_thread.start()


# --- RBAC DECORATOR & AUTH HELPERS ---

def get_current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return db.get_user_by_id(user_id)


def require_role(*allowed_roles):
    """Server-side RBAC decorator for API endpoints."""
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            user = get_current_user()
            if not user:
                return jsonify({"error": "Unauthorized. Please log in first."}), 401
            if user["role"] not in allowed_roles:
                return jsonify({
                    "error": f"Forbidden. Role '{user['role']}' is not authorized to access this resource."
                }), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# --- AUTH ENDPOINTS ---

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or request.form
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    user = db.get_user_by_username(username)
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Invalid credentials"}), 401

    session["user_id"] = user["user_id"]
    session["username"] = user["username"]
    session["role"] = user["role"]

    return jsonify({
        "status": "success",
        "user": {
            "user_id": user["user_id"],
            "username": user["username"],
            "role": user["role"],
        }
    })


@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"status": "success", "message": "Logged out"})


@app.route("/api/me", methods=["GET"])
def api_me():
    user = get_current_user()
    if not user:
        return jsonify({"authenticated": False}), 200
    return jsonify({
        "authenticated": True,
        "user": {
            "user_id": user["user_id"],
            "username": user["username"],
            "role": user["role"],
        }
    })


# --- DASHBOARD UI ROUTE ---

@app.route("/")
def dashboard():
    return render_template("dashboard.html")


# --- EVENTS & ALERTS ENDPOINTS ---

@app.route("/api/events", methods=["GET"])
def api_events():
    page = request.args.get("page", 1, type=int)
    limit = request.args.get("limit", 50, type=int)
    source = request.args.get("source", None, type=str)
    level = request.args.get("level", None, type=str) or request.args.get("severity", None, type=str)
    start_time = request.args.get("start_time", None, type=str)
    end_time = request.args.get("end_time", None, type=str)

    if page < 1:
        page = 1
    if limit < 1 or limit > 500:
        limit = 50

    if level and level.upper() in ("ALL", "*", ""):
        level = None
    elif level:
        level = level.strip().upper()

    if source and source.upper() in ("ALL", "*", ""):
        source = None
    elif source:
        source = source.strip().lower().replace("-", "_")

    offset = (page - 1) * limit
    res = db.get_events(
        limit=limit,
        offset=offset,
        source=source,
        level=level,
        start_time=start_time,
        end_time=end_time,
    )
    res["page"] = page
    return jsonify(res)


@app.route("/api/alerts", methods=["GET"])
def api_alerts():
    limit = request.args.get("limit", 50, type=int)
    status = request.args.get("status", None, type=str)
    if status and status.upper() in ("ALL", "*", ""):
        status = None
    elif status:
        status = status.strip().upper()
    alerts = db.get_alerts(limit=limit, status=status)
    return jsonify({"alerts": alerts, "count": len(alerts)})


@app.route("/api/alerts/<int:alert_id>/resolve", methods=["POST"])
@require_role("ADMIN", "OPERATOR")
def api_resolve_alert(alert_id):
    user = get_current_user()
    success = db.resolve_alert(alert_id, user_id=user["user_id"])
    if not success:
        return jsonify({"error": "Alert not found"}), 404
    return jsonify({"status": "success", "message": f"Alert #{alert_id} resolved by {user['username']}"})


@app.route("/api/alerts/<int:alert_id>/history", methods=["GET"])
def api_alert_history(alert_id):
    history_records = db.get_alert_history(alert_id)
    return jsonify({"history": history_records})


# --- INGESTION ENDPOINTS ---

@app.route("/api/ingest/file", methods=["POST"])
@app.route("/api/upload", methods=["POST"])
def api_ingest_file():
    if "file" not in request.files:
        return jsonify({"error": "No file parameter in request"}), 400

    uploaded = request.files["file"]
    if not uploaded or not uploaded.filename:
        return jsonify({"error": "No file selected"}), 400

    source = request.form.get("source") or request.args.get("source") or "hdfs"
    filename = os.path.basename(uploaded.filename)
    raw_bytes = uploaded.read()

    result = tailer.ingest_file_stream(source, raw_bytes, filename=filename)
    return jsonify(result)


@app.route("/api/ingest/live/start", methods=["POST"])
@require_role("ADMIN", "OPERATOR")
def api_live_start():
    data = request.get_json(silent=True) or request.form
    source = (data.get("source") or "hdfs").strip()
    file_path = (data.get("file_path") or "").strip()

    if not file_path:
        return jsonify({"error": "file_path is required"}), 400

    tailer.start_watcher(source, file_path)
    return jsonify({"status": "success", "message": f"Started live tailing source '{source}' at '{file_path}'"})


@app.route("/api/ingest/live/stop", methods=["POST"])
@require_role("ADMIN", "OPERATOR")
def api_live_stop():
    data = request.get_json(silent=True) or request.form
    source = (data.get("source") or "").strip()

    if not source:
        return jsonify({"error": "source is required"}), 400

    stopped = tailer.stop_watcher(source)
    if stopped:
        return jsonify({"status": "success", "message": f"Stopped live tailing for source '{source}'"})
    return jsonify({"error": f"No active watcher found for source '{source}'"}), 404


@app.route("/api/rejected", methods=["GET"])
def api_rejected():
    limit = request.args.get("limit", 100, type=int)
    rejected_rows = db.get_rejected_lines(limit=limit)
    return jsonify({"rejected": rejected_rows, "count": len(rejected_rows)})


# --- CONFIGURATION ENDPOINTS (ADMIN ONLY FOR WRITES) ---

@app.route("/api/config", methods=["GET"])
def api_get_config():
    parser.refresh_config_cache()
    return jsonify({
        "config": db.get_all_configs(),
        "live_cache": parser.get_config_cache(),
    })


@app.route("/api/config", methods=["POST"])
@require_role("ADMIN")
def api_update_config():
    user = get_current_user()
    data = request.get_json(silent=True) or request.form
    if not data:
        return jsonify({"error": "No configuration parameters provided"}), 400

    updated_keys = []
    valid_keys = {"hdfs_window", "hdfs_threshold", "nasa_http_window", "nasa_http_threshold"}
    for key, val in data.items():
        if key in valid_keys:
            try:
                val_int = int(val)
                if val_int <= 0:
                    return jsonify({"error": f"Value for key '{key}' must be a positive integer"}), 400
                db.update_config(key, str(val_int), user_id=user["user_id"])
                parser.set_config_value(key, val_int)
                updated_keys.append(key)
            except (ValueError, TypeError):
                return jsonify({"error": f"Invalid integer value for key '{key}'"}), 400

    if not updated_keys:
        return jsonify({"error": "No valid configuration keys provided"}), 400

    parser.refresh_config_cache()
    return jsonify({
        "status": "success",
        "message": f"Updated config keys: {', '.join(updated_keys)}",
        "updated_keys": updated_keys,
    })


@app.route("/api/config/history", methods=["GET"])
@require_role("ADMIN")
def api_config_history():
    history_records = db.get_config_history()
    return jsonify({"history": history_records})


# --- USER MANAGEMENT ENDPOINTS (ADMIN ONLY) ---

@app.route("/api/users", methods=["GET"])
@require_role("ADMIN")
def api_get_users():
    return jsonify({"users": db.get_all_users()})


@app.route("/api/users", methods=["POST"])
@require_role("ADMIN")
def api_create_user():
    admin_user = get_current_user()
    data = request.get_json(silent=True) or request.form
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    role = (data.get("role") or "").strip().upper()

    if not username or not role:
        return jsonify({"error": "username and role are required"}), 400

    try:
        user_id = db.create_or_update_user(username, password, role, admin_id=admin_user["user_id"])
        return jsonify({"status": "success", "user_id": user_id, "username": username, "role": role})
    except ValueError as err:
        return jsonify({"error": str(err)}), 400


# --- SYSTEM STATS & METRICS ---

@app.route("/api/stats", methods=["GET"])
def api_stats():
    db_stats = db.get_event_stats()
    runtime = tailer.get_metrics()
    alert_buffer = parser.get_alert_buffer_metrics()
    return jsonify({
        "total_events": db_stats["total_events"],
        "hdfs_events": db_stats.get("hdfs_events", 0),
        "nasa_events": db_stats.get("nasa_events", 0),
        "errors": db_stats["errors"],
        "warn_count": db_stats.get("warn_count", 0),
        "error_count": db_stats.get("error_count", 0),
        "active_alerts": db_stats["active_alerts"],
        "resolved_alerts": db_stats.get("resolved_alerts", 0),
        "rejected_lines": db_stats["rejected_lines"],
        "active_threads": runtime["active_threads"],
        "queue_size": runtime["queue_size"],
        "events_processed": runtime["events_processed"],
        "alert_buffer_metrics": alert_buffer,
    })


@app.route("/api/metrics/pending-alerts", methods=["GET"])
def api_pending_alerts():
    return jsonify(parser.get_alert_buffer_metrics())


@app.route("/api/metrics/timeseries", methods=["GET"])
def api_metrics_timeseries():
    return jsonify(db.get_timeseries())


@app.route("/api/reset", methods=["POST"])
@require_role("ADMIN")
def api_reset():
    db.reset_db()
    parser.reset_sliding_windows()
    tailer.reset_metrics()
    return jsonify({"status": "success", "message": "Database and runtime metrics cleared"})


# --- DEMO / SIMULATION ENDPOINT ---

@app.route("/api/simulate-auth-failure", methods=["POST", "GET"])
@app.route("/simulate", methods=["POST", "GET"])
def api_simulate():
    """Push 5 fake HDFS exception events to trigger sliding window alert."""
    fake_lines = [
        "081109 203518 143 WARN dfs.DataNode$DataXceiver: Got exception while serving block blk_-1608999687919862906 to /10.251.91.84",
        "081109 203519 144 ERROR dfs.DataNode$DataXceiver: Got exception while serving block blk_-1608999687919862907 to /10.251.91.85",
        "081109 203520 145 WARN dfs.DataNode$DataXceiver: Got exception while serving block blk_-1608999687919862908 to /10.251.91.86",
        "081109 203521 146 ERROR dfs.DataNode$DataXceiver: Got exception while serving block blk_-1608999687919862909 to /10.251.91.87",
        "081109 203522 147 WARN dfs.DataNode$DataXceiver: Got exception while serving block blk_-1608999687919862910 to /10.251.91.88",
    ]
    for line in fake_lines:
        tailer.log_queue.put(("hdfs", line))
    return jsonify({"status": "ok", "queued": len(fake_lines), "message": "Queued 5 block exception events for HDFS burst alert"})


if __name__ == "__main__":
    db.init_db()
    parser.refresh_config_cache()
    start_consumer()
    print("LogSentry E4 Signal Web Server running on http://localhost:5050")
    app.run(host="0.0.0.0", port=5050, debug=False, use_reloader=False)
