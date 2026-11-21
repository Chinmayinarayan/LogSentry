# LogSentry — Multi-Threaded Real-Time Log Analysis & Alerting System

**LogSentry** is a real-time, multi-threaded log analysis and alerting system built strictly on deterministic pre-compiled regex classification and time-based sliding window anomaly detection (no ML/probabilistic models).

It ingests, classifies, persists, and surfaces anomalies from two log sources:
1. **HDFS Loghub** (distributed storage block events)
2. **NASA-HTTP** Common Log Format (Kennedy Space Center web server access logs)

---

## Architecture Overview (4-Engine System)

- **ENGINE 1: E1 WATCH (`watch/tailer.py` / `watch.py`)**
  - Thread-per-source tailer with zero dropped lines guarantee under burst load (`queue.Queue` maxsize=10000 with backpressure).
  - Supports Replay Mode, Live Tailing Mode (`tail -f`), and File Upload Mode (with automatic `.zip` archive extraction).

- **ENGINE 2: E2 PARSE (`parse/parser.py` / `parse.py`)**
  - Pre-compiled regex patterns for HDFS Loghub and NASA-HTTP CLF formats.
  - Strict format validation: Non-matching, malformed, binary (e.g. `.zip`/`.jpg`), or unauthorized-format lines are quarantined into the `rejected_lines` table (never defaulted or guessed).
  - Sliding-window anomaly detection (`collections.deque`) with configurable Window ($W$) and Threshold ($T$) per source independently.

- **ENGINE 3: E3 VAULT (`vault/db.py` / `vault.py`)**
  - SQLite persistent database (`vault/logsentry.db`) using single-writer lock pattern.
  - Maintains 6 tables: `events`, `alerts`, `users`, `config`, `history`, `rejected_lines` with indexes.
  - Complete audit trail logging in `history` for alert resolutions and ADMIN threshold updates.

- **ENGINE 4: E4 SIGNAL (`signal_app.py` / `app.py` + `signal/templates/dashboard.html`)**
  - Flask RESTful API with server-side Role-Based Access Control (RBAC): `ADMIN`, `OPERATOR`, `VIEWER`.
  - Single-Page SOC Dashboard featuring real-time Chart.js metrics, active alert management with audit history, rejected lines log viewer, and live threshold controls.

---

## Quick Start

### 1. Install Dependencies
```bash
py -m pip install -r requirements.txt
```

### 2. Run the Application
```bash
py app.py
```
Open your browser at `http://localhost:5050`.

### 3. Run Validation & Accuracy Harness
```bash
py validation/evaluate_accuracy.py --log validation/fixtures/synthetic_hdfs_style.log --labels validation/fixtures/synthetic_anomaly_label.csv --json-out validation/results_synthetic.json
```

### 4. Run Test Suite
```bash
py -m pytest -v
```

---

## Live Tailing Setup Notes

### NASA-HTTP Source (Apache / Nginx Access Log)
1. Point live tailing at your local server's access log path (e.g., `/var/log/apache2/access.log` or `C:\nginx\logs\access.log`).
2. Submit request via dashboard UI or API:
   ```bash
   curl -X POST http://localhost:5050/api/ingest/live/start -H "Content-Type: application/json" -d "{\"source\": \"nasa_http\", \"file_path\": \"C:/nginx/logs/access.log\"}"
   ```

### HDFS Source (Single-Node Pseudo-Distributed Hadoop/HDFS)
1. Point live tailing at your local HDFS datanode log file:
   ```bash
   curl -X POST http://localhost:5050/api/ingest/live/start -H "Content-Type: application/json" -d "{\"source\": \"hdfs\", \"file_path\": \"/usr/local/hadoop/logs/hadoop-hdfs-datanode.log\"}"
   ```
2. Generate block operations using HDFS CLI (`hdfs dfs -put`, `hdfs dfs -rm`) to trigger log appends.

---

## Pre-seeded Auth Credentials

- **Admin**: `admin` / `adminpassword` (Full rights: W/T threshold config, user management)
- **Operator**: `operator` / `operatorpassword` (View streams, start/stop tailing, resolve alerts)
- **Viewer**: `viewer` / `viewerpassword` (Read-only access)
