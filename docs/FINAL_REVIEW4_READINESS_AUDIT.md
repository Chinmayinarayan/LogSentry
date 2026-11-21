# LogSentry — Final Code Audit & Review-4 Readiness Verification Report

**Project:** LogSentry — Multi-Threaded Real-Time Log Analysis & Alerting System  
**Team:** Team 06 | **Theme:** Theme 05  
**Review Stage:** Review-4 Final Evaluation Sign-Off
**Audit Date:** November 21, 2026
**Auditor:** Antigravity Automated Verification & System Audit Harness
**Platform / Runtime:** Windows 11, Python 3.13.5 (64-bit), pytest 9.1.1  
**Git Baseline Commit:** `6e406d69f9770c591230b0de88b426993d9be569`  
**Overall Readiness Verdict:** **READY AFTER MANUAL DEMONSTRATION CHECK**

---

## 1. Executive Summary

This audit report provides a rigorous, evidence-based verification of the LogSentry system across all four core engines:
- **E1 WATCH:** File ingestion, tailing, archive extraction, and bounded queue backpressure.
- **E2 PARSE:** Multi-format log regex extraction, sliding-window anomaly detection, and per-source FIFO persistence serialization.
- **E3 VAULT:** Persistent SQLite storage, WAL mode concurrency, atomic state mutations, and append-only application audit ledger.
- **E4 SIGNAL:** Flask REST API, role-based access control (RBAC), and dynamic auto-refresh monitoring dashboard.

Every requirement and claim has been verified against actual source code execution and automated test suites under Python 3.13.5. No claims are based on assumptions, stub endpoints, or hypothetical behaviors.

### Summary Metrics
| Metric | Verified Value | Evidence |
|---|---|---|
| **Total Test Suites** | 7 test files | `tests/` directory |
| **Total Test Count** | **89 passed, 0 failed, 0 skipped** | `pytest -v` run (30.38s) |
| **Code Coverage** | All E1, E2, E3, E4 critical paths | Unit, property, concurrency, and security tests |
| **Live Demo Workflow** | **10/10 Steps Verified Live** | Executed against isolated runtime DB |
| **Dashboard Polling** | **3 seconds (3,000 ms)** | Verified in `signal/templates/dashboard.html` |
| **Git Working Tree** | Clean / Audited | All tests passing on clean tree |

---

## 2. System Architecture & Modular Responsibilities

LogSentry is architected as an event-driven, producer-consumer pipeline with strict separation of concerns across four engines.

```
+---------------------------------------------------------------------------------------------+
|                                    LOGSENTRY PIPELINE                                       |
+---------------------------------------------------------------------------------------------+

  [ Log Sources ]
   * HDFS Loghub / ISO
   * NASA-HTTP CLF
   * ZIP Archives
         |
         v
+------------------+         Bounded Queue (Capacity: 10,000)
|    E1: WATCH     | ----------------------------------------------+
| (Tailer/Ingest)  | [Backpressure: Put blocks when queue is full]  |
+------------------+                                               |
                                                                   v
                                                         +------------------+
                                                         |    E2: PARSE     |
                                                         | (Worker Threads) |
                                                         +------------------+
                                                            |          |
                                          Malformed/Garbage |          | Valid Record
                                                            v          v
                                                   +------------+  +----------------------+
                                                   | Quarantine |  | Sliding-Window Burst |
                                                   | Storage    |  | Detection (Per Source|
                                                   +------------+  +----------------------+
                                                                               |
                                                              Threshold Exceeded
                                                              (FIFO Serializer)
                                                                               |
                                                                               v
                                                         +------------------------------------+
                                                         |             E3: VAULT              |
                                                         |   * SQLite Write-Ahead Log (WAL)   |
                                                         |   * Global DB Write Serializer     |
                                                         |   * Atomic Audit Ledger (History)  |
                                                         +------------------------------------+
                                                                        ^
                                                                        | REST / Queries
                                                         +------------------------------------+
                                                         |             E4: SIGNAL             |
                                                         |   * Flask Web REST API             |
                                                         |   * Server-Side RBAC Enforcement   |
                                                         |   * 3s AJAX Polling UI Dashboard   |
                                                         +------------------------------------+
```

### Modular Engine Specifications

#### E1: WATCH (`watch/tailer.py`)
- **Ingestion Mechanisms:** Incremental line streaming (`read_file_incremental`), live directory tailing (`tail_file`), and safe ZIP archive extraction.
- **Safety & Sandboxing:** Validates archive entry paths against Directory Traversal (`..` and absolute paths) before decompression. Quarantines invalid archives immediately.
- **Backpressure Mechanism:** Implements a thread-safe `queue.Queue(maxsize=10000)`. When full, producer threads block safely until parser threads consume items, guaranteeing bounded process memory.

#### E2: PARSE (`parse/parser.py`)
- **Multi-Format Extraction:** High-performance precompiled regular expressions parse HDFS Loghub (`date time pid level component: content`), HDFS ISO-8601 (`YYYY-MM-DDTHH:MM:SS`), and NASA-HTTP Common Log Format (CLF: `host - - [timestamp] "METHOD route HTTP/1.0" status bytes`).
- **Quarantine Engine:** Binary data, null bytes (`\x00`), truncated lines, and schema-mismatched records are safely diverted to the `quarantine` table without terminating parser workers.
- **Sliding-Window Anomaly Detection:** Independent `collections.deque` buffers for HDFS and NASA sources. Sliding window calculates event rates over time ($\Delta t \le \text{window\_seconds}$). When threshold is crossed, an anomaly alert is triggered.
- **Alert Persistence FIFO Serializer:** Per-source serialization lock (`_flush_locks`) ensures that when database connectivity is slow or retried, alerts arrive in SQLite strictly in FIFO arrival order without dropping or reordering. Bounded pending buffer (1,000 items) tracks dropped alerts through observable counters.

#### E3: VAULT (`vault/db.py`, `vault/schema.sql`)
- **Database Architecture:** Embedded SQLite 3 database operating in **Write-Ahead Logging (WAL)** mode with `PRAGMA synchronous = NORMAL`.
- **Write Serialization:** Multi-threaded writes are serialized via a dedicated `threading.Lock()` (`_DB_WRITE_LOCK`), eliminating `sqlite3.OperationalError: database is locked`.
- **Append-Only Application Audit Trail:** Every state mutation (alert resolution, configuration threshold update, user password update) executes within an atomic database transaction alongside an insert into the `history` table. If audit recording fails, the entire transaction rolls back.
- **Data Integrity:** Foreign keys enabled (`PRAGMA foreign_keys = ON`), SHA-256 password hashing with salt, and parameterized SQL queries preventing SQL injection across all interfaces.

#### E4: SIGNAL (`signal_app.py`, `signal/templates/dashboard.html`)
- **Web Application:** Lightweight Flask application serving a responsive dark-mode monitoring dashboard and JSON REST API.
- **RBAC Server-Side Enforcement:** `@require_role` decorator inspects session identity on every sensitive endpoint. Unauthenticated requests receive HTTP 401; unauthorized roles receive HTTP 403.
- **Monitoring & Observability:** Real-time metrics endpoints for pending alert buffers, ingested event rates, active alerts, quarantine counts, and timeseries histogram data. Polling dashboard refreshes automatically every 3 seconds (3,000 ms).

---

## 3. Verified Endpoint Access & RBAC Security Matrix

The LogSentry E4 SIGNAL web service exposes 24 HTTP routes. Access permissions fall into two deliberate design categories:

1. **Protected Endpoints (Authentication & Role Required):** State mutations, user provisioning, live tail thread control, and administrative reset. Server-side `@require_role` decorator inspects the session cookie. Unauthenticated requests receive HTTP 401 Unauthorized; unauthorized roles receive HTTP 403 Forbidden.
2. **Public Endpoints (Unauthenticated Access Intentional):** Read-only metrics, active alert summaries, log queries, headless ingestion upload, and demonstration simulation endpoints. These allow SOC wallboard monitors to render without an interactive user login and allow automated log shipper agents (e.g. curl, filebeat) to push logs without interactive session cookies.

| Endpoint / Route | HTTP Method | Auth Required | Permitted Roles | Server-Side Enforcement | Unauthorized Status | Access Model Justification & Test Evidence |
|---|---|---|---|---|---|---|
| `/` | `GET` | No | Public / Any | None | N/A (200 OK) | Serves SPA Dashboard HTML; `test_dashboard_route_and_authentication` |
| `/api/login` | `POST` | No | Public | Credential check + hash verify | 400 (Missing), 401 (Invalid) | Authentication entry point; `test_dashboard_route_and_authentication` |
| `/api/logout` | `POST` | No | Public | Session clearance | N/A (200 OK) | Session termination; `test_dashboard_route_and_authentication` |
| `/api/me` | `GET` | No | Public | Returns current auth state | N/A (200 OK) | Returns `{"authenticated": false}` or user info; `test_rest_api_responses_and_status_codes` |
| `/api/events` | `GET` | No | Public | Query limits & pagination | N/A (200 OK) | Intentional: Read-only wallboard event stream; `test_event_filtering_and_pagination` |
| `/api/alerts` | `GET` | No | Public | Query filters | N/A (200 OK) | Intentional: Read-only wallboard alert stream; `test_alert_filtering` |
| `/api/alerts/<id>/resolve` | `POST` | **Yes** | `ADMIN`, `OPERATOR` | `@require_role("ADMIN", "OPERATOR")` | 401 Unauth, 403 Forbidden | State mutation; `test_operator_permissions`, `test_viewer_read_only_restrictions` |
| `/api/alerts/<id>/history` | `GET` | No | Public | History lookup | N/A (200 OK) | Intentional: Read-only audit transparency; `test_alert_resolution_and_audit_history` |
| `/api/ingest/file` | `POST` | No | Public / Shippers | Container & size validation | 400 (Bad file / empty) | Intentional: Headless log shipper upload; `test_end_to_end_ingestion_to_dashboard_integration` |
| `/api/upload` | `POST` | No | Public / Shippers | Alias to `/api/ingest/file` | 400 (Bad file / empty) | Backward compatible upload route; `test_error_handling_and_invalid_inputs` |
| `/api/ingest/live/start` | `POST` | **Yes** | `ADMIN`, `OPERATOR` | `@require_role("ADMIN", "OPERATOR")` | 401 Unauth, 403 Forbidden | Process thread control; `test_unauthorized_access_rejection` |
| `/api/ingest/live/stop` | `POST` | **Yes** | `ADMIN`, `OPERATOR` | `@require_role("ADMIN", "OPERATOR")` | 401 Unauth, 403 Forbidden | Process thread control; `test_unauthorized_access_rejection` |
| `/api/rejected` | `GET` | No | Public | Preview sanitize & limit | N/A (200 OK) | Intentional: Read-only quarantine preview; `test_rest_api_responses_and_status_codes` |
| `/api/config` | `GET` | No | Public | Config lookup | N/A (200 OK) | Intentional: Dashboard fetches threshold sliders; `test_viewer_read_only_restrictions` |
| `/api/config` | `POST` | **Yes** | `ADMIN` | `@require_role("ADMIN")` | 401 Unauth, 403 Forbidden | System reconfiguration; `test_admin_permissions`, `test_operator_permissions` |
| `/api/config/history` | `GET` | **Yes** | `ADMIN` | `@require_role("ADMIN")` | 401 Unauth, 403 Forbidden | Audit trail inspection; `test_admin_permissions`, `test_operator_permissions` |
| `/api/users` | `GET` | **Yes** | `ADMIN` | `@require_role("ADMIN")` | 401 Unauth, 403 Forbidden | User credential management; `test_admin_permissions` |
| `/api/users` | `POST` | **Yes** | `ADMIN` | `@require_role("ADMIN")` | 401 Unauth, 403 Forbidden | User provisioning; `test_admin_permissions` |
| `/api/stats` | `GET` | No | Public | Aggregate query | N/A (200 OK) | Intentional: 3s dashboard polling counters; `test_rest_api_responses_and_status_codes` |
| `/api/metrics/pending-alerts` | `GET` | No | Public | Buffer status lookup | N/A (200 OK) | Intentional: 3s pipeline health polling; `test_pending_alert_buffer_metrics_api` |
| `/api/metrics/timeseries` | `GET` | No | Public | Histogram aggregation | N/A (200 OK) | Intentional: 3s Chart.js polling; `test_rest_api_responses_and_status_codes` |
| `/api/reset` | `POST` | **Yes** | `ADMIN` | `@require_role("ADMIN")` | 401 Unauth, 403 Forbidden | Database reset; `test_admin_permissions`, `test_unauthorized_access_rejection` |
| `/api/simulate-auth-failure` | `POST`/`GET` | No | Public | Queue push | N/A (200 OK) | Intentional: Demo/evaluation simulation generator; `test_end_to_end_ingestion_to_dashboard_integration` |
| `/simulate` | `POST`/`GET` | No | Public | Alias to simulator | N/A (200 OK) | Demo/evaluation shortcut; `test_dashboard_route_and_authentication` |

---

## 4. Dashboard Polling Implementation Verification

- **Actual Code Implementation:**
  In [`signal/templates/dashboard.html`](file:///c:/Users/DELL/OneDrive/ドキュメント/Desktop/Mini%20Project/logsentry-project-master/signal/templates/dashboard.html#L909-L913):
  ```javascript
  setInterval(() => {
    fetchStats();
    fetchChart();
    fetchAlerts();
  }, 3000);
  ```
- **UI Labels:**
  - Line 122: `<span class="text-[11px] text-slate-400">Live Polling (every 3s)</span>`
  - Line 166: `<span class="text-xs text-slate-400">Live Polling (3s refresh)</span>`
- **Verification Result:** The actual polling interval in code and UI labels has consistently been **3 seconds (3,000 ms)**. Any earlier documentation referencing "5 seconds" has been corrected to reflect the true 3-second polling interval.

---

## 5. Reconciled Test Counts & Distribution

The test suite consists of 89 tests across 7 test files. Earlier summaries reported minor distribution variance across two files; this section provides the definitive reconciliation.

### Reconciled File-by-File Breakdown
| Test File | Verified Items | Focus & Added Coverage |
|---|---|---|
| `tests/test_logsentry.py` | 14 passed | Full-pipeline integration, RBAC, live tailing, validation harness |
| `tests/test_parse.py` | 9 passed | Regex extraction, sliding-window expiration, queue consumption |
| `tests/test_phase2_db_models.py` | 7 passed | Schema synchronization, foreign keys, WAL mode, dataclasses |
| `tests/test_phase4_review.py` | 21 passed | Alert persistence FIFO ordering, retry semantics, bounded queues |
| `tests/test_phase5_vault.py` | 18 passed | E3 database transactions, atomic audit rollback, concurrency |
| `tests/test_phase6_signal.py` | 14 passed | E4 REST API, RBAC server enforcement, config reload, metrics |
| `tests/test_watch.py` | 6 passed | Incremental streaming, safe ZIP extraction, backpressure |
| **TOTAL** | **89 passed** | **Completed in 30.38 seconds** |

### Test Distribution Explanation
1. **`test_phase5_vault.py` (18 tests):**
   - In commit `4760729` (initial Phase 5), 14 tests were created.
   - In commit `d4392af` (E3 audit fix), 4 additional tests were added:
     - `test_transaction_atomicity_audit_failure_rolls_back_primary_operation`
     - `test_concurrent_readers_and_writers_wal_mode`
     - `test_user_password_update_audit_trail`
     - `test_no_recursive_lock_deadlock_across_vault_operations`
   - Total in `test_phase5_vault.py` = **18 tests**.
2. **`test_watch.py` (6 tests):**
   - Contains exactly 6 tests: `test_bounded_queue_capacity`, `test_queue_backpressure_producer_blocks`, `test_concurrent_watchers_thread_per_source`, `test_zip_extraction_and_ingestion`, `test_invalid_zip_container_quarantined`, `test_large_file_streaming_incremental`.
   - Total in `test_watch.py` = **6 tests**.
3. **Reconciliation:** An earlier tabular report inverted the counts (writing 17 and 7 instead of 18 and 6, both summing to 24). The collected and verified test count is **89 tests**, with zero tests added, modified, or deleted merely to match arbitrary counts.

---

## 6. Audit of Reliability Claims & Known Architectural Boundaries

LogSentry is designed for robust local edge/workstation SOC deployment. To preserve academic integrity, unsupported claims are explicitly eliminated, and operational boundaries are documented:

1. **Ingestion Queue Bounds:**
   - The queue between E1 WATCH and E2 PARSE is a thread-safe in-memory queue (`queue.Queue(maxsize=10000)`).
   - If the queue fills to 10,000 items, producer threads block on `.put()` applying backpressure.
   - Because the queue is in process memory, unconsumed in-flight items will be lost if the process crashes or power fails.
2. **Pending Alert Buffer Bounds & Dropped Alerts:**
   - Pending alert buffers in E2 PARSE are in-memory deques bounded at 1,000 alerts per source (`collections.deque(maxlen=1000)`).
   - If the database write path fails repeatedly and the buffer saturates, excess alerts are dropped and an observable counter (`dropped_alerts`) is incremented and exposed via `/api/metrics/pending-alerts`.
   - The system **does not guarantee zero data loss** under sustained database outage or abrupt process termination.
3. **Append-Only Application Audit Trail vs Cryptographic Immutability:**
   - The `history` table functions as an **append-only application ledger**. The application code only performs `INSERT` operations and never modifies or deletes existing history entries.
   - This is enforced at the application code and transaction layer; it is not a hardware WORM (Write Once Read Many) or cryptographic blockchain ledger.
4. **Dashboard Polling vs Push Notifications:**
   - Dashboard updates rely on asynchronous HTTP polling (every 3 seconds), not WebSockets or Server-Sent Events (SSE).
   - Visual updates have an upper-bound display latency of 3 seconds.
5. **Process Concurrency Scope:**
   - Concurrency synchronization (`_DB_WRITE_LOCK`, `_window_locks`, `_flush_locks`) utilizes Python `threading.Lock` primitives.
   - The system is designed for a single coordinated server process (`python app.py`). Running behind a multi-process WSGI server (such as multi-worker Gunicorn) without an external broker (Redis/Celery) would isolate in-memory sliding windows.

---

## 7. End-to-End Live Demonstration Workflow Verification

An automated live demonstration workflow was executed against an isolated runtime database to prove end-to-end functionality across all four engines without modifying production data.

### 10-Step Verification Trace
1. **Dashboard Route:** `GET /` responded with HTTP 200 OK (HTML template rendered).
2. **Viewer Authentication:** Logged in as `viewer` / `viewerpassword`. Session verified with role `VIEWER`.
3. **RBAC Restriction Check:** Viewer attempted `POST /api/config` with threshold change. Server responded with **HTTP 403 Forbidden** (write blocked).
4. **Log Ingestion:** Streamed 5 valid HDFS log lines via `POST /api/ingest/file`. Verified successful staging.
5. **Anomaly Burst Simulation:** Triggered 6 rapid authentication failures via `POST /api/simulate-auth-failure`. E1 ingested to queue; E2 consumed and evaluated sliding window.
6. **Alert Generation:** Verified stats via `GET /api/stats`: Total Events $\ge 7$, Active Alerts $\ge 1$.
7. **Operator Alert Resolution:** Logged in as `operator` / `operatorpassword`. Successfully resolved active alert via `POST /api/alerts/<id>/resolve` (HTTP 200 OK).
8. **Audit Trail Verification:** Queried `GET /api/alerts/<id>/history`. Confirmed audit event recorded with `changed_by_name == 'operator'`, timestamp, and previous state.
9. **Admin Dynamic Reconfiguration:** Logged in as `admin` / `adminpassword`. Updated `hdfs_threshold` from `5` to `8` via `POST /api/config`. Verified HTTP 200 OK and live E2 cache dynamically reloaded without restart.
10. **Buffer & System Metrics Check:** Queried `GET /api/metrics/pending-alerts`. Verified active pending counts (`0`), dropped counts (`0`), and healthy pipeline status.

---

## 8. Verified Predefined Credentials & Faculty Demonstration Script

### System Credentials
Three predefined accounts are seeded in `vault/schema.sql`:

| Username | Password | Role | Permitted Actions |
|---|---|---|---|
| `admin` | `adminpassword` | `ADMIN` | Full control: Config thresholds, user management, alert resolution, live tail, reset |
| `operator` | `operatorpassword` | `OPERATOR` | Operational control: Alert resolution, live tail start/stop, viewing all metrics/logs |
| `viewer` | `viewerpassword` | `VIEWER` | Read-only access: Viewing dashboard, events, alerts, metrics. All writes blocked (HTTP 403) |

### Demonstration Script (For Review-4 Presentation)

1. **Start the System:**
   ```powershell
   python app.py
   ```
   *System boots Flask server on `http://127.0.0.1:5000` (or `http://localhost:5050` when running `signal_app.py`) and initializes background consumer threads.*

2. **Step 1: Open Dashboard & Log In as Viewer**
   - Open browser to `http://127.0.0.1:5000`.
   - Click "Login", enter `viewer` / `viewerpassword`.
   - Notice the status pill shows "VIEWER (Read-Only)".
   - Attempt to modify threshold slider or resolve alert: Action is rejected with HTTP 403 error.

3. **Step 2: Log In as Operator & Resolve Alert**
   - Switch user to `operator` / `operatorpassword`.
   - Click "Simulate Anomaly Burst" button.
   - An alert appears in the Active Alerts table within 3 seconds.
   - Click "Resolve" on the alert and enter a resolution comment. Alert status updates to Resolved.
   - Click "Audit History" to demonstrate the append-only audit record showing `operator` resolved the alert.

4. **Step 3: Log In as Admin & Update Configuration**
   - Log in as `admin` / `adminpassword`.
   - Change HDFS Threshold from 5 to 8 and click "Save Config".
   - Show that the update succeeds and the change is recorded in the Audit Log with `admin` attribution.
   - Demonstrate that E2 parser cache dynamically applied the new threshold immediately.

---

## 9. Viva Voce & Core Concepts Guide for Team 06

### Q1: How does LogSentry prevent memory exhaustion when reading high-volume log files?
> **Answer:** LogSentry employs two memory boundaries:
> 1. Incremental line-by-line file streaming (`read_file_incremental`) reading chunks up to 64KB without loading multi-gigabyte files into RAM.
> 2. A bounded thread-safe `queue.Queue(maxsize=10000)` between E1 WATCH and E2 PARSE. When the queue reaches 10,000 items, the producer thread blocks on `.put()`, applying natural backpressure until consumer threads drain the queue.

### Q2: How does the sliding-window burst detection algorithm work?
> **Answer:** Each source maintains a `collections.deque` of epoch timestamps protected by an independent mutex (`_window_locks`). When a new error event arrives at timestamp $T$, all timestamps older than $T - \Delta t$ (where $\Delta t$ is the configured window in seconds) are popped from the left of the deque. If the remaining count plus the new event reaches or exceeds the threshold, an anomaly alert is triggered.

### Q3: Why does LogSentry have independent locks for HDFS and NASA sources?
> **Answer:** In high-throughput systems, lock contention creates throughput bottlenecks. By assigning dedicated locks (`_window_locks['hdfs']` vs `_window_locks['nasa']` and `_flush_locks['hdfs']` vs `_flush_locks['nasa']`), slow database persistence or high error volume in HDFS logs can never block, delay, or deadlock NASA HTTP log processing.

### Q4: How is FIFO ordering guaranteed when persisting alerts?
> **Answer:** Each source uses a dedicated `_flush_locks[source]` serializer and a bounded pending buffer. When an alert arrives, the serializer first attempts to flush any older pending alerts for that source. If older alerts remain unflushed due to transient database errors, the new alert is appended to the back of the pending buffer. This guarantees that new alerts never bypass older unpersisted alerts for the same source.

### Q5: What is SQLite WAL mode, and why did we enable it?
> **Answer:** Write-Ahead Logging (`PRAGMA journal_mode=WAL`) changes how SQLite handles transactions. Instead of modifying the database file directly via rollback journals, changes are appended to a separate `-wal` file. This allows readers to read from the main database file simultaneously while a writer writes to the WAL file, significantly increasing concurrency and throughput.

### Q6: How does LogSentry enforce database write thread-safety?
> **Answer:** Even with WAL mode, SQLite only allows one writer at a time. To prevent `sqlite3.OperationalError: database is locked` exceptions across multiple worker threads, all write operations in `vault/db.py` pass through a re-entrant `_DB_WRITE_LOCK` mutex.

### Q7: How does LogSentry ensure audit log atomicity?
> **Answer:** Every state modification (such as resolving an alert or updating a threshold) is executed inside a single SQLite transaction with `PRAGMA foreign_keys = ON`. Both the state update and the audit insertion into the `history` table must succeed together. If the audit insertion fails, Python's transaction context manager automatically issues a `ROLLBACK`, preventing untracked state mutations.

### Q8: How does server-side Role-Based Access Control (RBAC) work in LogSentry?
> **Answer:** Client-side UI controls (hiding buttons) are not trusted for security. Every privileged route is decorated with `@require_role("ADMIN", ...)` which inspects the cryptographic session cookie on the server. If unauthenticated, it returns HTTP 401; if authenticated as an unauthorized role (e.g. VIEWER attempting an update), it aborts with HTTP 403 Forbidden.

### Q9: How are directory traversal attacks prevented during ZIP ingestion?
> **Answer:** When decompressing ZIP archives in `extract_zip_safely`, LogSentry validates each `ZipInfo.filename`. It resolves the destination path using `os.path.commonpath` to ensure the target path strictly resides within the designated extraction directory, rejecting filenames containing `..` or leading slashes and quarantining the archive.

### Q10: How does configuration updating affect the running pipeline without a restart?
> **Answer:** When an Admin updates a threshold via `POST /api/config`, the route writes the new value atomically to the `config` table and calls `parser.reload_config()`. This reloads the in-memory thresholds cached by E2 PARSE under lock, applying new anomaly detection rules instantly to subsequent events.

---

## 10. Verification Sign-Off

- **Automated Verification:** **100% COMPLETE** (89/89 tests passing, clean working tree, consistent database schema, atomic transactions, RBAC enforcement).
- **Manual Verification Required:** A human team member must perform the interactive demonstration walkthrough before the evaluation panel (starting `python app.py` and demonstrating Viewer, Operator, and Admin interactions in the browser).
- **Final Verdict:** **READY AFTER MANUAL DEMONSTRATION CHECK**
