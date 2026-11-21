# LogSentry — Complete Technical Audit

**Project:** LogSentry — Multi-threaded Log Analysis & Alerting System (Theme 5)  
**Workspace root documented:** `logsentry/`  
**Audit scope:** Current on-disk implementation (source, schema, APIs, concurrency, UI)  
**Excluded from tree listing detail:** `venv/` (third-party virtualenv), `__pycache__/` (bytecode), binary SQLite pages inside `vault/logsentry.db` (schema documented separately)

---

## 1. FULL FILE TREE

```
logsentry/
├── .cursorrules                          # Cursor architecture rules for Theme 5 / 4-engine model
├── README.md                             # Original quick-start notes (partially outdated vs current APIs)
├── requirements.txt                      # Declared Python dependencies
├── seed.py                               # Legacy offline seed script (uses old APIs; not used by signal_app)
├── signal_app.py                         # Flask Web/Networks engine — routes, upload, queue consumer
├── TECHNICAL_AUDIT.md                    # This audit document (generated)
├── data/
│   ├── sample.log                        # Demo log tailed at startup as source "server1"
│   ├── test_logs.log                     # Additional sample/upload test log
│   └── upload_test.log                   # Copy/artifact from upload testing
├── parse/                                # DSA Engine package
│   ├── __init__.py                       # Package marker (empty)
│   ├── parser.py                         # Regex parse + sliding-window detection (live path)
│   └── rules.py                          # Legacy categorization helpers (not imported by live parser)
├── signal/
│   └── templates/
│       └── dashboard.html                # SOC dashboard UI + Chart.js + polling JS
├── vault/                                # DBMS Engine package
│   ├── __init__.py                       # Package marker (empty)
│   ├── db.py                             # SQLite helpers, schema init, queries
│   ├── logsentry.db                      # Runtime SQLite database file
│   └── schema.sql                        # Legacy schema snapshot (older alerts columns; superseded by init_db)
├── watch/                                # OS Engine package
│   ├── __init__.py                       # Package marker (empty)
│   └── tailer.py                         # Multithreaded file tailers + shared log_queue
└── venv/                                 # Local Python virtual environment (Flask install)
```

**Binary / generated (purpose only):**
- `vault/logsentry.db` — Persistent SQLite vault created/updated by `init_db()`.
- `venv/` — Isolated interpreter + installed packages (`flask`, etc.).

---

## 2. FULL SOURCE CODE

The complete source dump is in **TECHNICAL_AUDIT_SOURCE.md** (same folder as this file).

Every project source file is included there verbatim: signal_app.py, ault/db.py, parse/parser.py, watch/tailer.py, dashboard.html, schema, configs, and sample logs.


## 3. DATA FLOW

Exact path of **one log line** from upload to dashboard display, naming live functions in order.

### Phase A — HTTP upload (Web & Networks)

1. Browser: user selects a file in the dropzone (`handleFileSelection`) and clicks **Upload Log File**.
2. Browser: `uploadLogFile()` builds `FormData` with field name `file` and `fetch()` POSTs to `/api/upload`.
3. Flask: `api_upload()` in `signal_app.py` runs:
   - Validates `request.files["file"]`.
   - `os.path.basename(uploaded.filename)` → safe filename.
   - `uploaded.save(saved_file_path)` under `data/`.
   - `os.path.getsize(saved_file_path)` → size.
   - `save_upload_history(filename, file_size)` in `vault/db.py` inserts into `upload_history`.
   - Calls `start_monitoring_source(filename, saved_file_path)`.

### Phase B — Enqueue existing lines + start OS tailer

4. `start_monitoring_source()`:
   - Opens the saved file and, for every non-blank line, executes `log_queue.put((filename, line))` where `log_queue` is the global `queue.Queue` from `watch/tailer.py`.
   - Calls `start_watcher(filename, saved_file_path)`.
5. `start_watcher()` spawns a daemon `threading.Thread` targeting `worker_thread(source_name, file_path)`.
6. `worker_thread()` seeks to **EOF** and thereafter appends only *new* lines to `log_queue` (so historical content was already queued in step 4; future appends are tailed).

### Phase C — Queue consumer (bridging OS → DSA)

7. At process start (`if __name__ == "__main__"`), a daemon thread runs `process_queue()` forever.
8. `process_queue()` blocks on `log_queue.get()`, unpacks `(source, line)`, then calls `parse_line(line, source)`.

### Phase D — Parse + detect + persist (DSA + DBMS)

9. `parse_line()` in `parse/parser.py`:
   - Strips empty lines.
   - `_extract_severity(message)` via `SEVERITY_PATTERN`.
   - `_extract_category(message)` via `CATEGORY_RULES`.
   - `db.save_event(severity, category, source, message)` → INSERT into `events` (timestamp = `datetime.now()`).
   - `_check_sliding_window(category, source, message)` — may call `db.save_alert(...)` → INSERT into `alerts`.
10. Returns a dict (unused by `process_queue` except for side effects).

### Phase E — Dashboard poll (Web UI)

11. Browser `setInterval(updateDashboard, 3000)` (and immediate load) calls:
    - `GET /api/stats` → `api_stats()` → `get_event_stats()` + `get_metrics()`.
    - `GET /api/metrics/timeseries` → `api_metrics_timeseries()` → `get_timeseries()`.
    - `GET /api/alerts` → `api_alerts()` → `get_recent_alerts()`.
    - `fetchFilteredLogs()` → `GET /api/logs?...` → `api_logs()` → `get_logs(...)`.
12. UI renderers:
    - Metric cards updated from timeseries `totals` + stats `active_threads`.
    - `updateChartsFromPayload()` updates Chart.js line/bar charts.
    - `renderAlerts()` fills `#alertsTable`.
    - `renderLogs()` fills `#logsTable`.

**Alternate inject path (no file):** `simulateAttack()` → `POST /simulate` → `api_simulate_auth_failure()` → five `log_queue.put(("simulator", line))` → same Phase C onward.

---

## 4. DETECTION LOGIC EXPLAINED

### Where it lives

| Concern | Location |
|--------|----------|
| Window length | `parse/parser.py` → `WINDOW_SECONDS = 10` |
| Threshold | `parse/parser.py` → `THRESHOLD = 5` |
| Per-category deques | `parse/parser.py` → `sliding_windows = {"auth_failure": deque()}` |
| Algorithm | `parse/parser.py` → `_check_sliding_window()` |
| Invoked from | `parse_line()` after every successful `save_event` |
| Alert persistence | `vault/db.py` → `save_alert(...)` |
| DB seed rule (documentation/config only) | `detection_rules` row `auth_failure_burst` (10s / 5) created in `init_db()` — **not read at runtime** by the detector |

### What counts as the window

- The window is a **time-based sliding window of wall-clock seconds**, not a fixed count of log file lines.
- Each time an event’s `category` is a key in `sliding_windows` (currently only `"auth_failure"`), `_check_sliding_window` appends `time.time()` to that category’s `collections.deque`.
- It then `popleft()`s timestamps while `now - window[0] > WINDOW_SECONDS` (strictly older than 10 seconds).
- The live window length is therefore **the number of auth_failure timestamps still within the last 10 seconds**.

### What triggers an alert

1. A log line must be categorized as `auth_failure` by `_extract_category` matching regexes such as `failed login|authentication failed|auth.?fail` (case-insensitive).
2. That category must exist in `sliding_windows` (non-auth categories are ignored by the detector even though they are still stored as events).
3. After pruning, if `len(window) >= THRESHOLD` (**≥ 5** timestamps within 10 seconds), an alert is written:
   - `alert_type="sliding_window"`
   - `severity="CRITICAL"`
   - `category` = the matching category
   - Message includes threshold, window seconds, and the last message text
4. Immediately after firing, `window.clear()` resets the deque so the same burst does not continuously re-alert without a fresh cluster of events.

### What does *not* drive detection today

- `detection_rules` table values are **not** loaded into `WINDOW_SECONDS` / `THRESHOLD`.
- `parse/rules.py` / `SlidingWindowDetector` (legacy in `seed.py`) are **not** on the live `signal_app` path.
- Network/storage/resource categories are stored but have **no** sliding-window deque unless added to `sliding_windows`.

---

## 5. DATABASE SCHEMA

### Authoritative runtime schema

Created by `vault/db.py` → `init_db()` (this supersedes the older `vault/schema.sql` for `alerts`).

#### Table: `events`

| Column | Type | Constraints / default | Purpose |
|--------|------|----------------------|---------|
| `id` | INTEGER | PRIMARY KEY AUTOINCREMENT | Event row id |
| `timestamp` | TEXT | NOT NULL | Ingestion time (`YYYY-MM-DD HH:MM:SS` from `save_event`) |
| `severity` | TEXT | NOT NULL | Parsed severity (INFO/WARN/ERROR/…) |
| `category` | TEXT | NOT NULL | Parsed category (`auth_failure`, etc.) |
| `source` | TEXT | nullable | Source name (filename, `server1`, `simulator`) |
| `message` | TEXT | NOT NULL | Raw log line |
| `created_at` | TEXT | DEFAULT CURRENT_TIMESTAMP | SQLite insert time |

Indexes: `idx_events_category`, `idx_events_timestamp`.

#### Table: `alerts`

| Column | Type | Constraints / default | Purpose |
|--------|------|----------------------|---------|
| `id` | INTEGER | PRIMARY KEY AUTOINCREMENT | Alert id |
| `timestamp` | TEXT | NOT NULL | When alert was saved |
| `alert_type` | TEXT | NOT NULL | e.g. `sliding_window` |
| `category` | TEXT | NOT NULL | Trigger category |
| `severity` | TEXT | NOT NULL | Alert severity (`CRITICAL`) |
| `source` | TEXT | nullable | Source of triggering event |
| `message` | TEXT | NOT NULL | Human-readable anomaly text |
| `created_at` | TEXT | DEFAULT CURRENT_TIMESTAMP | Insert time |

Index: `idx_alerts_timestamp`.

#### Table: `log_sources`

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK AI | |
| `name` | TEXT UNIQUE NOT NULL | Intended logical source name |
| `file_path` | TEXT NOT NULL | Intended path |
| `enabled` | INTEGER DEFAULT 1 | |
| `created_at` | TEXT DEFAULT CURRENT_TIMESTAMP | |

**Relation status:** Table exists; **no live writer** in `signal_app` / `tailer` currently inserts into it (sources are passed as strings on the queue).

#### Table: `detection_rules`

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK AI | |
| `name` | TEXT UNIQUE NOT NULL | e.g. `auth_failure_burst` |
| `category` | TEXT NOT NULL | e.g. `auth_failure` |
| `window_seconds` | INTEGER NOT NULL | Seeded as `10` |
| `threshold` | INTEGER NOT NULL | Seeded as `5` |
| `enabled` | INTEGER DEFAULT 1 | |
| `created_at` | TEXT DEFAULT CURRENT_TIMESTAMP | |

**Relation status:** Seeded for documentation/config; **runtime detector uses module constants**, not this table.

#### Table: `upload_history`

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK AI | |
| `filename` | TEXT NOT NULL | Uploaded basename |
| `file_size` | INTEGER NOT NULL | Bytes on disk |
| `timestamp` | TEXT NOT NULL | App-level timestamp |
| `created_at` | TEXT DEFAULT CURRENT_TIMESTAMP | |

Index: `idx_upload_history_timestamp`. Written by `save_upload_history` on each successful upload.

### How tables relate (logical ER)

```
upload_history ──(audit of files)──► filesystem under data/
        │
        │ (filename becomes source string)
        ▼
   events ◄── many rows per source / upload
        │
        │ (when sliding window fires)
        ▼
   alerts ── references category/source/message textually (no FK constraints)

detection_rules ── parallel config (no FK / no runtime join)
log_sources ── intended registry (unused at runtime)
```

There are **no FOREIGN KEY constraints** in the live schema; relationships are by convention (shared `category` / `source` strings).

### Legacy file: `vault/schema.sql`

Older `alerts` definition used columns `(timestamp, category, count, message)` without `alert_type` / `severity` / `source`. The live app does **not** apply this file; `init_db()` embeds the current DDL.

---

## 6. API ENDPOINTS

Base URL when running locally: `http://127.0.0.1:5050`

### `GET /`

- **Handler:** `dashboard()`
- **Input:** none
- **Returns:** HTML rendered from `signal/templates/dashboard.html`

### `POST /api/upload`

- **Handler:** `api_upload()`
- **Input:** `multipart/form-data` with field `file` (`.log` / `.txt`); body limited by `MAX_CONTENT_LENGTH` = 50 MiB
- **Returns (200):**
  ```json
  {"status":"success","message":"File uploaded and thread started","filename":"...","file_size":123}
  ```
- **Errors:** `400` missing file; `413` via `handle_file_too_large` → `{"error":"File exceeds the 50MB limit"}`

### `POST /api/reset`

- **Handler:** `api_reset()`
- **Input:** empty body
- **Side effect:** `reset_events_and_alerts()` deletes all `events` and `alerts` (and resets sqlite sequences for those tables). Does **not** clear `upload_history`.
- **Returns (200):**
  ```json
  {"status":"success","message":"Events and alerts cleared","total_events":0,"active_alerts":0}
  ```

### `GET /api/metrics/timeseries`

- **Handler:** `api_metrics_timeseries()` → `get_timeseries()`
- **Input:** none
- **Returns (200):**
  ```json
  {
    "totals": {"events": N, "errors": N, "alerts": N},
    "timeline": {"labels": ["YYYY-MM-DD HH:MM", ...], "events": [..], "errors": [..]},
    "labels": [...],
    "data": [...],
    "points": [{"timestamp":"...","count":N}, ...]
  }
  ```

### `GET /api/logs`

- **Handler:** `api_logs()` → `get_logs(...)`
- **Query params:**
  - `limit` (int, default 200)
  - `search` (string, optional) — LIKE across message/source/category/severity
  - `severity` (string, optional) — INFO/WARN/ERROR/FATAL; WARN also matches WARNING; ALL/* ignored
- **Returns (200):**
  ```json
  {"events":[{...},...],"filters":{"search":"...","severity":"..."}}
  ```

### `GET /api/stats`

- **Handler:** `api_stats()`
- **Input:** none
- **Returns (200):**
  ```json
  {
    "total_events": N,
    "errors": N,
    "active_alerts": N,
    "active_threads": N,
    "queue_size": N,
    "events_processed": N
  }
  ```
  (`active_threads` / `queue_size` / `events_processed` from OS engine metrics; counts from DB.)

### `GET /api/events`

- **Handler:** `api_events()` → `get_recent_events(100)`
- **Returns:** JSON array of full event row dicts (newest first). Not used by the current polished dashboard (which uses `/api/logs`).

### `GET /api/alerts`

- **Handler:** `api_alerts()` → `get_recent_alerts(50)`
- **Returns:** JSON array of alert row dicts (newest first).

### `POST|GET /api/simulate-auth-failure` and `POST|GET /simulate`

- **Handler:** `api_simulate_auth_failure()` (both routes)
- **Input:** none required
- **Side effect:** enqueues 5 synthetic ERROR auth-failure lines with source `simulator`
- **Returns (200):**
  ```json
  {"status":"ok","queued":5,"message":"Queued 5 fake auth failures for sliding-window detection"}
  ```

### Error handler

- **`413 Request Entity Too Large`:** `handle_file_too_large` → `{"error":"File exceeds the 50MB limit"}` with status 413.

---

## 7. CONCURRENCY / THREADING

### Threads created

| Thread | Started by | Target | Daemon? | Role |
|--------|------------|--------|---------|------|
| `queue-consumer` | `signal_app.__main__` | `process_queue` | yes | Single consumer of `log_queue` → `parse_line` |
| `tailer-{source}` | `start_watcher` / startup `server1` / each upload | `worker_thread` | yes | Tail file; producer into `log_queue` |
| Flask main thread | `app.run(...)` | Werkzeug server | n/a | HTTP request handling |

`use_reloader=False` avoids a double-process reloader spawning duplicate consumers.

### Shared structures & protection

| Structure | Module | Protection | Why |
|-----------|--------|------------|-----|
| `log_queue` | `watch/tailer.py` | `queue.Queue` (thread-safe put/get) | Multiple producers (tailers + simulate + upload bulk enqueue) / one consumer |
| `_events_processed` | `watch/tailer.py` | `_events_lock` | Counter incremented from multiple tailer threads |
| `_active_workers` | `watch/tailer.py` | `_workers_lock` | Track how many `worker_thread`s are alive for `/api/stats` |
| SQLite writes (`save_event`, `save_alert`, `save_upload_history`, `reset_...`) | `vault/db.py` | `_lock` threading.Lock | Serialize writers; connections use `check_same_thread=False` |
| `sliding_windows` deques | `parse/parser.py` | **No lock** | Safe today only because a **single** `process_queue` thread calls `parse_line`; would race if multiple consumers were added |

### Important concurrency semantics

- Upload path bulk-`put`s historical lines on the **HTTP thread**, then starts a tailer that seeks to EOF — intentional handoff so existing content is processed once.
- `events_processed` in metrics counts lines put by **tailers**, not lines bulk-queued in `start_monitoring_source`, so upload-only historical ingestion may not increase that counter.
- Sliding-window state is **in-memory**; restarting the process clears deques even though DB events/alerts remain.

---

## 8. DEPENDENCIES

From `requirements.txt`:

| Package | Declared | Actually used by current live code? | Purpose |
|---------|----------|-------------------------------------|---------|
| `flask` | yes | **Yes** — `signal_app.py` | HTTP server, templates, `request`, `jsonify` |
| `flask-socketio` | yes | **No** in current sources | Listed but unused; leftover from earlier socket design |
| `python-socketio` | yes | **No** | Transitive/companion to Socket.IO; unused in app code |
| `eventlet` | yes | **No** | Async network lib often paired with Socket.IO; unused |

**Stdlib used heavily (not in requirements):** `os`, `sys`, `threading`, `queue`, `time`, `re`, `collections.deque`, `sqlite3`, `datetime`.

**CDN (frontend, not pip):** Chart.js from `https://cdn.jsdelivr.net/npm/chart.js` in `dashboard.html`.

**Implicit Flask dependency:** `werkzeug.exceptions.RequestEntityTooLarge` for 413 handling.

---

## 9. FEATURES BUILT BEYOND THE ORIGINAL PLAN

Beyond a minimal 4-engine “tail → parse → store → show” pipeline, this codebase includes:

1. **50MB upload limit + 413 JSON handler** — `MAX_CONTENT_LENGTH` and `handle_file_too_large`.
2. **Upload → `upload_history` audit trail** — filename, size, timestamp persisted.
3. **`start_monitoring_source` hybrid ingest** — process existing file contents then continue tailing.
4. **Auth-failure simulator** — `/simulate` and `/api/simulate-auth-failure` enqueue a 5-burst for demos/vivas.
5. **Dashboard reset** — `POST /api/reset` clears events/alerts for clean testing.
6. **Chart.js telemetry** — Events Over Time (line) + Error Spikes (bar) from `/api/metrics/timeseries` minute buckets.
7. **SOC UI polish** — dark theme, dropzone with name/size, status bar, busy button states, fixed 250px chart panels.
8. **Live search & severity filter** — `/api/logs?search=&severity=` + toolbar with debounced `input`/`change` fetch.
9. **Metric cards** — total events, errors, active threads, active alerts via timeseries totals + `/api/stats`.
10. **Critical alert badges** — CRITICAL severity styled in alerts table.
11. **Dual simulate routes** — short `/simulate` alias for frontend contract.
12. **`detection_rules` / `log_sources` tables** — schema readiness beyond minimal events/alerts.
13. **`.cursorrules`** — academic/Theme 5 architectural guardrails for agents.

---

## 10. KNOWN LIMITATIONS / TODOs

1. **Hardcoded detector constants** — `WINDOW_SECONDS=10`, `THRESHOLD=5`; `detection_rules` unused at runtime.
2. **Only `auth_failure` has a sliding window** — other categories are classified but not anomaly-tracked.
3. **No authentication / authorization** — dashboard and all APIs are open on `0.0.0.0:5050`.
4. **No HTTPS / production WSGI** — Flask development server only.
5. **Socket.IO packages unused** — dead weight in `requirements.txt`.
6. **`README.md` and `seed.py` are stale** — reference `get_connection`, `insert_event`, `SlidingWindowDetector` which the live path no longer uses.
7. **`vault/schema.sql` stale** vs `init_db()` alert columns.
8. **`parse/rules.py` unused** by live `parser.py` (duplicated regex logic).
9. **`log_sources` never populated** by runtime code.
10. **Sliding window not durable / not locked for multi-consumer** — process restart loses window; multi-consumer would race.
11. **Event timestamps are ingestion time**, not always the timestamp embedded in the log line.
12. **Upload overwrite** — same filename replaces prior file on disk; may spawn **additional** tailer threads for the same logical name without stopping old ones.
13. **No watcher shutdown / thread join** — daemon threads live until process exit; duplicate uploads can inflate `active_threads`.
14. **`events_processed` metric incomplete** for bulk upload enqueue path.
15. **Reset does not clear `upload_history` or in-memory deques** (deque clears only when alert fires or process restarts; after reset, a partial window could still exist in memory).
16. **No pagination UI** beyond `limit` query param; table shows first 50 of filtered results client-side.
17. **No automated test suite** in the repo.
18. **Windows path / venv assumption** — run instructions typically use `venv\Scripts\python.exe`.

---

## 11. HOW TO RUN IT

Commands below match the **current** `logsentry/` layout on this machine (Windows PowerShell). Adjust activation syntax on macOS/Linux (`source venv/bin/activate`).

### Fresh setup

```powershell
cd t:\logsentry_working\logsentry

# Create venv if missing
python -m venv venv

# Activate (Windows)
.\venv\Scripts\Activate.ps1

# Install declared deps (Flask is required; others optional/unused)
pip install -r requirements.txt

# Initialize / migrate SQLite schema (also happens automatically on app start)
.\venv\Scripts\python.exe vault\db.py
```

### Start the application

```powershell
cd t:\logsentry_working\logsentry
.\venv\Scripts\python.exe signal_app.py
```

On start, the app will:
1. Call `init_db()`.
2. Start a tailer on `data/sample.log` as source `server1` (seeks to EOF — existing sample lines are **not** auto-imported unless appended or uploaded).
3. Start the `queue-consumer` thread.
4. Bind Flask to `0.0.0.0:5050`.

### Use the UI

1. Open `http://127.0.0.1:5050`
2. Click **Simulate Auth Failures** to exercise DSA alerting.
3. Or use the dropzone + **Upload Log File** with `data/test_logs.log` / `data/sample.log`.
4. Use search/severity filters above Recent Events.
5. **Reset Dashboard** clears events/alerts for a clean demo.

### Optional API checks

```powershell
Invoke-WebRequest http://127.0.0.1:5050/api/stats -UseBasicParsing
Invoke-WebRequest http://127.0.0.1:5050/api/metrics/timeseries -UseBasicParsing
Invoke-WebRequest -Method POST http://127.0.0.1:5050/simulate -UseBasicParsing
```

### Note on outdated README seed path

Do **not** follow `README.md` / `seed.py` as the primary run path; they call removed symbols (`get_connection`, `insert_event`, `SlidingWindowDetector`). The supported entrypoint is **`python signal_app.py`** (via the project venv).

---

*End of LogSentry Complete Technical Audit.*
