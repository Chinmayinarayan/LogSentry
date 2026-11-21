-- LogSentry Authoritative Relational Database Schema (SQLite 3)
-- Compliant with LogSentry SRS Engine E3 VAULT Specifications
-- WAL Mode enabled for high-performance concurrent reads and single-writer synchronization

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 30000;

-- 1. USER ENTITY (SRS: USER)
-- Role-Based Access Control: ADMIN, OPERATOR, VIEWER
CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT CHECK(role IN ('ADMIN', 'OPERATOR', 'VIEWER')) NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 2. EVENT ENTITY (SRS: EVENT)
-- Normalized classified operational logs from HDFS & NASA-HTTP
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL,
    source TEXT NOT NULL,
    log_level TEXT NOT NULL,
    component_host TEXT,
    raw_message TEXT NOT NULL
);

-- 3. ALERT ENTITY (SRS: ALERT)
-- Sliding-window anomaly burst detections with lifecycle status
CREATE TABLE IF NOT EXISTS alerts (
    alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL,
    source TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    event_count INT NOT NULL,
    window_duration_sec INT NOT NULL,
    status TEXT DEFAULT 'ACTIVE',
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_by INTEGER REFERENCES users(user_id)
);

-- 4. CONFIG ENTITY (SRS: CONFIG)
-- Configurable sliding-window parameters: W (window seconds) and T (threshold count)
CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_by INTEGER REFERENCES users(user_id)
);

-- 5. AUDIT HISTORY ENTITY (SRS: AUDIT_LOG)
-- Immutable audit record for state mutations (alert resolutions, threshold updates)
CREATE TABLE IF NOT EXISTS history (
    history_id INTEGER PRIMARY KEY AUTOINCREMENT,
    table_name TEXT NOT NULL,
    record_id INTEGER NOT NULL,
    field_changed TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    changed_by INTEGER REFERENCES users(user_id),
    changed_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 6. QUARANTINE ENTITY (SRS: QUARANTINE / REJECTED_LINES)
-- Evidence locker for malformed, truncated, wrong-source, or binary inputs
CREATE TABLE IF NOT EXISTS rejected_lines (
    rejected_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL,
    source TEXT NOT NULL,
    reason TEXT NOT NULL,
    raw_bytes BLOB NOT NULL
);

-- PERFORMANCE & SEARCH INDEXES
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_level ON events(log_level);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_history_record ON history(table_name, record_id);
CREATE INDEX IF NOT EXISTS idx_rejected_source ON rejected_lines(source);
