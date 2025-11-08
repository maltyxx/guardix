-- WAF Events Log
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    decision TEXT NOT NULL,
    confidence REAL NOT NULL,
    reason TEXT,
    ip_addr TEXT,
    user_agent TEXT
);

CREATE INDEX IF NOT EXISTS idx_decision_timestamp ON events(decision, timestamp);
CREATE INDEX IF NOT EXISTS idx_payload_hash ON events(payload_hash);
CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp DESC);

