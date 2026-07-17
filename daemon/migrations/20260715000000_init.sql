CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    public_key BLOB NOT NULL,
    last_seen INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS history (
    uuid TEXT PRIMARY KEY NOT NULL,
    url TEXT NOT NULL,
    normalized_url TEXT NOT NULL,
    title TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    browser TEXT NOT NULL,
    device TEXT NOT NULL,
    hash TEXT NOT NULL,
    visit_type TEXT NOT NULL,
    deleted BOOLEAN NOT NULL DEFAULT 0,
    synced BOOLEAN NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS event_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT NOT NULL,
    operation TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    vector_clock TEXT NOT NULL,
    device TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_history_url ON history(url);
CREATE INDEX IF NOT EXISTS idx_history_timestamp ON history(timestamp);
CREATE INDEX IF NOT EXISTS idx_history_device ON history(device);
CREATE INDEX IF NOT EXISTS idx_event_log_uuid ON event_log(uuid);
CREATE INDEX IF NOT EXISTS idx_event_log_timestamp ON event_log(timestamp);



