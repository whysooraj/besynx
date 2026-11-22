CREATE TABLE IF NOT EXISTS tabs (
    device_id TEXT NOT NULL,
    tab_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    title TEXT NOT NULL,
    favicon TEXT,
    window_id INTEGER,
    active BOOLEAN NOT NULL DEFAULT 0,
    pinned BOOLEAN NOT NULL DEFAULT 0,
    last_active_at INTEGER NOT NULL,
    PRIMARY KEY (device_id, tab_id)
);

CREATE INDEX IF NOT EXISTS idx_tabs_device ON tabs (device_id);
CREATE INDEX IF NOT EXISTS idx_tabs_last_active ON tabs (last_active_at);
