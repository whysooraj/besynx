CREATE TABLE IF NOT EXISTS cookies (
    domain TEXT NOT NULL,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    path TEXT NOT NULL,
    secure BOOLEAN NOT NULL,
    http_only BOOLEAN NOT NULL,
    expiration_date INTEGER,
    same_site TEXT NOT NULL,
    device TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    PRIMARY KEY (domain, name, path)
);
