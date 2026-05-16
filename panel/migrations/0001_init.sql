-- Initial schema.
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS users (
    username    TEXT PRIMARY KEY,
    pw_hash     TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'admin',
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS peer_meta (
    pubkey      TEXT PRIMARY KEY,
    label       TEXT,
    blocked     INTEGER NOT NULL DEFAULT 0,
    tor_routed  INTEGER NOT NULL DEFAULT 0,
    notes       TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS acl_rules (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_pubkey   TEXT NOT NULL,
    dst_cidr      TEXT NOT NULL,
    proto         TEXT NOT NULL DEFAULT 'tcp',  -- tcp | udp | any
    dport         INTEGER,
    action        TEXT NOT NULL DEFAULT 'accept', -- accept | drop
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_acl_peer ON acl_rules(peer_pubkey);

CREATE TABLE IF NOT EXISTS internal_hosts (
    mac         TEXT PRIMARY KEY,
    ip          TEXT,
    hostname    TEXT,
    static      INTEGER NOT NULL DEFAULT 0,
    tor_routed  INTEGER NOT NULL DEFAULT 0,
    blocked     INTEGER NOT NULL DEFAULT 0,
    notes       TEXT,
    last_seen   TEXT
);

CREATE TABLE IF NOT EXISTS settings (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      TEXT NOT NULL DEFAULT (datetime('now')),
    actor   TEXT NOT NULL,
    action  TEXT NOT NULL,
    target  TEXT,
    detail  TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);

INSERT OR IGNORE INTO settings(key, value) VALUES
    ('wg_enabled',   'true'),
    ('tor_enabled',  'false'),
    ('dhcp_enabled', 'true'),
    ('dirty',        'false');

INSERT OR IGNORE INTO schema_version(version) VALUES (1);
