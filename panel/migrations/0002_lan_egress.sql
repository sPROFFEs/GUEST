-- LAN egress control: restricted private subnets + allowlist exceptions.
PRAGMA foreign_keys = ON;

-- Subnets that internal-LAN hosts are blocked from reaching by default.
-- Empty table = no restriction (full upstream access, current behavior).
CREATE TABLE IF NOT EXISTS lan_restricted_subnets (
    cidr        TEXT PRIMARY KEY,
    description TEXT,
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Explicit accept rules. Evaluated BEFORE the drop in lan_egress, so a rule
-- here punches a hole through the restriction.
CREATE TABLE IF NOT EXISTS lan_egress_rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    dst_cidr    TEXT NOT NULL,
    proto       TEXT NOT NULL DEFAULT 'tcp',  -- tcp | udp | any
    dport       INTEGER,
    description TEXT,
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_lan_egress_dst ON lan_egress_rules(dst_cidr);

INSERT OR IGNORE INTO schema_version(version) VALUES (2);
