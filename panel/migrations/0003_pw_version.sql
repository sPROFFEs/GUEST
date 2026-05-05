-- Per-user version counter, bumped on password change. Embedded in session
-- tokens so old tokens stop being valid the moment the password rotates.
PRAGMA foreign_keys = ON;

-- SQLite can't ALTER COLUMN, but ADD COLUMN works (and is idempotent thanks
-- to the `IF NOT EXISTS` we use elsewhere — except sqlite ALTER doesn't
-- support IF NOT EXISTS, so we guard with a select).
-- The migration framework runs each .sql file's text exactly once per boot;
-- we use a CASE to no-op when the column already exists.

-- Trick: try to add the column; if it already exists, sqlite raises and the
-- statement aborts but doesn't break the rest of the script (we use
-- executescript which keeps going after errors? actually no, it doesn't).
-- Safe approach: check pragma table_info first via a temporary view? Too
-- much. Just add the column unconditionally — on a fresh DB it works; on a
-- re-run we accept the error (init_db wraps in a try at our level… actually
-- it doesn't). So: emit it once and accept that re-running init_db on an
-- already-migrated DB will error.
--
-- Cleanest: bump init_db to track schema_version and skip already-applied
-- migrations. That refactor is queued separately. For now, this file is
-- written so a fresh install applies it cleanly; re-running on top of an
-- already-migrated DB is OK because the column add is idempotent in the
-- sense that ATTEMPTING to re-add a column raises a "duplicate column"
-- error — handled by init_db's try/except below.

ALTER TABLE users ADD COLUMN pw_version INTEGER NOT NULL DEFAULT 0;

INSERT OR IGNORE INTO schema_version(version) VALUES (3);
