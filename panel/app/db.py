"""SQLite access. Single connection per request via dependency."""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


def connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db(db_path: Path, migrations_dir: Path) -> None:
    """Apply migrations whose version isn't recorded in schema_version yet.

    Migration files are named `NNNN_*.sql` where NNNN is the integer version.
    schema_version (created in 0001) tracks what's been applied, so re-running
    init on a healthy DB is a fast no-op rather than re-executing DDL that
    would raise (e.g. duplicate column).
    """
    import re
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = connect(db_path)
    try:
        # Make sure the bookkeeping table exists before we query it. The very
        # first migration creates it too, but the query below needs it now.
        conn.executescript(
            "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY);"
        )
        applied = {row["version"] for row in conn.execute("SELECT version FROM schema_version")}

        for sql_file in sorted(migrations_dir.glob("*.sql")):
            m = re.match(r"^(\d+)_", sql_file.name)
            if not m:
                continue
            version = int(m.group(1))
            if version in applied:
                continue
            conn.executescript(sql_file.read_text())
    finally:
        conn.close()


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    conn.execute("BEGIN")
    try:
        yield conn
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise


def get_setting(conn: sqlite3.Connection, key: str, default: str = "") -> str:
    row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO settings(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )


def mark_dirty(conn: sqlite3.Connection) -> None:
    set_setting(conn, "dirty", "true")


def mark_clean(conn: sqlite3.Connection) -> None:
    set_setting(conn, "dirty", "false")


def is_dirty(conn: sqlite3.Connection) -> bool:
    return get_setting(conn, "dirty", "false") == "true"


def audit(conn: sqlite3.Connection, actor: str, action: str, target: str = "", detail: str = "") -> None:
    conn.execute(
        "INSERT INTO audit_log(actor, action, target, detail) VALUES(?, ?, ?, ?)",
        (actor, action, target, detail),
    )
