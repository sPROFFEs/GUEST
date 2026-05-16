"""Operator CLI: DB init, admin creation, scanner one-shot."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from app import auth, config, db as dbmod


_MIGRATIONS = Path(__file__).resolve().parent.parent / "migrations"


def _init_db(args) -> int:
    dbmod.init_db(Path(args.db), _MIGRATIONS)
    print(f"db initialized at {args.db}")
    return 0


def _has_admin(args) -> int:
    conn = dbmod.connect(Path(args.db))
    try:
        n = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    finally:
        conn.close()
    return 0 if n > 0 else 1


def _create_admin(args) -> int:
    conn = dbmod.connect(Path(args.db))
    try:
        conn.execute(
            "INSERT INTO users(username, pw_hash, role) VALUES(?, ?, 'admin')",
            (args.username, auth.hash_password(args.password)),
        )
    finally:
        conn.close()
    print(f"admin user created: {args.username}")
    return 0


def _scan(args) -> int:
    cfg = config.load()
    conn = dbmod.connect(cfg.db_path)
    try:
        from app.services.scanner import scan, upsert_into_db
        neighbors = scan(cfg.lan_iface)
        with dbmod.transaction(conn):
            upsert_into_db(conn, neighbors)
        print(f"scanned: {len(neighbors)} hosts on {cfg.lan_iface}")
    finally:
        conn.close()
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser("gateway-cli")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init-db"); s.add_argument("--db", required=True); s.set_defaults(fn=_init_db)
    s = sub.add_parser("has-admin"); s.add_argument("--db", required=True); s.set_defaults(fn=_has_admin)
    s = sub.add_parser("create-admin")
    s.add_argument("--db", required=True)
    s.add_argument("--username", required=True)
    s.add_argument("--password", required=True)
    s.set_defaults(fn=_create_admin)
    s = sub.add_parser("scan"); s.set_defaults(fn=_scan)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
