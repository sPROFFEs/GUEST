"""Session-cookie auth with argon2 password hashing."""
from __future__ import annotations

import sqlite3
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Cookie, Depends, HTTPException, Request, status
from itsdangerous import BadSignature, URLSafeSerializer

_hasher = PasswordHasher()


def hash_password(plain: str) -> str:
    return _hasher.hash(plain)


def verify_password(hash_: str, plain: str) -> bool:
    try:
        _hasher.verify(hash_, plain)
        return True
    except VerifyMismatchError:
        return False


class SessionManager:
    """Stateless session via signed cookie. The secret lives in the DB so it
    survives restarts but is unique per gateway."""

    COOKIE_NAME = "gw_session"

    def __init__(self, secret: str) -> None:
        self._s = URLSafeSerializer(secret, salt="gateway-panel-session")

    def issue(self, username: str) -> str:
        return self._s.dumps({"u": username})

    def read(self, token: Optional[str]) -> Optional[str]:
        if not token:
            return None
        try:
            data = self._s.loads(token)
            return data.get("u")
        except BadSignature:
            return None


def authenticate(conn: sqlite3.Connection, username: str, password: str) -> bool:
    row = conn.execute("SELECT pw_hash FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        return False
    return verify_password(row["pw_hash"], password)


def get_or_create_session_secret(conn: sqlite3.Connection) -> str:
    """Persist a per-gateway secret in the settings table."""
    row = conn.execute("SELECT value FROM settings WHERE key='session_secret'").fetchone()
    if row:
        return row["value"]
    import secrets
    secret = secrets.token_urlsafe(32)
    conn.execute(
        "INSERT OR REPLACE INTO settings(key, value) VALUES('session_secret', ?)",
        (secret,),
    )
    return secret


# --- FastAPI dependency ---

def require_user(request: Request) -> str:
    """Returns the authenticated username or raises 401."""
    sm: SessionManager = request.app.state.sessions
    token = request.cookies.get(SessionManager.COOKIE_NAME)
    user = sm.read(token)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="login required")
    return user
