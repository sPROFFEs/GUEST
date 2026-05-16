"""User management — admins only (the role distinction is for future use)."""
from __future__ import annotations

import re
import secrets
import string

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse

from app import auth, db as dbmod
from app.auth import require_user

router = APIRouter()


_USERNAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]{1,31}$")


def _flash(request: Request, kind: str, msg: str) -> RedirectResponse:
    request.app.state.users_flash = (kind, msg)
    return RedirectResponse(url="/users", status_code=303)


@router.post("/users")
def create_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    user: str = Depends(require_user),
):
    username = username.strip()
    if not _USERNAME_RE.match(username):
        return _flash(request, "error",
                      "Username: 2–32 chars, start with a letter, then letters/digits/_/-.")
    if len(password) < 10:
        return _flash(request, "error", "Password must be at least 10 characters.")

    conn = request.app.state.db
    exists = conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone()
    if exists:
        return _flash(request, "error", f"User '{username}' already exists.")

    with dbmod.transaction(conn):
        conn.execute(
            "INSERT INTO users(username, pw_hash, role) VALUES(?, ?, 'admin')",
            (username, auth.hash_password(password)),
        )
        dbmod.audit(conn, user, "user.create", target=username)
    return _flash(request, "ok", f"User '{username}' created.")


@router.post("/users/{username}/delete")
def delete_user(username: str, request: Request, user: str = Depends(require_user)):
    if username == user:
        return _flash(request, "error", "You can't delete your own account.")

    conn = request.app.state.db
    n = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    if n <= 1:
        return _flash(request, "error", "Can't delete the last remaining user.")

    with dbmod.transaction(conn):
        conn.execute("DELETE FROM users WHERE username=?", (username,))
        dbmod.audit(conn, user, "user.delete", target=username)
    return _flash(request, "ok", f"User '{username}' deleted.")


@router.post("/users/{username}/reset-password")
def reset_password(username: str, request: Request, user: str = Depends(require_user)):
    """Generates a one-shot password, shows it once via flash. Bumps pw_version
    so any active session for this user is invalidated."""
    conn = request.app.state.db
    exists = conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone()
    if not exists:
        return _flash(request, "error", f"No such user: '{username}'.")

    new_pw = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
    with dbmod.transaction(conn):
        conn.execute(
            "UPDATE users SET pw_hash=?, pw_version = pw_version + 1 WHERE username=?",
            (auth.hash_password(new_pw), username),
        )
        dbmod.audit(conn, user, "user.reset_password", target=username)
    return _flash(request, "ok", f"Password reset for '{username}': {new_pw}")
