"""Self-service account actions: change own password."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse

from app import auth, db as dbmod
from app.auth import require_user

router = APIRouter()


@router.post("/me/password")
def change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    user: str = Depends(require_user),
):
    conn = request.app.state.db

    def _flash(kind: str, msg: str) -> RedirectResponse:
        request.app.state.password_flash = (kind, msg)
        return RedirectResponse(url="/settings", status_code=303)

    if new_password != confirm_password:
        return _flash("error", "New password and confirmation don't match.")
    if len(new_password) < 10:
        return _flash("error", "New password must be at least 10 characters.")
    if not auth.authenticate(conn, user, current_password):
        return _flash("error", "Current password is incorrect.")

    new_hash = auth.hash_password(new_password)
    with dbmod.transaction(conn):
        # Bump pw_version so every existing session for this user is rejected
        # on its next request (including the cookie that submitted this form).
        conn.execute(
            "UPDATE users SET pw_hash=?, pw_version = pw_version + 1 WHERE username=?",
            (new_hash, user),
        )
        dbmod.audit(conn, user, "user.password_changed")

    # Re-issue a session with the new pw_version so the current admin doesn't
    # get instantly logged out after the operation they just performed.
    row = conn.execute("SELECT pw_version FROM users WHERE username=?", (user,)).fetchone()
    sm: auth.SessionManager = request.app.state.sessions
    new_token = sm.issue(user, pw_version=int(row["pw_version"]))
    resp = _flash("ok", "Password updated.")
    resp.set_cookie(
        auth.SessionManager.COOKIE_NAME,
        new_token,
        httponly=True,
        samesite="strict",
        secure=request.url.scheme == "https",
        max_age=60 * 60 * 12,
    )
    return resp
