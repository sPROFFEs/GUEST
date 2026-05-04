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
        conn.execute("UPDATE users SET pw_hash=? WHERE username=?", (new_hash, user))
        dbmod.audit(conn, user, "user.password_changed")

    return _flash("ok", "Password updated.")
