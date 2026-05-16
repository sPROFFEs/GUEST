"""Login/logout views."""
from __future__ import annotations

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app import auth, db as dbmod

router = APIRouter()
_templates = Jinja2Templates(directory="app/web/templates")


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return _templates.TemplateResponse("login.html", {
        "request": request,
        "gateway_name": request.app.state.cfg.gateway_name,
        "error": None,
    })


@router.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    conn = request.app.state.db
    if not auth.authenticate(conn, username, password):
        return _templates.TemplateResponse("login.html", {
            "request": request,
            "gateway_name": request.app.state.cfg.gateway_name,
            "error": "Invalid credentials.",
        }, status_code=401)
    row = conn.execute("SELECT pw_version FROM users WHERE username=?", (username,)).fetchone()
    pw_version = int(row["pw_version"]) if row and "pw_version" in row.keys() else 0
    sm: auth.SessionManager = request.app.state.sessions
    token = sm.issue(username, pw_version=pw_version)
    resp = RedirectResponse(url="/", status_code=303)
    resp.set_cookie(
        auth.SessionManager.COOKIE_NAME,
        token,
        httponly=True,
        samesite="strict",
        # Auto: Secure flag tracks the request scheme. Over plain HTTP (the WG
        # tunnel itself is the encryption) we leave it off; under TLS we set it.
        secure=request.url.scheme == "https",
        max_age=60 * 60 * 12,
    )
    dbmod.audit(conn, username, "login")
    return resp


@router.post("/logout")
def logout(request: Request):
    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie(auth.SessionManager.COOKIE_NAME)
    return resp
