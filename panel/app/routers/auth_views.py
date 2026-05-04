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
    sm: auth.SessionManager = request.app.state.sessions
    token = sm.issue(username)
    resp = RedirectResponse(url="/", status_code=303)
    resp.set_cookie(
        auth.SessionManager.COOKIE_NAME,
        token,
        httponly=True,
        samesite="strict",
        secure=False,  # served over plain HTTP on wg0; tunnel itself is the encryption
        max_age=60 * 60 * 12,
    )
    dbmod.audit(conn, username, "login")
    return resp


@router.post("/logout")
def logout(request: Request):
    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie(auth.SessionManager.COOKIE_NAME)
    return resp
