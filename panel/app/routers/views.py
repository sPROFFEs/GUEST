"""HTML views (htmx + Pico). Read-only renders; mutations go through the
form-posting endpoints in the other routers and redirect back here."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app import db as dbmod
from app.auth import require_user
from app.routers.peers import _list as list_peers_with_meta
from app.routers.settings import _SERVICE_FOR_TOGGLE
import subprocess

router = APIRouter()
_templates = Jinja2Templates(directory="app/web/templates")


def _flags(request: Request) -> dict:
    conn = request.app.state.db
    return {
        "dirty": dbmod.is_dirty(conn),
        "last_error": getattr(request.app.state, "last_error", None),
        "gateway_name": request.app.state.cfg.gateway_name,
    }


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, user: str = Depends(require_user)):
    conn = request.app.state.db
    cfg = request.app.state.cfg
    settings = {
        k: dbmod.get_setting(conn, k, "false") == "true"
        for k in _SERVICE_FOR_TOGGLE
    }
    services = {}
    for key, svc in _SERVICE_FOR_TOGGLE.items():
        r = subprocess.run(
            ["sudo", "/bin/systemctl", "is-active", svc],
            capture_output=True, text=True,
        )
        services[svc] = r.stdout.strip() or "unknown"
    return _templates.TemplateResponse("dashboard.html", {
        "request": request, "user": user,
        "settings": settings, "services": services,
        "wan_iface": cfg.wan_iface, "lan_iface": cfg.lan_iface,
        "lan_cidr": cfg.lan_cidr, "wg_peer_cidr": cfg.wg_peer_cidr,
        **_flags(request),
    })


@router.get("/peers", response_class=HTMLResponse)
def peers_view(request: Request, user: str = Depends(require_user)):
    conn = request.app.state.db
    cfg = request.app.state.cfg
    peers = list_peers_with_meta(conn, cfg)
    now = int(datetime.now(timezone.utc).timestamp())
    for p in peers:
        p["handshake_age"] = (now - p["last_handshake"]) if p["last_handshake"] else None
    return _templates.TemplateResponse("peers.html", {
        "request": request, "user": user, "peers": peers, **_flags(request),
    })


@router.get("/peers/{pubkey}/acl", response_class=HTMLResponse)
def acl_view(pubkey: str, request: Request, user: str = Depends(require_user)):
    conn = request.app.state.db
    rules = [dict(r) for r in conn.execute(
        "SELECT * FROM acl_rules WHERE peer_pubkey=? ORDER BY id", (pubkey,)
    )]
    label_row = conn.execute("SELECT label FROM peer_meta WHERE pubkey=?", (pubkey,)).fetchone()
    label = label_row["label"] if label_row else ""
    return _templates.TemplateResponse("acl.html", {
        "request": request, "user": user,
        "pubkey": pubkey, "label": label, "rules": rules,
        **_flags(request),
    })


@router.get("/hosts", response_class=HTMLResponse)
def hosts_view(request: Request, user: str = Depends(require_user)):
    conn = request.app.state.db
    rows = [dict(r) for r in conn.execute("SELECT * FROM internal_hosts ORDER BY ip")]
    return _templates.TemplateResponse("hosts.html", {
        "request": request, "user": user, "hosts": rows, **_flags(request),
    })


@router.get("/settings", response_class=HTMLResponse)
def settings_view(request: Request, user: str = Depends(require_user)):
    conn = request.app.state.db
    settings = {
        k: dbmod.get_setting(conn, k, "false") == "true"
        for k in _SERVICE_FOR_TOGGLE
    }
    # One-shot flash for the password-change form. Read and clear.
    flash = getattr(request.app.state, "password_flash", None)
    request.app.state.password_flash = None
    return _templates.TemplateResponse("settings.html", {
        "request": request, "user": user, "settings": settings,
        "password_flash": flash,
        **_flags(request),
    })


@router.get("/audit", response_class=HTMLResponse)
def audit_view(request: Request, user: str = Depends(require_user)):
    conn = request.app.state.db
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM audit_log ORDER BY id DESC LIMIT 200"
    )]
    return _templates.TemplateResponse("audit.html", {
        "request": request, "user": user, "rows": rows, **_flags(request),
    })
