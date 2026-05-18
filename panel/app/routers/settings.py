"""Module toggles + apply/status."""
from __future__ import annotations

import subprocess

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse

from app import db as dbmod
from app.auth import require_user
from app.services import applier
from app.util import safe_redirect_back

router = APIRouter()


_SERVICE_FOR_TOGGLE = {
    "wg_enabled":   "wg-quick@wg0",
    # Debian's tor.service is a placeholder; tor@default.service is the real
    # daemon that listens on TransPort. Manage the real one.
    "tor_enabled":  "tor@default",
    "dhcp_enabled": "dnsmasq",
}


@router.post("/settings/toggle")
def toggle(key: str = Form(...), request: Request = None, user: str = Depends(require_user)):
    target = safe_redirect_back(request, fallback="/settings")
    if key not in _SERVICE_FOR_TOGGLE:
        return RedirectResponse(url=target, status_code=303)
    conn = request.app.state.db
    cur = dbmod.get_setting(conn, key, "false")
    new = "false" if cur == "true" else "true"
    with dbmod.transaction(conn):
        dbmod.set_setting(conn, key, new)
        dbmod.audit(conn, user, "settings.toggle", target=key, detail=new)

    # Apply effect immediately for service toggles. nft rule changes still
    # need an explicit Apply because they depend on the rendered fragment.
    svc = _SERVICE_FOR_TOGGLE[key]
    action = "start" if new == "true" else "stop"
    subprocess.run(["sudo", "/usr/bin/systemctl", action, svc], check=False)

    return RedirectResponse(url=target, status_code=303)


@router.post("/apply")
def apply(request: Request, user: str = Depends(require_user)):
    conn = request.app.state.db
    cfg = request.app.state.cfg
    try:
        applier.apply(conn, cfg, actor=user)
        request.app.state.last_error = None
    except applier.ApplyError as e:
        request.app.state.last_error = str(e)
    return RedirectResponse(url=safe_redirect_back(request, fallback="/"), status_code=303)


@router.get("/api/status")
def status(request: Request, user: str = Depends(require_user)):
    conn = request.app.state.db
    out = {
        "dirty": dbmod.is_dirty(conn),
        "last_error": getattr(request.app.state, "last_error", None),
        "settings": {
            k: dbmod.get_setting(conn, k, "false")
            for k in _SERVICE_FOR_TOGGLE
        },
        "services": {},
    }
    for key, svc in _SERVICE_FOR_TOGGLE.items():
        r = subprocess.run(
            ["sudo", "/usr/bin/systemctl", "is-active", svc],
            capture_output=True, text=True,
        )
        out["services"][svc] = r.stdout.strip()
    return out
