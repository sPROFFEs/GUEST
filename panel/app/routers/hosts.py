"""LAN-internal host listing + per-host toggles + static-lease editing."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse

from app import db as dbmod
from app.auth import require_user

router = APIRouter()


@router.get("/api/hosts")
def api_list(request: Request, user: str = Depends(require_user)):
    conn = request.app.state.db
    rows = conn.execute("SELECT * FROM internal_hosts ORDER BY ip").fetchall()
    return {"hosts": [dict(r) for r in rows]}


@router.post("/hosts")
def create(
    mac: str = Form(...),
    ip: str = Form(...),
    hostname: str = Form(""),
    request: Request = None,
    user: str = Depends(require_user),
):
    mac = mac.lower()
    conn = request.app.state.db
    with dbmod.transaction(conn):
        conn.execute(
            "INSERT INTO internal_hosts(mac, ip, hostname, static, last_seen) "
            "VALUES(?, ?, ?, 1, NULL) "
            "ON CONFLICT(mac) DO UPDATE SET ip=excluded.ip, hostname=excluded.hostname, static=1",
            (mac, ip, hostname),
        )
        dbmod.mark_dirty(conn)
        dbmod.audit(conn, user, "host.create", target=mac, detail=f"{ip} {hostname}")
    return RedirectResponse(url="/hosts", status_code=303)


@router.post("/hosts/{mac}/toggle")
def toggle(mac: str, field: str = Form(...), request: Request = None, user: str = Depends(require_user)):
    if field not in {"blocked", "tor_routed", "static"}:
        raise HTTPException(400, "bad field")
    conn = request.app.state.db
    with dbmod.transaction(conn):
        conn.execute(
            f"UPDATE internal_hosts SET {field} = 1 - {field} WHERE mac=?",
            (mac.lower(),),
        )
        dbmod.mark_dirty(conn)
        dbmod.audit(conn, user, f"host.toggle.{field}", target=mac)
    return RedirectResponse(url="/hosts", status_code=303)


@router.post("/hosts/{mac}/ip")
def set_ip(mac: str, ip: str = Form(...), request: Request = None, user: str = Depends(require_user)):
    conn = request.app.state.db
    with dbmod.transaction(conn):
        conn.execute(
            "UPDATE internal_hosts SET ip=?, static=1 WHERE mac=?",
            (ip, mac.lower()),
        )
        dbmod.mark_dirty(conn)
        dbmod.audit(conn, user, "host.ip", target=mac, detail=ip)
    return RedirectResponse(url="/hosts", status_code=303)


@router.post("/hosts/{mac}/delete")
def delete(mac: str, request: Request, user: str = Depends(require_user)):
    conn = request.app.state.db
    with dbmod.transaction(conn):
        conn.execute("DELETE FROM internal_hosts WHERE mac=?", (mac.lower(),))
        dbmod.mark_dirty(conn)
        dbmod.audit(conn, user, "host.delete", target=mac)
    return RedirectResponse(url="/hosts", status_code=303)
