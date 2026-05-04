"""Peer listing + per-peer toggles. Joins live `wg show` with peer_meta."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import db as dbmod
from app.auth import require_user
from app.services.wg_sync import list_peers

router = APIRouter()


def _list(conn, cfg) -> list[dict]:
    peers = list_peers(cfg.wg_show_cmd)
    metas = {r["pubkey"]: dict(r) for r in conn.execute("SELECT * FROM peer_meta")}
    out = []
    for p in peers:
        m = metas.get(p.pubkey, {})
        out.append({
            "pubkey": p.pubkey,
            "label": m.get("label") or "",
            "peer_ip": p.peer_ip,
            "endpoint": p.endpoint,
            "last_handshake": p.last_handshake,
            "rx": p.rx_bytes,
            "tx": p.tx_bytes,
            "blocked": bool(m.get("blocked", 0)),
            "tor_routed": bool(m.get("tor_routed", 0)),
        })
    return out


@router.get("/api/peers")
def api_list(request: Request, user: str = Depends(require_user)):
    conn = request.app.state.db
    cfg = request.app.state.cfg
    return {"peers": _list(conn, cfg)}


@router.post("/peers/{pubkey}/toggle")
def toggle(pubkey: str, field: str = Form(...), request: Request = None, user: str = Depends(require_user)):
    if field not in {"blocked", "tor_routed"}:
        raise HTTPException(400, "bad field")
    conn = request.app.state.db
    with dbmod.transaction(conn):
        conn.execute(
            f"INSERT INTO peer_meta(pubkey, {field}, updated_at) VALUES(?, 1, datetime('now')) "
            f"ON CONFLICT(pubkey) DO UPDATE SET {field}=1-{field}, updated_at=datetime('now')",
            (pubkey,),
        )
        dbmod.mark_dirty(conn)
        dbmod.audit(conn, user, f"peer.toggle.{field}", target=pubkey)
    return RedirectResponse(url="/peers", status_code=303)


@router.post("/peers/{pubkey}/label")
def set_label(pubkey: str, label: str = Form(""), request: Request = None, user: str = Depends(require_user)):
    conn = request.app.state.db
    with dbmod.transaction(conn):
        conn.execute(
            "INSERT INTO peer_meta(pubkey, label, updated_at) VALUES(?, ?, datetime('now')) "
            "ON CONFLICT(pubkey) DO UPDATE SET label=excluded.label, updated_at=datetime('now')",
            (pubkey, label),
        )
        dbmod.audit(conn, user, "peer.label", target=pubkey, detail=label)
    return RedirectResponse(url="/peers", status_code=303)
