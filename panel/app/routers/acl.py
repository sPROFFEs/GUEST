"""ACL CRUD per peer."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse

from app import db as dbmod
from app.auth import require_user
from app.util import normalize_cidr

router = APIRouter()


@router.get("/api/peers/{pubkey}/acl")
def api_list(pubkey: str, request: Request, user: str = Depends(require_user)):
    conn = request.app.state.db
    rows = conn.execute(
        "SELECT * FROM acl_rules WHERE peer_pubkey=? ORDER BY id", (pubkey,)
    ).fetchall()
    return {"rules": [dict(r) for r in rows]}


@router.post("/peers/{pubkey}/acl")
def add(
    pubkey: str,
    dst_cidr: str = Form(...),
    proto: str = Form("tcp"),
    dport: str = Form(""),
    action: str = Form("accept"),
    request: Request = None,
    user: str = Depends(require_user),
):
    if proto not in {"tcp", "udp", "any"}:
        raise HTTPException(400, "bad proto")
    if action not in {"accept", "drop"}:
        raise HTTPException(400, "bad action")
    dst_cidr = normalize_cidr(dst_cidr)
    dport_val = int(dport) if dport.strip() else None
    conn = request.app.state.db
    with dbmod.transaction(conn):
        # Make sure the peer_meta row exists (FK-like; we don't enforce FK
        # because pubkey could be added before WG handshake).
        conn.execute(
            "INSERT OR IGNORE INTO peer_meta(pubkey) VALUES(?)", (pubkey,)
        )
        conn.execute(
            "INSERT INTO acl_rules(peer_pubkey, dst_cidr, proto, dport, action) "
            "VALUES(?, ?, ?, ?, ?)",
            (pubkey, dst_cidr, proto, dport_val, action),
        )
        dbmod.mark_dirty(conn)
        dbmod.audit(conn, user, "acl.add", target=pubkey,
                    detail=f"{action} {proto}:{dst_cidr}:{dport_val}")
    return RedirectResponse(url=f"/peers/{pubkey}/acl", status_code=303)


@router.post("/acl/{rule_id}/delete")
def delete(rule_id: int, request: Request, user: str = Depends(require_user)):
    conn = request.app.state.db
    row = conn.execute("SELECT peer_pubkey FROM acl_rules WHERE id=?", (rule_id,)).fetchone()
    if not row:
        raise HTTPException(404, "not found")
    with dbmod.transaction(conn):
        conn.execute("DELETE FROM acl_rules WHERE id=?", (rule_id,))
        dbmod.mark_dirty(conn)
        dbmod.audit(conn, user, "acl.delete", target=str(rule_id))
    return RedirectResponse(url=f"/peers/{row['peer_pubkey']}/acl", status_code=303)
