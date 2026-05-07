"""LAN egress control: restricted subnets + allowlist exceptions."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse

from app import db as dbmod
from app.auth import require_user
from app.util import normalize_cidr

router = APIRouter()


def _parse_port(value: str) -> int | None:
    value = (value or "").strip()
    if not value:
        return None
    try:
        port = int(value)
    except ValueError:
        raise HTTPException(400, "bad port")
    if not (1 <= port <= 65535):
        raise HTTPException(400, "bad port")
    return port


# ----- restricted subnets -----

@router.post("/lan-egress/subnets")
def add_subnet(
    request: Request,
    cidr: str = Form(...),
    description: str = Form(""),
    user: str = Depends(require_user),
):
    cidr = normalize_cidr(cidr)
    conn = request.app.state.db
    with dbmod.transaction(conn):
        conn.execute(
            "INSERT INTO lan_restricted_subnets(cidr, description) VALUES(?, ?) "
            "ON CONFLICT(cidr) DO UPDATE SET description=excluded.description, enabled=1",
            (cidr, description),
        )
        dbmod.mark_dirty(conn)
        dbmod.audit(conn, user, "lan_egress.subnet.add", target=cidr, detail=description)
    return RedirectResponse(url="/lan-egress", status_code=303)


@router.post("/lan-egress/subnets/{cidr_path:path}/toggle")
def toggle_subnet(cidr_path: str, request: Request, user: str = Depends(require_user)):
    conn = request.app.state.db
    with dbmod.transaction(conn):
        conn.execute(
            "UPDATE lan_restricted_subnets SET enabled = 1 - enabled WHERE cidr=?",
            (cidr_path,),
        )
        dbmod.mark_dirty(conn)
        dbmod.audit(conn, user, "lan_egress.subnet.toggle", target=cidr_path)
    return RedirectResponse(url="/lan-egress", status_code=303)


@router.post("/lan-egress/subnets/{cidr_path:path}/delete")
def delete_subnet(cidr_path: str, request: Request, user: str = Depends(require_user)):
    conn = request.app.state.db
    with dbmod.transaction(conn):
        conn.execute("DELETE FROM lan_restricted_subnets WHERE cidr=?", (cidr_path,))
        dbmod.mark_dirty(conn)
        dbmod.audit(conn, user, "lan_egress.subnet.delete", target=cidr_path)
    return RedirectResponse(url="/lan-egress", status_code=303)


# ----- allowlist rules -----

@router.post("/lan-egress/rules")
def add_rule(
    request: Request,
    dst_cidr: str = Form(...),
    proto: str = Form("tcp"),
    dport: str = Form(""),
    description: str = Form(""),
    user: str = Depends(require_user),
):
    if proto not in {"tcp", "udp", "any"}:
        raise HTTPException(400, "bad proto")
    dst_cidr = normalize_cidr(dst_cidr)
    dport_val = _parse_port(dport)

    conn = request.app.state.db
    with dbmod.transaction(conn):
        conn.execute(
            "INSERT INTO lan_egress_rules(dst_cidr, proto, dport, description) "
            "VALUES(?, ?, ?, ?)",
            (dst_cidr, proto, dport_val, description),
        )
        dbmod.mark_dirty(conn)
        dbmod.audit(
            conn, user, "lan_egress.rule.add",
            target=dst_cidr,
            detail=f"{proto}:{dport_val} {description}".strip(),
        )
    return RedirectResponse(url="/lan-egress", status_code=303)


@router.post("/lan-egress/rules/{rule_id}/toggle")
def toggle_rule(rule_id: int, request: Request, user: str = Depends(require_user)):
    conn = request.app.state.db
    with dbmod.transaction(conn):
        conn.execute("UPDATE lan_egress_rules SET enabled = 1 - enabled WHERE id=?", (rule_id,))
        dbmod.mark_dirty(conn)
        dbmod.audit(conn, user, "lan_egress.rule.toggle", target=str(rule_id))
    return RedirectResponse(url="/lan-egress", status_code=303)


@router.post("/lan-egress/rules/{rule_id}/delete")
def delete_rule(rule_id: int, request: Request, user: str = Depends(require_user)):
    conn = request.app.state.db
    with dbmod.transaction(conn):
        conn.execute("DELETE FROM lan_egress_rules WHERE id=?", (rule_id,))
        dbmod.mark_dirty(conn)
        dbmod.audit(conn, user, "lan_egress.rule.delete", target=str(rule_id))
    return RedirectResponse(url="/lan-egress", status_code=303)
