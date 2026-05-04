"""LAN egress control: restricted subnets + allowlist exceptions."""
from __future__ import annotations

import ipaddress

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse

from app import db as dbmod
from app.auth import require_user

router = APIRouter()


def _validate_cidr(s: str) -> str:
    """Normalize and validate a CIDR (IPv4 only for now)."""
    try:
        net = ipaddress.IPv4Network(s.strip(), strict=False)
        return str(net)
    except (ValueError, ipaddress.AddressValueError, ipaddress.NetmaskValueError):
        raise HTTPException(400, f"Invalid CIDR: {s}")


# ----- restricted subnets -----

@router.post("/lan-egress/subnets")
def add_subnet(
    request: Request,
    cidr: str = Form(...),
    description: str = Form(""),
    user: str = Depends(require_user),
):
    cidr = _validate_cidr(cidr)
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
    dst_cidr = _validate_cidr(dst_cidr)
    dport_val = int(dport) if dport.strip() else None
    if dport_val is not None and not (1 <= dport_val <= 65535):
        raise HTTPException(400, "bad port")

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
