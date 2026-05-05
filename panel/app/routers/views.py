"""HTML views (htmx + Pico). Read-only renders; mutations go through the
form-posting endpoints in the other routers and redirect back here."""
from __future__ import annotations

import subprocess
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app import db as dbmod
from app.auth import require_user
from app.routers.peers import _list as list_peers_with_meta
from app.routers.settings import _SERVICE_FOR_TOGGLE
from app.services import diagnostics, traffic

router = APIRouter()
_templates = Jinja2Templates(directory="app/web/templates")


# Audit events that don't count as "pending changes" (they don't alter the
# rendered ruleset / dnsmasq config).
_NON_MUTATIONS = (
    "apply.ok", "apply.fail",
    "login", "logout",
    "host.scan",
    "user.password_changed", "user.create", "user.delete", "user.reset_password",
)


def _pending_count(conn) -> int:
    """How many DB-state-changing actions sit between the last successful
    Apply and now. The topbar reads this to know whether to nag the user."""
    last_apply_id = conn.execute(
        "SELECT COALESCE(MAX(id), 0) AS i FROM audit_log WHERE action='apply.ok'"
    ).fetchone()["i"]
    placeholders = ",".join(["?"] * len(_NON_MUTATIONS))
    row = conn.execute(
        f"SELECT COUNT(*) AS c FROM audit_log "
        f"WHERE id > ? AND action NOT IN ({placeholders})",
        (last_apply_id, *_NON_MUTATIONS),
    ).fetchone()
    return int(row["c"])


def _tor_inconsistency(conn) -> str | None:
    """Return a human-readable warning when Tor service is OFF but at least one
    peer or host is still flagged tor_routed=1. Their traffic would be marked
    on next Apply and then dropped (TransPort isn't listening) — fail-closed
    by design but easy to miss."""
    if dbmod.get_setting(conn, "tor_enabled", "false") == "true":
        return None
    peer_count = conn.execute(
        "SELECT COUNT(*) AS c FROM peer_meta WHERE tor_routed=1"
    ).fetchone()["c"]
    host_count = conn.execute(
        "SELECT COUNT(*) AS c FROM internal_hosts WHERE tor_routed=1"
    ).fetchone()["c"]
    total = peer_count + host_count
    if total == 0:
        return None
    parts = []
    if peer_count: parts.append(f"{peer_count} peer{'s' if peer_count != 1 else ''}")
    if host_count: parts.append(f"{host_count} host{'s' if host_count != 1 else ''}")
    return (
        f"Tor service is disabled but { ' and '.join(parts) } are flagged to route via Tor. "
        f"Their traffic will be dropped after Apply — turn the Tor service on in Settings."
    )


def _flags(request: Request) -> dict:
    conn = request.app.state.db
    return {
        "dirty": dbmod.is_dirty(conn),
        "last_error": getattr(request.app.state, "last_error", None),
        "gateway_name": request.app.state.cfg.gateway_name,
        "pending_count": _pending_count(conn),
        "tor_warning": _tor_inconsistency(conn),
    }


# --------- Overview ---------

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

    # Traffic totals + last-24h sparkline per relevant interface.
    totals = traffic.proc_totals()
    iface_cards = []
    for name in (cfg.wan_iface, cfg.lan_iface, "wg0"):
        t = totals.get(name)
        if not t:
            continue
        history = traffic.vnstat_hourly(name, hours=24)
        iface_cards.append({
            "name": name,
            "rx_total": t["rx_bytes"],
            "tx_total": t["tx_bytes"],
            "rx_series": ",".join(str(h["rx"]) for h in history),
            "tx_series": ",".join(str(h["tx"]) for h in history),
            "has_history": bool(history),
        })

    # Tor pipeline health (only show the card if Tor is enabled or any
    # peer/host has tor_routed=1 — otherwise it's noise on the dashboard).
    show_tor_health = settings.get("tor_enabled") or _tor_inconsistency(conn) is not None
    tor_checks = diagnostics.tor_health(cfg.tor_trans_port) if show_tor_health else []

    return _templates.TemplateResponse("dashboard.html", {
        "request": request, "user": user,
        "settings": settings, "services": services,
        "wan_iface": cfg.wan_iface, "lan_iface": cfg.lan_iface,
        "lan_cidr": cfg.lan_cidr, "wg_peer_cidr": cfg.wg_peer_cidr,
        "iface_cards": iface_cards,
        "tor_checks": tor_checks,
        **_flags(request),
    })


# --------- Peers ---------

@router.get("/peers", response_class=HTMLResponse)
def peers_view(request: Request, user: str = Depends(require_user)):
    conn = request.app.state.db
    cfg = request.app.state.cfg
    peers = list_peers_with_meta(conn, cfg)
    now = int(datetime.now(timezone.utc).timestamp())
    for p in peers:
        p["handshake_age"] = (now - p["last_handshake"]) if p["last_handshake"] else None
    flash = getattr(request.app.state, "peer_flash", None)
    request.app.state.peer_flash = None
    return _templates.TemplateResponse("peers.html", {
        "request": request, "user": user, "peers": peers,
        "peer_flash": flash, **_flags(request),
    })


@router.get("/peers/{pubkey}/acl", response_class=HTMLResponse)
def acl_view(pubkey: str, request: Request, user: str = Depends(require_user)):
    conn = request.app.state.db
    rules = [dict(r) for r in conn.execute(
        "SELECT * FROM acl_rules WHERE peer_pubkey=? ORDER BY id", (pubkey,)
    )]
    label_row = conn.execute(
        "SELECT label FROM peer_meta WHERE pubkey=?", (pubkey,)
    ).fetchone()
    label = label_row["label"] if label_row else ""
    return _templates.TemplateResponse("acl.html", {
        "request": request, "user": user,
        "pubkey": pubkey, "label": label, "rules": rules,
        **_flags(request),
    })


# --------- Hosts ---------

@router.get("/hosts", response_class=HTMLResponse)
def hosts_view(request: Request, user: str = Depends(require_user)):
    conn = request.app.state.db
    rows = [dict(r) for r in conn.execute("SELECT * FROM internal_hosts ORDER BY ip")]
    return _templates.TemplateResponse("hosts.html", {
        "request": request, "user": user, "hosts": rows, **_flags(request),
    })


# --------- LAN egress ---------

@router.get("/lan-egress", response_class=HTMLResponse)
def lan_egress_view(request: Request, user: str = Depends(require_user)):
    conn = request.app.state.db
    cfg = request.app.state.cfg
    subnets = [dict(r) for r in conn.execute(
        "SELECT * FROM lan_restricted_subnets ORDER BY cidr"
    )]
    rules = [dict(r) for r in conn.execute(
        "SELECT * FROM lan_egress_rules ORDER BY dst_cidr, dport"
    )]
    return _templates.TemplateResponse("lan_egress.html", {
        "request": request, "user": user,
        "subnets": subnets, "rules": rules,
        "lan_iface": cfg.lan_iface, "lan_cidr": cfg.lan_cidr,
        "wan_iface": cfg.wan_iface,
        **_flags(request),
    })


# --------- Users ---------

@router.get("/users", response_class=HTMLResponse)
def users_view(request: Request, user: str = Depends(require_user)):
    conn = request.app.state.db
    rows = [dict(r) for r in conn.execute(
        "SELECT username, role, created_at FROM users ORDER BY username"
    )]
    flash = getattr(request.app.state, "users_flash", None)
    request.app.state.users_flash = None
    return _templates.TemplateResponse("users.html", {
        "request": request, "user": user,
        "users": rows, "users_flash": flash,
        **_flags(request),
    })


# --------- Settings ---------

@router.get("/settings", response_class=HTMLResponse)
def settings_view(request: Request, user: str = Depends(require_user)):
    conn = request.app.state.db
    settings = {
        k: dbmod.get_setting(conn, k, "false") == "true"
        for k in _SERVICE_FOR_TOGGLE
    }
    flash = getattr(request.app.state, "password_flash", None)
    request.app.state.password_flash = None
    return _templates.TemplateResponse("settings.html", {
        "request": request, "user": user, "settings": settings,
        "password_flash": flash, **_flags(request),
    })


# --------- Audit (paginated + filterable) ---------

_PER_PAGE = 50


@router.get("/audit", response_class=HTMLResponse)
def audit_view(
    request: Request,
    user: str = Depends(require_user),
    page: int = 1,
    actor: str = "",
    action: str = "",
    q: str = "",
):
    conn = request.app.state.db
    page = max(1, page)

    where_clauses: list[str] = []
    params: list = []
    if actor:
        where_clauses.append("actor = ?")
        params.append(actor)
    if action:
        where_clauses.append("action LIKE ?")
        params.append(action + "%")
    if q:
        where_clauses.append("(target LIKE ? OR detail LIKE ?)")
        params.extend([f"%{q}%", f"%{q}%"])
    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    total = conn.execute(
        f"SELECT COUNT(*) AS c FROM audit_log {where_sql}", params
    ).fetchone()["c"]

    rows = [dict(r) for r in conn.execute(
        f"SELECT * FROM audit_log {where_sql} ORDER BY id DESC LIMIT ? OFFSET ?",
        params + [_PER_PAGE, (page - 1) * _PER_PAGE],
    )]

    actors = [r["actor"] for r in conn.execute(
        "SELECT DISTINCT actor FROM audit_log ORDER BY actor"
    )]
    # Distinct top-level action prefixes (e.g. "peer", "acl", "host", "apply").
    action_prefixes = sorted({
        r["action"].split(".", 1)[0]
        for r in conn.execute("SELECT DISTINCT action FROM audit_log")
    })

    pages = max(1, (total + _PER_PAGE - 1) // _PER_PAGE)
    return _templates.TemplateResponse("audit.html", {
        "request": request, "user": user, "rows": rows,
        "page": page, "pages": pages, "total": total, "per_page": _PER_PAGE,
        "filter_actor": actor, "filter_action": action, "filter_q": q,
        "actors": actors, "action_prefixes": action_prefixes,
        **_flags(request),
    })
