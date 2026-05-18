"""LAN-internal host listing + per-host toggles + static-lease editing."""
from __future__ import annotations

import ipaddress
import logging
import re
import subprocess

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse

from app import db as dbmod
from app.auth import require_user

router = APIRouter()
log = logging.getLogger("gateway.hosts")

_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def _normalize_mac(value: str) -> str:
    mac = (value or "").strip().lower()
    if not _MAC_RE.match(mac):
        raise HTTPException(400, "bad mac")
    return mac


def _normalize_ipv4(value: str) -> str:
    try:
        return str(ipaddress.IPv4Address((value or "").strip()))
    except ValueError:
        raise HTTPException(400, "bad ip")


def _normalize_hostname(value: str) -> str:
    hostname = (value or "").strip()
    if not hostname:
        return ""
    if "," in hostname or "\n" in hostname or "\r" in hostname:
        raise HTTPException(400, "bad hostname")
    if not _HOSTNAME_RE.match(hostname):
        raise HTTPException(400, "bad hostname")
    return hostname


def _release_lease(lan_iface: str, ip: str, mac: str) -> None:
    """Tell dnsmasq to forget the lease for this host. Best-effort — if it
    fails (no active lease, or dhcp_release missing) we don't surface an
    error because the goal is just to keep the lease file from re-spawning
    the host on the next scan."""
    if not (lan_iface and ip and mac):
        return
    try:
        subprocess.run(
            ["sudo", "/usr/local/sbin/gateway-dhcp-release", lan_iface, ip, mac],
            check=False, capture_output=True, timeout=3,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        log.info("dhcp_release skipped: %s", e)


@router.get("/api/hosts")
def api_list(request: Request, user: str = Depends(require_user)):
    conn = request.app.state.db
    rows = conn.execute("SELECT * FROM internal_hosts ORDER BY ip").fetchall()
    return {"hosts": [dict(r) for r in rows]}


@router.post("/hosts/scan")
def scan_now(request: Request, user: str = Depends(require_user)):
    """Run the scanner inline (no waiting for the systemd timer)."""
    from app.services.scanner import scan, upsert_into_db
    conn = request.app.state.db
    cfg = request.app.state.cfg
    discoveries = scan(cfg.lan_iface)
    with dbmod.transaction(conn):
        upsert_into_db(conn, discoveries)
        dbmod.audit(conn, user, "host.scan", detail=f"{len(discoveries)} found")
    return RedirectResponse(url="/hosts", status_code=303)


@router.post("/hosts")
def create(
    mac: str = Form(...),
    ip: str = Form(...),
    hostname: str = Form(""),
    request: Request = None,
    user: str = Depends(require_user),
):
    mac = _normalize_mac(mac)
    ip = _normalize_ipv4(ip)
    hostname = _normalize_hostname(hostname)
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
    mac = _normalize_mac(mac)
    conn = request.app.state.db
    with dbmod.transaction(conn):
        conn.execute(
            f"UPDATE internal_hosts SET {field} = 1 - {field} WHERE mac=?",
            (mac,),
        )
        dbmod.mark_dirty(conn)
        dbmod.audit(conn, user, f"host.toggle.{field}", target=mac)
    return RedirectResponse(url="/hosts", status_code=303)


@router.post("/hosts/{mac}/ip")
def set_ip(mac: str, ip: str = Form(...), request: Request = None, user: str = Depends(require_user)):
    mac = _normalize_mac(mac)
    ip = _normalize_ipv4(ip)
    conn = request.app.state.db
    with dbmod.transaction(conn):
        conn.execute(
            "UPDATE internal_hosts SET ip=?, static=1 WHERE mac=?",
            (ip, mac),
        )
        dbmod.mark_dirty(conn)
        dbmod.audit(conn, user, "host.ip", target=mac, detail=ip)
    return RedirectResponse(url="/hosts", status_code=303)


@router.post("/hosts/{mac}/delete")
def delete(mac: str, request: Request, user: str = Depends(require_user)):
    conn = request.app.state.db
    cfg = request.app.state.cfg
    mac = _normalize_mac(mac)

    # Look up the IP we know about so we can release its lease, otherwise the
    # next scanner pass would just re-import the host from dnsmasq.leases.
    row = conn.execute("SELECT ip FROM internal_hosts WHERE mac=?", (mac,)).fetchone()
    ip = row["ip"] if row and row["ip"] else None

    with dbmod.transaction(conn):
        conn.execute("DELETE FROM internal_hosts WHERE mac=?", (mac,))
        dbmod.mark_dirty(conn)
        dbmod.audit(conn, user, "host.delete", target=mac, detail=ip or "")

    _release_lease(cfg.lan_iface, ip, mac)
    return RedirectResponse(url="/hosts", status_code=303)


@router.post("/hosts/reset")
def reset_lan_state(request: Request, user: str = Depends(require_user)):
    """Hard wipe of LAN-side state: drops every internal_hosts row, truncates
    the dnsmasq lease file and our static-reservations file, and bounces
    dnsmasq. Intended for "I just cloned this VM and want a clean slate".

    Does NOT touch peer ACLs, peer metadata, lan_egress rules, or audit log."""
    conn = request.app.state.db

    with dbmod.transaction(conn):
        n = conn.execute("SELECT COUNT(*) AS c FROM internal_hosts").fetchone()["c"]
        conn.execute("DELETE FROM internal_hosts")
        dbmod.mark_dirty(conn)
        dbmod.audit(
            conn, user, "host.reset",
            detail=f"wiped {n} hosts, leases, and reservations",
        )

    # Stop dnsmasq, truncate state files, restart. If the helper is missing
    # (older install before this feature), fall back to a manual best-effort.
    try:
        subprocess.run(
            ["sudo", "/usr/local/sbin/gateway-lan-reset"],
            check=True, capture_output=True, timeout=10,
        )
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        log.warning("gateway-lan-reset wrapper failed: %s", e)
        request.app.state.last_error = (
            "Reset wiped the database, but could not bounce dnsmasq cleanly. "
            "Run `sudo systemctl restart dnsmasq` from the VM."
        )

    return RedirectResponse(url="/hosts", status_code=303)
