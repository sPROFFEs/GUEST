"""Render config from DB and reload services. Atomic, validated."""
from __future__ import annotations

import shutil
import sqlite3
import subprocess
import time
from pathlib import Path
from typing import Tuple

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.config import Config
from app import db as dbmod


_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates_cfg"
_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATES_DIR)),
    autoescape=select_autoescape([]),
    keep_trailing_newline=True,
)


class ApplyError(RuntimeError):
    pass


def _peers_meta(conn: sqlite3.Connection) -> dict:
    rows = conn.execute("SELECT pubkey, label, blocked, tor_routed FROM peer_meta").fetchall()
    return {r["pubkey"]: dict(r) for r in rows}


def _peer_ip_for(pubkey: str, allowed_ips_by_pk: dict) -> str | None:
    a = allowed_ips_by_pk.get(pubkey)
    if not a:
        return None
    first = a.split(",")[0].strip().split("/")[0]
    return first or None


def render(conn: sqlite3.Connection, cfg: Config) -> Tuple[str, str]:
    """Render nft fragment + dnsmasq hosts file as strings."""
    from app.services.wg_sync import list_peers
    peers = list_peers(cfg.wg_show_cmd)
    allowed_by_pk = {p.pubkey: p.allowed_ips for p in peers}

    meta = _peers_meta(conn)

    blocked_peer_ips: list[str] = []
    tor_peer_ips: list[str] = []
    for pk, m in meta.items():
        ip = _peer_ip_for(pk, allowed_by_pk)
        if not ip:
            continue
        if m["blocked"]:
            blocked_peer_ips.append(ip)
        if m["tor_routed"]:
            tor_peer_ips.append(ip)

    hosts = conn.execute(
        "SELECT mac, ip, hostname, static, blocked, tor_routed FROM internal_hosts"
    ).fetchall()
    blocked_host_ips = [h["ip"] for h in hosts if h["blocked"] and h["ip"]]
    tor_host_ips     = [h["ip"] for h in hosts if h["tor_routed"] and h["ip"]]
    static_hosts = [
        {"mac": h["mac"], "ip": h["ip"], "hostname": h["hostname"] or ""}
        for h in hosts if h["static"] and h["ip"]
    ]

    # ACL rules: peer pubkey -> peer IP -> rule list
    acls = []
    for r in conn.execute(
        "SELECT peer_pubkey, dst_cidr, proto, dport, action "
        "FROM acl_rules WHERE enabled=1"
    ).fetchall():
        ip = _peer_ip_for(r["peer_pubkey"], allowed_by_pk)
        if not ip:
            continue
        acls.append({
            "src_ip": ip,
            "dst_cidr": r["dst_cidr"],
            "proto": r["proto"],
            "dport": r["dport"],
            "action": r["action"],
        })

    nft_text = _env.get_template("nftables.j2").render(
        blocked_peer_ips=blocked_peer_ips,
        tor_peer_ips=tor_peer_ips,
        blocked_host_ips=blocked_host_ips,
        tor_host_ips=tor_host_ips,
        acls=acls,
    )
    dnsmasq_text = _env.get_template("dnsmasq.j2").render(
        static_hosts=static_hosts,
    )
    return nft_text, dnsmasq_text


def _snapshot(cfg: Config) -> Path:
    ts = time.strftime("%Y%m%d-%H%M%S")
    snap = cfg.snapshots_dir / ts
    snap.mkdir(parents=True, exist_ok=True)
    for src in (cfg.nft_panel_fragment, cfg.dnsmasq_hosts):
        if src.exists():
            shutil.copy2(src, snap / src.name)
    return snap


def _write_via_sudo(staged: Path, dst: Path) -> None:
    # The sudoers drop-in lets us install files from /var/lib/gateway/render/.
    subprocess.run(
        ["sudo", "/usr/bin/install", "-m", "0644", str(staged), str(dst)],
        check=True,
    )


def apply(conn: sqlite3.Connection, cfg: Config, actor: str) -> None:
    nft_text, dnsmasq_text = render(conn, cfg)

    cfg.render_dir.mkdir(parents=True, exist_ok=True)
    nft_staged = cfg.render_dir / "50-panel.nft.new"
    dns_staged = cfg.render_dir / "gateway-hosts.conf.new"
    nft_staged.write_text(nft_text)
    dns_staged.write_text(dnsmasq_text)

    # Validate: write nft to a temp path inside /etc/nftables.d (so the include
    # picks it up) and run `nft -c -f` against the full ruleset.
    snap = _snapshot(cfg)
    try:
        _write_via_sudo(nft_staged, cfg.nft_panel_fragment)
        _write_via_sudo(dns_staged, cfg.dnsmasq_hosts)

        subprocess.run(
            ["sudo", "/usr/sbin/nft", "-c", "-f", "/etc/nftables.conf"],
            check=True, capture_output=True, text=True,
        )
        subprocess.run(
            ["sudo", "/usr/sbin/nft", "-f", "/etc/nftables.conf"],
            check=True, capture_output=True, text=True,
        )
        subprocess.run(
            ["sudo", "/bin/systemctl", "restart", "dnsmasq"],
            check=True, capture_output=True, text=True,
        )
    except subprocess.CalledProcessError as e:
        # Rollback from snapshot
        for name in ("50-panel.nft", "gateway-hosts.conf"):
            saved = snap / name
            target = cfg.nft_panel_fragment if name.endswith(".nft") else cfg.dnsmasq_hosts
            if saved.exists():
                _write_via_sudo(saved, target)
        subprocess.run(["sudo", "/usr/sbin/nft", "-f", "/etc/nftables.conf"], check=False)
        subprocess.run(["sudo", "/bin/systemctl", "restart", "dnsmasq"], check=False)
        dbmod.audit(conn, actor, "apply.fail", detail=(e.stderr or str(e))[:500])
        raise ApplyError(e.stderr or str(e)) from e

    dbmod.audit(conn, actor, "apply.ok", target=str(snap))
    dbmod.mark_clean(conn)
