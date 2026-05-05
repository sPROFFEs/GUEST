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


def _peer_ips_for(pubkey: str, allowed_ips_by_pk: dict) -> list[str]:
    """Every IPv4 the peer is allowed on. Empty if the peer isn't in wg show
    (e.g. configured but never handshaked, or pubkey mismatch)."""
    a = allowed_ips_by_pk.get(pubkey, "")
    out: list[str] = []
    for chunk in a.split(","):
        chunk = chunk.strip()
        if not chunk or ":" in chunk:   # skip empties and IPv6
            continue
        ip = chunk.split("/")[0]
        if ip:
            out.append(ip)
    return out


def render(conn: sqlite3.Connection, cfg: Config) -> Tuple[str, str]:
    """Render nft fragment + dnsmasq hosts file as strings."""
    from app.services.wg_sync import list_peers
    peers = list_peers(cfg.wg_show_cmd)
    allowed_by_pk = {p.pubkey: p.allowed_ips for p in peers}

    meta = _peers_meta(conn)

    blocked_peer_ips: list[str] = []
    tor_peer_ips: list[str] = []
    for pk, m in meta.items():
        ips = _peer_ips_for(pk, allowed_by_pk)
        if not ips:
            continue
        if m["blocked"]:
            blocked_peer_ips.extend(ips)
        if m["tor_routed"]:
            tor_peer_ips.extend(ips)

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
        ips = _peer_ips_for(r["peer_pubkey"], allowed_by_pk)
        for ip in ips:
            acls.append({
                "src_ip": ip,
                "dst_cidr": r["dst_cidr"],
                "proto": r["proto"],
                "dport": r["dport"],
                "action": r["action"],
            })

    # LAN egress: restricted subnets + allowlist exceptions
    restricted = [
        r["cidr"] for r in conn.execute(
            "SELECT cidr FROM lan_restricted_subnets WHERE enabled=1"
        ).fetchall()
    ]
    egress_allow = [
        {"dst_cidr": r["dst_cidr"], "proto": r["proto"], "dport": r["dport"]}
        for r in conn.execute(
            "SELECT dst_cidr, proto, dport FROM lan_egress_rules WHERE enabled=1"
        ).fetchall()
    ]

    nft_text = _env.get_template("nftables.j2").render(
        blocked_peer_ips=blocked_peer_ips,
        tor_peer_ips=tor_peer_ips,
        blocked_host_ips=blocked_host_ips,
        tor_host_ips=tor_host_ips,
        acls=acls,
        lan_restricted=restricted,
        lan_egress_allow=egress_allow,
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
    """Render config from DB, validate, swap, reload. Rolls back on failure.

    Failure modes (in order of likelihood):
      A. Render produced syntactically invalid nft (caught by standalone -c).
         → nothing touched, raise.
      B. Render is valid alone but the merged ruleset fails (caught by full -c).
         → nothing touched, raise.
      C. Apply succeeded but reload threw an unexpected error after the swap.
         → restore from snapshot, reload again, raise.
    """
    import logging
    log = logging.getLogger("gateway.apply")

    nft_text, dnsmasq_text = render(conn, cfg)

    cfg.render_dir.mkdir(parents=True, exist_ok=True)
    nft_staged = cfg.render_dir / "50-panel.nft.new"
    dns_staged = cfg.render_dir / "gateway-hosts.conf.new"
    nft_staged.write_text(nft_text)
    dns_staged.write_text(dnsmasq_text)

    # --- (A) Standalone syntax check on the rendered fragment ------------
    # Best-effort: catches obvious render mistakes (bad CIDR, malformed
    # rule) BEFORE we touch /etc/nftables.d/. If the pre-check itself can't
    # run (e.g. older sudoers without the wildcard for staged paths, or nft
    # rejecting an isolated fragment that references an existing chain), we
    # log and continue — the full ruleset validate post-swap is the real
    # safety net.
    pre = subprocess.run(
        ["sudo", "/usr/sbin/nft", "-c", "-f", str(nft_staged)],
        capture_output=True, text=True,
    )
    if pre.returncode != 0:
        stderr = (pre.stderr or pre.stdout or "").strip()
        looks_like_perm = (
            "password is required" in stderr
            or "a terminal is required" in stderr
            or "not allowed" in stderr.lower()
        )
        looks_like_render_bug = (
            "syntax error" in stderr.lower()
            or "Error: " in stderr
        )
        if looks_like_render_bug and not looks_like_perm:
            log.warning("apply pre-check rejected the render: %s", stderr)
            dbmod.audit(conn, actor, "apply.fail", detail=("[pre-check] " + stderr)[:500])
            raise ApplyError(f"Pre-check failed (nothing changed): {stderr}")
        log.info("apply pre-check skipped: %s", stderr[:200])

    snap = _snapshot(cfg)
    try:
        # --- swap into production ---
        _write_via_sudo(nft_staged, cfg.nft_panel_fragment)
        _write_via_sudo(dns_staged, cfg.dnsmasq_hosts)

        # --- (B) full-ruleset validate + (C) actual reload ---
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
        msg = (e.stderr or e.stdout or str(e)).strip()
        log.error("apply failed post-swap, rolling back: %s", msg)
        # restore each saved file (snapshot may be empty if first run)
        for name, target in (
            ("50-panel.nft", cfg.nft_panel_fragment),
            ("gateway-hosts.conf", cfg.dnsmasq_hosts),
        ):
            saved = snap / name
            if saved.exists():
                _write_via_sudo(saved, target)
        # best-effort reload; don't mask the original error
        subprocess.run(["sudo", "/usr/sbin/nft", "-f", "/etc/nftables.conf"],
                       check=False, capture_output=True)
        subprocess.run(["sudo", "/bin/systemctl", "restart", "dnsmasq"],
                       check=False, capture_output=True)
        dbmod.audit(conn, actor, "apply.fail", detail=("[post-swap] " + msg)[:500])
        raise ApplyError(msg) from e

    log.info("apply ok, snapshot=%s", snap)
    dbmod.audit(conn, actor, "apply.ok", target=str(snap))
    dbmod.mark_clean(conn)
