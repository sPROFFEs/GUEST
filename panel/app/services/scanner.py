"""Discover hosts on the LAN-internal interface.

Two sources, in order of authority:

1. **dnsmasq leases** (`/var/lib/misc/dnsmasq.leases`) — every host we handed
   an IP to. Format: `expiry mac ip hostname client_id`. This is the source of
   truth for DHCP clients. Hosts only appear once they've ACK'd a lease.

2. **`ip neigh show dev <lan>`** — kernel neighbor table. Catches hosts with
   static IPs (no DHCP lease) that the gateway has talked to. Adds rows that
   leases miss.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
import subprocess
from typing import List


_NEIGH_LINE = re.compile(
    r"^(?P<ip>\S+)\s+lladdr\s+(?P<mac>[0-9a-f:]{17})\s+(?P<state>\w+)",
    re.IGNORECASE,
)

DNSMASQ_LEASES = Path("/var/lib/misc/dnsmasq.leases")


@dataclass
class Discovery:
    mac: str
    ip: str
    hostname: str = ""
    source: str = "neigh"   # "lease" | "neigh"


def _from_leases() -> List[Discovery]:
    if not DNSMASQ_LEASES.exists():
        return []
    out: List[Discovery] = []
    for line in DNSMASQ_LEASES.read_text().splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        # parts: <expiry> <mac> <ip> <hostname or *> <client_id or *>
        _, mac, ip, hostname = parts[0], parts[1].lower(), parts[2], parts[3]
        if hostname == "*":
            hostname = ""
        out.append(Discovery(mac=mac, ip=ip, hostname=hostname, source="lease"))
    return out


def _from_neigh(lan_iface: str) -> List[Discovery]:
    try:
        out = subprocess.check_output(
            ["ip", "-4", "neigh", "show", "dev", lan_iface],
            text=True, stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    discovered: List[Discovery] = []
    for line in out.splitlines():
        m = _NEIGH_LINE.match(line.strip())
        if not m:
            continue
        if m.group("state").upper() not in {"REACHABLE", "STALE", "DELAY", "PROBE"}:
            continue
        discovered.append(Discovery(
            mac=m.group("mac").lower(),
            ip=m.group("ip"),
            source="neigh",
        ))
    return discovered


def scan(lan_iface: str) -> List[Discovery]:
    """Merged view: leases first, then neigh entries we don't already have."""
    by_mac: dict[str, Discovery] = {}
    for d in _from_leases():
        by_mac[d.mac] = d
    for d in _from_neigh(lan_iface):
        # Only add if not already present from leases (leases are richer).
        by_mac.setdefault(d.mac, d)
    return list(by_mac.values())


def upsert_into_db(conn, discoveries: List[Discovery]) -> None:
    """Update internal_hosts. Existing rows keep their toggles (blocked,
    tor_routed, static, notes) and label; only ip/hostname/last_seen change."""
    for d in discoveries:
        # If the panel/operator has already set a hostname, don't overwrite it
        # with an empty one from neigh — only the lease source provides one.
        if d.hostname:
            conn.execute(
                "INSERT INTO internal_hosts(mac, ip, hostname, last_seen) "
                "VALUES(?, ?, ?, datetime('now')) "
                "ON CONFLICT(mac) DO UPDATE SET "
                "  ip=excluded.ip, "
                "  hostname=COALESCE(NULLIF(internal_hosts.hostname,''), excluded.hostname), "
                "  last_seen=excluded.last_seen",
                (d.mac, d.ip, d.hostname),
            )
        else:
            conn.execute(
                "INSERT INTO internal_hosts(mac, ip, last_seen) "
                "VALUES(?, ?, datetime('now')) "
                "ON CONFLICT(mac) DO UPDATE SET "
                "  ip=excluded.ip, last_seen=excluded.last_seen",
                (d.mac, d.ip),
            )
