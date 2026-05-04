"""Discover hosts on the LAN-internal interface and persist them.

Strategy: parse `ip neigh show dev <lan>`. Hosts marked REACHABLE/STALE/DELAY
are present; FAILED entries are kept until they age out.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from typing import List


_LINE = re.compile(
    r"^(?P<ip>\S+)\s+lladdr\s+(?P<mac>[0-9a-f:]{17})\s+(?P<state>\w+)",
    re.IGNORECASE,
)


@dataclass
class Neighbor:
    ip: str
    mac: str
    state: str


def scan(lan_iface: str) -> List[Neighbor]:
    try:
        out = subprocess.check_output(
            ["ip", "-4", "neigh", "show", "dev", lan_iface],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []

    seen: List[Neighbor] = []
    for line in out.splitlines():
        m = _LINE.match(line.strip())
        if m and m.group("state").upper() in {"REACHABLE", "STALE", "DELAY", "PROBE"}:
            seen.append(Neighbor(
                ip=m.group("ip"),
                mac=m.group("mac").lower(),
                state=m.group("state").upper(),
            ))
    return seen


def upsert_into_db(conn, neighbors: List[Neighbor]) -> None:
    """Update internal_hosts with what we just saw. Existing rows keep their
    metadata (label, blocked, tor_routed, static); only ip/last_seen update."""
    for n in neighbors:
        conn.execute(
            "INSERT INTO internal_hosts(mac, ip, last_seen) "
            "VALUES(?, ?, datetime('now')) "
            "ON CONFLICT(mac) DO UPDATE SET ip=excluded.ip, last_seen=excluded.last_seen",
            (n.mac, n.ip),
        )
