"""Read live WireGuard state via `wg show wg0 dump`. Source of truth for peers."""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import List


@dataclass
class WGPeer:
    pubkey: str
    endpoint: str            # "ip:port" or "(none)"
    allowed_ips: str         # "10.66.66.5/32"
    last_handshake: int      # epoch seconds, 0 = never
    rx_bytes: int
    tx_bytes: int
    persistent_keepalive: int

    @property
    def peer_ip(self) -> str:
        first = self.allowed_ips.split(",")[0].strip()
        return first.split("/")[0]


def list_peers(cmd: tuple = ("wg", "show", "wg0", "dump")) -> List[WGPeer]:
    """`wg show <if> dump` first line is the interface; rest are peers."""
    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []

    peers: List[WGPeer] = []
    for i, line in enumerate(out.splitlines()):
        if i == 0:
            continue  # interface line
        parts = line.split("\t")
        if len(parts) < 8:
            continue
        peers.append(WGPeer(
            pubkey=parts[0],
            endpoint=parts[2],
            allowed_ips=parts[3],
            last_handshake=int(parts[4]) if parts[4].isdigit() else 0,
            rx_bytes=int(parts[5]) if parts[5].isdigit() else 0,
            tx_bytes=int(parts[6]) if parts[6].isdigit() else 0,
            persistent_keepalive=int(parts[7]) if parts[7].isdigit() else 0,
        ))
    return peers
