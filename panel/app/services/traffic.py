"""Traffic stats from /proc/net/dev (instantaneous totals) and vnstat (history).

Both sources are best-effort — if vnstat isn't installed (monitoring module
disabled), we still return per-interface totals from /proc.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any


PROC_NET_DEV = Path("/proc/net/dev")


def proc_totals() -> dict[str, dict[str, int]]:
    """Parse /proc/net/dev. Returns {iface: {rx_bytes, tx_bytes}}."""
    out: dict[str, dict[str, int]] = {}
    if not PROC_NET_DEV.exists():
        return out
    text = PROC_NET_DEV.read_text()
    for line in text.splitlines()[2:]:
        if ":" not in line:
            continue
        name, rest = line.split(":", 1)
        name = name.strip()
        fields = rest.split()
        if len(fields) < 9:
            continue
        # rx_bytes is column 0, tx_bytes is column 8 (0-indexed)
        try:
            out[name] = {"rx_bytes": int(fields[0]), "tx_bytes": int(fields[8])}
        except ValueError:
            continue
    return out


def vnstat_hourly(iface: str, hours: int = 24) -> list[dict[str, Any]]:
    """Last N hourly samples for `iface` from vnstat. Returns [] if unavailable.

    Each entry: {"label": "HH:MM", "rx": int_bytes, "tx": int_bytes}
    """
    try:
        raw = subprocess.check_output(
            ["vnstat", "-i", iface, "--json", "h"],
            stderr=subprocess.DEVNULL, text=True, timeout=3,
        )
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []

    interfaces = data.get("interfaces", [])
    if not interfaces:
        return []
    iface_data = next((i for i in interfaces if i.get("name") == iface), interfaces[0])
    hourly = (iface_data.get("traffic") or {}).get("hour", [])
    samples = hourly[-hours:]

    out = []
    for s in samples:
        t = s.get("time", {})
        out.append({
            "label": f"{t.get('hour', 0):02d}:{t.get('minute', 0):02d}",
            "rx": int(s.get("rx", 0)),
            "tx": int(s.get("tx", 0)),
        })
    return out
