"""Live health checks for the moving parts that aren't obvious from the UI.

Each check returns ("ok"|"warn"|"err", "human message"). Cheap subprocess
calls — runs on every dashboard render, not on a hot path."""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import List, Tuple


_PROC_NET_TCP = Path("/proc/net/tcp")


def _is_listening(port: int) -> bool:
    """True if any local IPv4 socket is in LISTEN state on `port`."""
    try:
        text = _PROC_NET_TCP.read_text()
    except OSError:
        return False
    hex_port = f"{port:04X}"
    # Format: sl  local_address  rem_address  st  …
    # local_address is "IP:PORT" hex; state 0A = LISTEN.
    for line in text.splitlines()[1:]:
        cols = line.split()
        if len(cols) < 4:
            continue
        local, state = cols[1], cols[3]
        if state.upper() == "0A" and local.endswith(":" + hex_port):
            return True
    return False


def _service_active(svc: str) -> bool:
    r = subprocess.run(
        ["sudo", "/bin/systemctl", "is-active", svc],
        capture_output=True, text=True,
    )
    return r.stdout.strip() == "active"


def _nft_set_count(set_name: str) -> int | None:
    r = subprocess.run(
        ["sudo", "/usr/sbin/nft", "list", "set", "inet", "gateway", set_name],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        return None
    # Count IPs in the set: anything looking like an IPv4 in the elements line.
    import re
    return len(re.findall(r"\b\d+\.\d+\.\d+\.\d+\b", r.stdout))


def _ip_rule_present() -> bool:
    r = subprocess.run(["ip", "rule"], capture_output=True, text=True)
    return "fwmark 0x1 lookup 100" in r.stdout


def _ip_route_present() -> bool:
    r = subprocess.run(["ip", "route", "show", "table", "100"],
                       capture_output=True, text=True)
    return "local default" in r.stdout


def tor_health(tor_trans_port: int = 9040) -> List[Tuple[str, str, str]]:
    """Returns a list of (name, level, message) tuples for the Tor pipeline."""
    out: List[Tuple[str, str, str]] = []

    if _service_active("tor"):
        out.append(("Tor service", "ok", "running"))
    else:
        out.append(("Tor service", "err", "not running — turn it on in Settings"))

    if _is_listening(tor_trans_port):
        out.append((f"TransPort :{tor_trans_port}", "ok", "listening"))
    else:
        out.append((f"TransPort :{tor_trans_port}", "err",
                    "not listening — Tor isn't ready to accept marked traffic"))

    if _ip_rule_present():
        out.append(("Policy route", "ok", "fwmark 0x1 → table 100"))
    else:
        out.append(("Policy route", "err",
                    "missing — run `sudo ./install.sh --module 30-tor`"))

    if _ip_route_present():
        out.append(("Tor route", "ok", "default via lo in table 100"))
    else:
        out.append(("Tor route", "err",
                    "missing — table 100 has no default route"))

    peers_n = _nft_set_count("tor_peers")
    hosts_n = _nft_set_count("tor_hosts")
    if peers_n is None or hosts_n is None:
        out.append(("nft sets", "err", "nft tor_peers / tor_hosts unreachable"))
    else:
        total = peers_n + hosts_n
        if total == 0:
            out.append(("nft sets", "warn",
                        "no peers or hosts marked for Tor — toggle one and Apply"))
        else:
            out.append(("nft sets", "ok",
                        f"{peers_n} peer(s) and {hosts_n} host(s) marked"))

    return out
