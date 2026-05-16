"""Configuration loaded from env + gateway.toml."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore


@dataclass(frozen=True)
class Config:
    db_path: Path
    toml_path: Path
    bind_addr: str
    bind_port: int

    # Loaded from gateway.toml
    gateway_name: str
    wan_iface: str
    lan_iface: str
    lan_cidr: str
    wg_listen_port: int
    wg_peer_cidr: str
    dhcp_range: str
    tor_trans_port: int
    tor_dns_port: int

    # Paths the panel writes / reads
    render_dir: Path = Path("/var/lib/gateway/render")
    snapshots_dir: Path = Path("/var/lib/gateway/snapshots")
    nft_main: Path = Path("/etc/nftables.conf")
    nft_panel_fragment: Path = Path("/etc/nftables.d/50-panel.nft")
    dnsmasq_hosts: Path = Path("/etc/dnsmasq.d/gateway-hosts.conf")
    wg_show_cmd: tuple = ("wg", "show", "wg0", "dump")


def load() -> Config:
    db_path = Path(os.environ.get("GATEWAY_DB", "/var/lib/gateway/db.sqlite"))
    toml_path = Path(os.environ.get("GATEWAY_TOML", "/etc/gateway/gateway.toml"))
    bind_addr = os.environ.get("GATEWAY_BIND_ADDR", "127.0.0.1")
    bind_port = int(os.environ.get("GATEWAY_BIND_PORT", "8443"))

    with open(toml_path, "rb") as f:
        t = tomllib.load(f)

    return Config(
        db_path=db_path,
        toml_path=toml_path,
        bind_addr=bind_addr,
        bind_port=bind_port,
        gateway_name=t["gateway"]["name"],
        wan_iface=t["gateway"]["wan_iface"],
        lan_iface=t["gateway"]["lan_iface"],
        lan_cidr=t["gateway"]["lan_cidr"],
        wg_listen_port=int(t["wireguard"]["listen_port"]),
        wg_peer_cidr=t["wireguard"]["peer_cidr"],
        dhcp_range=t["dhcp"]["range"],
        tor_trans_port=int(t.get("tor", {}).get("trans_port", 9040)),
        tor_dns_port=int(t.get("tor", {}).get("dns_port", 5353)),
    )
