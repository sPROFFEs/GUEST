#!/usr/bin/env bash
# 20-wireguard: WireGuard server + WGDashboard, both bound to wg0 only.
# Idempotent.
set -euo pipefail

: "${GATEWAY_LAN_IFACE:?}"
: "${WIREGUARD_LISTEN_PORT:?}"
: "${WIREGUARD_PEER_CIDR:?}"
: "${PANEL_WGD_BIND_ADDR:?}"
: "${PANEL_WGD_BIND_PORT:?}"

export DEBIAN_FRONTEND=noninteractive
apt-get install -y --no-install-recommends wireguard wireguard-tools git >/dev/null

# --- Server keys (created once, never overwritten) ---
WG_DIR=/etc/wireguard
install -d -m 0700 "$WG_DIR"
if [[ ! -f "$WG_DIR/server.key" ]]; then
    umask 077
    wg genkey | tee "$WG_DIR/server.key" | wg pubkey > "$WG_DIR/server.pub"
fi
SRV_PRIV="$(cat "$WG_DIR/server.key")"

# --- wg0 server address: first usable IP in the peer CIDR ---
SRV_IP="$(python3 -c "import ipaddress,sys; n=ipaddress.ip_network(sys.argv[1]); print(f'{next(n.hosts())}/{n.prefixlen}')" "$WIREGUARD_PEER_CIDR")"

# --- wg0.conf (only written if missing; WGDashboard then owns mutations) ---
if [[ ! -f "$WG_DIR/wg0.conf" ]]; then
    cat > "$WG_DIR/wg0.conf" <<EOF
# Managed by WGDashboard after install. Initial bootstrap by gateway installer.
[Interface]
PrivateKey = ${SRV_PRIV}
Address = ${SRV_IP}
ListenPort = ${WIREGUARD_LISTEN_PORT}
SaveConfig = true
EOF
    chmod 600 "$WG_DIR/wg0.conf"
fi

systemctl enable wg-quick@wg0 >/dev/null 2>&1 || true
systemctl restart wg-quick@wg0

# --- WGDashboard ---
WGD_DIR=/opt/wgdashboard
if [[ ! -d "$WGD_DIR/.git" ]]; then
    git clone --depth 1 https://github.com/donaldzou/WGDashboard.git "$WGD_DIR" >/dev/null
fi

# WGDashboard's installer creates its own venv under src/ and installs deps.
# We invoke it once; subsequent runs are no-ops thanks to its idempotency.
(
    cd "$WGD_DIR/src"
    chmod +x ./wgd.sh
    ./wgd.sh install >/dev/null 2>&1 || true
)

# Bind only on wg0. WGDashboard reads wg-dashboard.ini for app_ip/app_port.
WGD_INI="$WGD_DIR/src/wg-dashboard.ini"
if [[ -f "$WGD_INI" ]]; then
    python3 - "$WGD_INI" "$PANEL_WGD_BIND_ADDR" "$PANEL_WGD_BIND_PORT" <<'PY'
import configparser, sys
p, ip, port = sys.argv[1], sys.argv[2], sys.argv[3]
c = configparser.ConfigParser()
c.read(p)
if not c.has_section("Server"):
    c.add_section("Server")
c["Server"]["app_ip"] = ip
c["Server"]["app_port"] = port
with open(p, "w") as f:
    c.write(f)
PY
fi

# Systemd unit for WGDashboard (wgd.sh's own daemonization is fragile).
cat > /etc/systemd/system/wgdashboard.service <<EOF
[Unit]
Description=WGDashboard
After=network-online.target wg-quick@wg0.service
Wants=network-online.target
Requires=wg-quick@wg0.service

[Service]
Type=simple
WorkingDirectory=${WGD_DIR}/src
ExecStart=${WGD_DIR}/src/venv/bin/python ${WGD_DIR}/src/dashboard.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable wgdashboard >/dev/null 2>&1 || true
systemctl restart wgdashboard

# --- nftables fragment ---
# Open WG udp port on WAN, allow forward wg0 -> LAN (panel ACLs refine which
# peer can reach which host:port via panel_forward chain), and let peers reach
# the panel + WGDashboard locally on wg0.
cat > /etc/nftables.d/20-wireguard.nft <<EOF
# Managed by gateway installer (20-wireguard)
table inet gateway {
    chain input {
        # WG handshake/data on WAN
        udp dport ${WIREGUARD_LISTEN_PORT} accept
        # Local services reachable only via the WG tunnel
        iifname "wg0" tcp dport { ${PANEL_BIND_PORT}, ${PANEL_WGD_BIND_PORT} } accept
        iifname "wg0" udp dport 53 accept
        iifname "wg0" tcp dport 53 accept
    }

    chain forward {
        # Peers reach the LAN-internal subnet — but only what panel_forward allows.
        # The jump is added by 45-panel-chains.nft; without that fragment yet,
        # this stays as a permissive bootstrap so phase-2 testing works.
        iifname "wg0" oifname "${GATEWAY_LAN_IFACE}" ip saddr != @blocked_peers accept
    }
}
EOF

nft -c -f /etc/nftables.conf
systemctl reload nftables 2>/dev/null || nft -f /etc/nftables.conf

echo "[20-wireguard] ok — server ${SRV_IP}, listening udp/${WIREGUARD_LISTEN_PORT}, WGDashboard on ${PANEL_WGD_BIND_ADDR}:${PANEL_WGD_BIND_PORT}"
