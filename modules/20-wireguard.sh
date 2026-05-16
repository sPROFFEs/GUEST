#!/usr/bin/env bash
# 20-wireguard: WireGuard server + WGDashboard, both bound to wg0 only.
# Idempotent.
set -euo pipefail

: "${GATEWAY_LAN_IFACE:?}"
: "${GATEWAY_WAN_IFACE:?}"
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
# Pinned to a stable tag. HEAD has been moving toward Python 3.12-only syntax
# (Amnezia modules use f-strings with backslashes), which breaks Debian 12's
# Python 3.11. Bump this when you've validated a newer release.
WGD_DIR=/opt/wgdashboard
WGD_TAG="${WGD_TAG:-v4.1.4}"
if [[ ! -d "$WGD_DIR/.git" ]]; then
    git clone --depth 1 --branch "$WGD_TAG" \
        https://github.com/donaldzou/WGDashboard.git "$WGD_DIR" >/dev/null
fi
# If a previous run cloned a different revision, force the pinned tag.
( cd "$WGD_DIR" && git fetch --tags --quiet && git checkout --quiet "$WGD_TAG" ) || \
    echo "WARN: could not switch /opt/wgdashboard to $WGD_TAG"

# Set up WGDashboard's venv manually. Their wgd.sh install script is fragile
# and fails silently on some Debian images (creates the wrapper but skips the
# venv). Doing it ourselves is one less moving part.
WGD_VENV="$WGD_DIR/src/venv"
WGD_REQ="$WGD_DIR/src/requirements.txt"
if [[ ! -x "$WGD_VENV/bin/python" ]]; then
    python3 -m venv "$WGD_VENV"
fi
"$WGD_VENV/bin/pip" install --upgrade pip
if [[ -f "$WGD_REQ" ]]; then
    "$WGD_VENV/bin/pip" install -r "$WGD_REQ"
else
    echo "WARN: $WGD_REQ not found; WGDashboard layout may have changed" >&2
fi

# Sanity check before declaring success.
"$WGD_VENV/bin/python" -c 'import flask' \
    || { echo "WGDashboard venv is incomplete (flask missing)"; exit 1; }

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
# WG udp port on WAN, services reachable on wg0 always, plus optionally on the
# WAN iface when [panel].expose_on_wan = true.
EXPOSE_WAN_RULE=""
if [[ "${PANEL_EXPOSE_ON_WAN:-false}" == "true" ]]; then
    EXPOSE_WAN_RULE="iifname \"${GATEWAY_WAN_IFACE}\" tcp dport { ${PANEL_BIND_PORT}, ${PANEL_WGD_BIND_PORT} } accept"
fi

cat > /etc/nftables.d/20-wireguard.nft <<EOF
# Managed by gateway installer (20-wireguard)
table inet gateway {
    chain input {
        # WG handshake/data on WAN
        udp dport ${WIREGUARD_LISTEN_PORT} accept
        # Panels reachable from inside the WG tunnel
        iifname "wg0" tcp dport { ${PANEL_BIND_PORT}, ${PANEL_WGD_BIND_PORT} } accept
        iifname "wg0" udp dport 53 accept
        iifname "wg0" tcp dport 53 accept
        ${EXPOSE_WAN_RULE}
    }

    chain forward {
        # Hard block always wins; panel ACLs cannot re-allow blocked peers.
        iifname "wg0" oifname "${GATEWAY_LAN_IFACE}" ip saddr @blocked_peers drop
        iifname "wg0" oifname "${GATEWAY_WAN_IFACE}" ip saddr @blocked_peers drop

        # Panel ACLs must run before the broad WG-to-LAN accept below.
        iifname "wg0" oifname "${GATEWAY_LAN_IFACE}" jump panel_forward

        iifname "wg0" oifname "${GATEWAY_LAN_IFACE}" accept

        # WG peers → internet. Tor-routed peers are caught earlier by the
        # REDIRECT in prerouting_nat (marked traffic never reaches forward),
        # so this only carries clear-WAN egress. The safety net in 30-tor.nft
        # drops any marked packet that somehow leaks past redirection.
        iifname "wg0" oifname "${GATEWAY_WAN_IFACE}" accept
    }
}
EOF

nft -c -f /etc/nftables.conf
systemctl reload nftables 2>/dev/null || nft -f /etc/nftables.conf

echo "[20-wireguard] ok — server ${SRV_IP}, listening udp/${WIREGUARD_LISTEN_PORT}, WGDashboard on ${PANEL_WGD_BIND_ADDR}:${PANEL_WGD_BIND_PORT}"
