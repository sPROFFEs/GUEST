#!/usr/bin/env bash
# 40-panel: install the custom FastAPI panel + scanner timer.
# Idempotent.
set -euo pipefail

: "${PANEL_BIND_ADDR:?}"
: "${PANEL_BIND_PORT:?}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
INSTALL_DIR=/opt/gateway-panel
DB_PATH=/var/lib/gateway/db.sqlite

# --- copy panel source into place (so we can update by re-running install) ---
install -d -m 0755 "$INSTALL_DIR"
rsync -a --delete "${REPO_ROOT}/panel/" "${INSTALL_DIR}/"
chown -R gateway:gateway "$INSTALL_DIR"

# Stash the active gateway.toml where the panel can find it. The panel only
# READS this; it never rewrites it (immutable network config lives here).
install -m 0640 -o gateway -g gateway "${REPO_ROOT}/gateway.toml" /etc/gateway/gateway.toml

# --- venv + deps ---
if [[ ! -x "${INSTALL_DIR}/venv/bin/python" ]]; then
    python3 -m venv "${INSTALL_DIR}/venv"
fi
"${INSTALL_DIR}/venv/bin/pip" install --upgrade pip
"${INSTALL_DIR}/venv/bin/pip" install -r "${INSTALL_DIR}/requirements.txt"

# Sanity-check: deps must actually be importable. If pip silently retried-and-
# gave-up (DNS flake, mirror down), abort here instead of failing later with
# a confusing message.
"${INSTALL_DIR}/venv/bin/python" -c 'import fastapi, jinja2, argon2, itsdangerous, uvicorn' \
    || { echo "panel deps missing — check pip output above"; exit 1; }

# --- DB init + admin bootstrap ---
# Run from INSTALL_DIR so `python -m app.cli` finds the `app` package.
# `runuser` (we're root here) preserves cwd cleanly, unlike sudo with --chdir
# which requires explicit sudoers allowance.
PY="${INSTALL_DIR}/venv/bin/python"
run_as_gateway() {
    ( cd "${INSTALL_DIR}" && runuser -u gateway -- "$@" )
}

run_as_gateway "$PY" -m app.cli init-db --db "$DB_PATH"

if ! run_as_gateway "$PY" -m app.cli has-admin --db "$DB_PATH"; then
    BOOT_PW="$(python3 -c 'import secrets,string; print("".join(secrets.choice(string.ascii_letters+string.digits) for _ in range(16)))')"
    run_as_gateway "$PY" -m app.cli create-admin \
        --db "$DB_PATH" --username admin --password "$BOOT_PW"
    echo
    echo "================================================================"
    echo "  PANEL ADMIN BOOTSTRAP — save this password, it's shown ONCE:"
    echo "  username: admin"
    echo "  password: ${BOOT_PW}"
    echo "================================================================"
    echo
fi

# --- static panel-chain skeleton (jumps + flushable child chains) ---
cat > /etc/nftables.d/45-panel-chains.nft <<'EOF'
# Managed by gateway installer (40-panel) — static chain skeleton.
# The dynamic content (rules + set elements) is written by the panel applier
# into 50-panel.nft on each Apply.
table inet gateway {
    chain panel_forward { }
}
EOF

nft -c -f /etc/nftables.conf
systemctl reload nftables 2>/dev/null || nft -f /etc/nftables.conf

# --- TLS (optional, self-signed) ---
UVICORN_TLS_ARGS=""
if [[ "${PANEL_TLS:-false}" == "true" ]]; then
    install -d -m 0750 -o gateway -g gateway /etc/gateway/tls
    CRT=/etc/gateway/tls/panel.crt
    KEY=/etc/gateway/tls/panel.key
    if [[ ! -s "$CRT" || ! -s "$KEY" ]]; then
        # Build a SAN list that covers every realistic way an admin reaches
        # the panel: gateway hostname, localhost (SSH-tunnel use case), the
        # loopback IP, and every non-loopback IPv4 currently bound to the
        # host (wg0, wan, lan iface).
        SAN_HOSTS=("DNS:${GATEWAY_NAME}" "DNS:$(hostname -s)" "DNS:localhost")
        SAN_IPS=("IP:127.0.0.1")
        while read -r ip; do
            [[ -n "$ip" ]] && SAN_IPS+=("IP:${ip}")
        done < <(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | sort -u)
        SAN_LIST="$(IFS=,; echo "${SAN_HOSTS[*]},${SAN_IPS[*]}")"

        openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
            -keyout "$KEY" -out "$CRT" \
            -subj "/CN=${GATEWAY_NAME}" \
            -addext "subjectAltName=${SAN_LIST}" \
            >/dev/null 2>&1
        chown gateway:gateway "$CRT" "$KEY"
        chmod 0640 "$CRT" "$KEY"
        echo "[40-panel] generated self-signed cert with SANs: ${SAN_LIST}"
    fi
    UVICORN_TLS_ARGS="--ssl-keyfile=${KEY} --ssl-certfile=${CRT}"
fi

# --- systemd units ---
cat > /etc/systemd/system/gateway-panel.service <<EOF
[Unit]
Description=Gateway custom panel (FastAPI)
After=network-online.target wg-quick@wg0.service
Wants=network-online.target

[Service]
Type=simple
User=gateway
Group=gateway
WorkingDirectory=${INSTALL_DIR}
Environment=GATEWAY_DB=${DB_PATH}
Environment=GATEWAY_TOML=/etc/gateway/gateway.toml
Environment=GATEWAY_BIND_ADDR=${PANEL_BIND_ADDR}
Environment=GATEWAY_BIND_PORT=${PANEL_BIND_PORT}
ExecStart=${INSTALL_DIR}/venv/bin/uvicorn app.main:app --host \${GATEWAY_BIND_ADDR} --port \${GATEWAY_BIND_PORT} ${UVICORN_TLS_ARGS}
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/gateway-scanner.service <<EOF
[Unit]
Description=Gateway: scan internal LAN hosts (one-shot)

[Service]
Type=oneshot
User=gateway
Group=gateway
Environment=GATEWAY_DB=${DB_PATH}
Environment=GATEWAY_TOML=/etc/gateway/gateway.toml
ExecStart=${INSTALL_DIR}/venv/bin/python -m app.cli scan
EOF

cat > /etc/systemd/system/gateway-scanner.timer <<'EOF'
[Unit]
Description=Gateway: periodic LAN host scan

[Timer]
OnBootSec=30s
OnUnitActiveSec=30s
Unit=gateway-scanner.service

[Install]
WantedBy=timers.target
EOF

# --- sudoers drop-in: panel can run a small whitelist of root commands ---
# This is the privilege boundary. Anything the applier needs to run as root
# goes here, nothing else.
# --- LAN-state wipe helper -----------------------------------------------
# A privileged helper script so the panel can hard-reset everything DHCP-side
# (leases + static reservations) without giving the gateway user blanket
# write access to dnsmasq paths via sudoers wildcards.
cat > /usr/local/sbin/gateway-lan-reset <<'WIPE'
#!/usr/bin/env bash
# Wipes dnsmasq's lease file and our gateway-managed static-host reservations,
# bouncing dnsmasq so the running state matches. Hardcoded paths only.
set -e
LEASES=/var/lib/misc/dnsmasq.leases
HOSTS=/etc/dnsmasq.d/gateway-hosts.conf

systemctl stop dnsmasq 2>/dev/null || true
: > "$LEASES"   2>/dev/null || true
: > "$HOSTS"    2>/dev/null || true
chown dnsmasq:nogroup "$LEASES" 2>/dev/null || true
chmod 0644 "$LEASES" "$HOSTS"   2>/dev/null || true
systemctl start dnsmasq
WIPE
chmod 0755 /usr/local/sbin/gateway-lan-reset

cat > /etc/sudoers.d/gateway-panel <<'EOF'
# Managed by gateway installer (40-panel).
# Privilege boundary for the unprivileged gateway user.
# One rule per line, no continuations, ASCII-only -- maximum compatibility
# across classic sudo and sudo-rs (Ubuntu 25.10+/26.04 default).
# Paths use /usr/bin/systemctl: canonical on Ubuntu, identical via
# merged-usr on Debian 12. Keep panel callers in sync.

gateway ALL=(root) NOPASSWD: /usr/sbin/nft -c -f /var/lib/gateway/render/50-panel.nft.new
gateway ALL=(root) NOPASSWD: /usr/sbin/nft -c -f /etc/nftables.conf
gateway ALL=(root) NOPASSWD: /usr/sbin/nft -f /etc/nftables.conf
gateway ALL=(root) NOPASSWD: /usr/sbin/nft list set inet gateway blocked_peers
gateway ALL=(root) NOPASSWD: /usr/sbin/nft list set inet gateway tor_peers
gateway ALL=(root) NOPASSWD: /usr/sbin/nft list set inet gateway blocked_hosts
gateway ALL=(root) NOPASSWD: /usr/sbin/nft list set inet gateway tor_hosts
gateway ALL=(root) NOPASSWD: /usr/sbin/nft list table inet gateway
gateway ALL=(root) NOPASSWD: /usr/bin/systemctl reload nftables
gateway ALL=(root) NOPASSWD: /usr/bin/systemctl start dnsmasq
gateway ALL=(root) NOPASSWD: /usr/bin/systemctl stop dnsmasq
gateway ALL=(root) NOPASSWD: /usr/bin/systemctl restart dnsmasq
gateway ALL=(root) NOPASSWD: /usr/bin/systemctl is-active dnsmasq
gateway ALL=(root) NOPASSWD: /usr/bin/systemctl is-active nftables
gateway ALL=(root) NOPASSWD: /usr/bin/systemctl is-active wg-quick@wg0
gateway ALL=(root) NOPASSWD: /usr/bin/systemctl is-active wgdashboard
gateway ALL=(root) NOPASSWD: /usr/bin/systemctl is-active tor
gateway ALL=(root) NOPASSWD: /usr/bin/systemctl is-active tor@default
gateway ALL=(root) NOPASSWD: /usr/bin/systemctl is-active gateway-panel
gateway ALL=(root) NOPASSWD: /usr/bin/systemctl status dnsmasq
gateway ALL=(root) NOPASSWD: /usr/bin/systemctl status nftables
gateway ALL=(root) NOPASSWD: /usr/bin/systemctl status wg-quick@wg0
gateway ALL=(root) NOPASSWD: /usr/bin/systemctl status tor@default
gateway ALL=(root) NOPASSWD: /usr/bin/systemctl status gateway-panel
gateway ALL=(root) NOPASSWD: /usr/bin/systemctl start wg-quick@wg0
gateway ALL=(root) NOPASSWD: /usr/bin/systemctl stop wg-quick@wg0
gateway ALL=(root) NOPASSWD: /usr/bin/systemctl start tor
gateway ALL=(root) NOPASSWD: /usr/bin/systemctl stop tor
gateway ALL=(root) NOPASSWD: /usr/bin/systemctl start tor@default
gateway ALL=(root) NOPASSWD: /usr/bin/systemctl stop tor@default
gateway ALL=(root) NOPASSWD: /usr/bin/systemctl restart tor@default
gateway ALL=(root) NOPASSWD: /usr/bin/install -m 0644 /var/lib/gateway/render/50-panel.nft.new /etc/nftables.d/50-panel.nft
gateway ALL=(root) NOPASSWD: /usr/bin/install -m 0644 /var/lib/gateway/render/gateway-hosts.conf.new /etc/dnsmasq.d/gateway-hosts.conf
gateway ALL=(root) NOPASSWD: /usr/bin/install -m 0644 /var/lib/gateway/snapshots/[0-9]*-[0-9]*/50-panel.nft /etc/nftables.d/50-panel.nft
gateway ALL=(root) NOPASSWD: /usr/bin/install -m 0644 /var/lib/gateway/snapshots/[0-9]*-[0-9]*/gateway-hosts.conf /etc/dnsmasq.d/gateway-hosts.conf
gateway ALL=(root) NOPASSWD: /usr/bin/dhcp_release [a-z]* [0-9]* [0-9a-fA-F:]*
gateway ALL=(root) NOPASSWD: /usr/local/sbin/gateway-lan-reset
EOF
chmod 440 /etc/sudoers.d/gateway-panel
visudo -cf /etc/sudoers.d/gateway-panel

install -d -m 0750 -o gateway -g gateway /var/lib/gateway/render

systemctl daemon-reload
systemctl enable --now gateway-panel >/dev/null 2>&1 || true
systemctl enable --now gateway-scanner.timer >/dev/null 2>&1 || true
systemctl restart gateway-panel

echo "[40-panel] ok — panel on https://${PANEL_BIND_ADDR}:${PANEL_BIND_PORT} (WG only)"
