#!/usr/bin/env bash
# 30-tor: Tor with TransPort/DNSPort, policy routing for fwmark 0x1.
# Idempotent.
set -euo pipefail

: "${TOR_TRANS_PORT:?}"
: "${TOR_DNS_PORT:?}"
: "${GATEWAY_LAN_CIDR:?}"
: "${GATEWAY_LAN_IFACE:?}"

# nft `redirect to :PORT` rewrites the destination to the *input interface's*
# IP, not 127.0.0.1. So packets from internal-LAN hosts marked for Tor end up
# at <LAN_IP>:9040 — Tor must be listening there. Extract the LAN IP from the
# CIDR we know.
LAN_IP="${GATEWAY_LAN_CIDR%/*}"

export DEBIAN_FRONTEND=noninteractive
apt-get install -y --no-install-recommends tor >/dev/null

# Inline our directives directly into /etc/tor/torrc rather than using
# %include /etc/tor/torrc.d/. The include path tickles a sandbox/AppArmor
# bug on Debian 12 + tor 0.4.9.6 where verify-config reads it fine but the
# actual ExecStart fails with "Error reading included configuration file or
# directory". Bypassing the include avoids it entirely.
TORRC=/etc/tor/torrc
BEGIN_TAG="# BEGIN gateway-installer (do not edit between these markers)"
END_TAG="# END gateway-installer"

# Strip any previous block we wrote (idempotent re-runs) and any %include we
# left behind from earlier installer revisions.
sed -i "/^${BEGIN_TAG}\$/,/^${END_TAG}\$/d" "$TORRC"
sed -i '\|^%include /etc/tor/torrc\.d|d' "$TORRC"
# Best-effort cleanup of the now-orphaned drop-in we used to write.
rm -f /etc/tor/torrc.d/gateway.conf 2>/dev/null || true

cat >> "$TORRC" <<EOF
${BEGIN_TAG}
VirtualAddrNetworkIPv4 10.192.0.0/10
AutomapHostsOnResolve 1
# Two binds:
#   127.0.0.1   — for the gateway itself if it ever wants to use Tor
#   ${LAN_IP}   — target of nft REDIRECT for marked LAN-host traffic
TransPort 127.0.0.1:${TOR_TRANS_PORT} IsolateClientAddr IsolateClientProtocol
TransPort ${LAN_IP}:${TOR_TRANS_PORT} IsolateClientAddr IsolateClientProtocol
DNSPort 127.0.0.1:${TOR_DNS_PORT}
DNSPort ${LAN_IP}:${TOR_DNS_PORT}
${END_TAG}
EOF

# On Debian, the meaningful unit is `tor@default.service`; `tor.service` is a
# placeholder that depends on it. Enable/restart the right one — restarting
# the placeholder won't actually pick up config changes.
systemctl enable tor@default >/dev/null 2>&1 || true
systemctl restart tor@default
# Keep the metasservice in sync so `systemctl is-active tor` reflects reality.
systemctl enable tor >/dev/null 2>&1 || true

# Policy routing for marked traffic. Idempotent guards so re-runs don't error.
if ! ip rule show | grep -q 'fwmark 0x1 lookup 100'; then
    ip rule add fwmark 0x1 lookup 100
fi
if ! ip route show table 100 2>/dev/null | grep -q '^local default'; then
    ip route add local 0.0.0.0/0 dev lo table 100
fi

# Persist across reboots via a small networkd-dispatcher-free helper.
cat > /etc/systemd/system/gateway-tor-route.service <<'EOF'
[Unit]
Description=Gateway: install policy route for Tor fwmark
After=network-online.target tor.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'ip rule show | grep -q "fwmark 0x1 lookup 100" || ip rule add fwmark 0x1 lookup 100'
ExecStart=/bin/sh -c 'ip route show table 100 | grep -q "^local default" || ip route add local 0.0.0.0/0 dev lo table 100'
ExecStop=/bin/sh -c 'ip rule del fwmark 0x1 lookup 100 2>/dev/null || true'

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now gateway-tor-route >/dev/null 2>&1 || true

# nft fragment: redirect marked TCP to TransPort, marked DNS to DNSPort,
# drop marked UDP (Tor doesn't carry it). Marking itself is done by the
# panel-rendered fragment based on tor_peers / tor_hosts sets.
cat > /etc/nftables.d/30-tor.nft <<EOF
# Managed by gateway installer (30-tor)
table inet gateway {
    chain prerouting_mangle {
        ip saddr @tor_peers meta mark set 0x1
        ip saddr @tor_hosts meta mark set 0x1
    }

    chain prerouting_nat {
        # REDIRECT rewrites destination to the input interface IP + this port.
        # Tor is configured to listen on that IP (see TransPort/DNSPort lines
        # in /etc/tor/torrc).
        meta mark 0x1 ip protocol tcp redirect to :${TOR_TRANS_PORT}
        meta mark 0x1 udp dport 53 redirect to :${TOR_DNS_PORT}
        meta mark 0x1 meta l4proto udp drop
    }

    chain input {
        # Accept the redirected traffic — it's now destined for the gateway's
        # LAN IP on the Tor ports. Without these rules input drops it
        # (default policy) and the host gets connection refused.
        iifname "${GATEWAY_LAN_IFACE}" meta mark 0x1 tcp dport ${TOR_TRANS_PORT} accept
        iifname "${GATEWAY_LAN_IFACE}" meta mark 0x1 udp dport ${TOR_DNS_PORT} accept
    }

    chain forward {
        # Marked traffic should never reach forward — it gets caught by the
        # REDIRECT in prerouting_nat. This is a safety net: if marking ever
        # happens but redirection doesn't, drop instead of leaking via WAN.
        meta mark 0x1 oifname != "lo" drop
    }
}
EOF

nft -c -f /etc/nftables.conf
systemctl reload nftables 2>/dev/null || nft -f /etc/nftables.conf

echo "[30-tor] ok — TransPort 127.0.0.1:${TOR_TRANS_PORT}, DNSPort 127.0.0.1:${TOR_DNS_PORT}"
