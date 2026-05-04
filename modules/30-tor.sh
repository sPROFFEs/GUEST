#!/usr/bin/env bash
# 30-tor: Tor with TransPort/DNSPort, policy routing for fwmark 0x1.
# Idempotent.
set -euo pipefail

: "${TOR_TRANS_PORT:?}"
: "${TOR_DNS_PORT:?}"

export DEBIAN_FRONTEND=noninteractive
apt-get install -y --no-install-recommends tor >/dev/null

install -d -m 0755 /etc/tor/torrc.d

cat > /etc/tor/torrc.d/gateway.conf <<EOF
# Managed by gateway installer
VirtualAddrNetworkIPv4 10.192.0.0/10
AutomapHostsOnResolve 1
TransPort 127.0.0.1:${TOR_TRANS_PORT} IsolateClientAddr IsolateClientProtocol
DNSPort 127.0.0.1:${TOR_DNS_PORT}
EOF

# Make sure main torrc includes our drop-in dir.
if ! grep -q '%include /etc/tor/torrc.d' /etc/tor/torrc 2>/dev/null; then
    echo '%include /etc/tor/torrc.d/' >> /etc/tor/torrc
fi

systemctl enable tor >/dev/null 2>&1 || true
systemctl restart tor

# Policy routing for marked traffic. Idempotent guards so re-runs don't error.
if ! ip rule show | grep -q 'fwmark 0x1 lookup 100'; then
    ip rule add fwmark 0x1 lookup 100
fi
if ! ip route show table 100 | grep -q '^local default'; then
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
        meta mark 0x1 ip protocol tcp redirect to :${TOR_TRANS_PORT}
        meta mark 0x1 udp dport 53 redirect to :${TOR_DNS_PORT}
        meta mark 0x1 meta l4proto udp drop
    }

    chain forward {
        # Marked traffic goes through Tor on lo; never let it leak via WAN.
        meta mark 0x1 oifname != "lo" drop
    }
}
EOF

nft -c -f /etc/nftables.conf
systemctl reload nftables 2>/dev/null || nft -f /etc/nftables.conf

echo "[30-tor] ok — TransPort 127.0.0.1:${TOR_TRANS_PORT}, DNSPort 127.0.0.1:${TOR_DNS_PORT}"
