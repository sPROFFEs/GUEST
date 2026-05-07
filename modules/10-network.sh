#!/usr/bin/env bash
# 10-network: configure LAN interface, dnsmasq DHCP/DNS, NAT masquerade.
# Idempotent.
set -euo pipefail

: "${GATEWAY_WAN_IFACE:?missing in toml}"
: "${GATEWAY_LAN_IFACE:?missing in toml}"
: "${GATEWAY_LAN_CIDR:?missing in toml}"

# --- LAN interface (static IP via ifupdown) ---
# Debian 12 default install uses ifupdown. We write a per-iface snippet so the
# main /etc/network/interfaces (managed by the installer image) stays untouched.
cat > /etc/network/interfaces.d/gateway-lan <<EOF
# Managed by gateway installer
auto ${GATEWAY_LAN_IFACE}
iface ${GATEWAY_LAN_IFACE} inet static
    address ${GATEWAY_LAN_CIDR}
EOF

# Bring up. Tolerate "already configured" — this is the idempotent path.
if ! ip -4 addr show dev "${GATEWAY_LAN_IFACE}" 2>/dev/null | grep -q "${GATEWAY_LAN_CIDR}"; then
    ifdown "${GATEWAY_LAN_IFACE}" 2>/dev/null || true
    ifup "${GATEWAY_LAN_IFACE}"
fi

# --- dnsmasq (DHCP + DNS for the LAN) ---
if [[ "${MODULES_DHCP:-true}" == "true" ]]; then
    : "${DHCP_RANGE:?missing [dhcp].range in toml}"

    cat > /etc/dnsmasq.d/gateway.conf <<EOF
# Managed by gateway installer — base config.
# Static leases per-host are appended by the panel to gateway-hosts.conf.
interface=${GATEWAY_LAN_IFACE}
bind-interfaces
domain-needed
bogus-priv
dhcp-range=${DHCP_RANGE}
dhcp-authoritative
log-dhcp
# Upstream DNS — the gateway resolves on behalf of the LAN.
server=1.1.1.1
server=9.9.9.9
EOF

    # Panel-managed file (per-MAC static leases, host overrides). Ensure it
    # exists so dnsmasq's --conf-file globbing finds it.
    [[ -f /etc/dnsmasq.d/gateway-hosts.conf ]] \
        || install -m 0644 /dev/null /etc/dnsmasq.d/gateway-hosts.conf

    systemctl enable dnsmasq >/dev/null 2>&1 || true
    systemctl restart dnsmasq
fi

# --- nftables fragment: NAT + initial broad allow ---
# The "iifname LAN oifname WAN accept" rule below is the PHASE-1 default: hosts
# in the LAN can reach the internet unrestricted. When the panel module (40)
# lands, it will render its own fragment (50-panel.nft) that adds the
# blocked_hosts/tor_hosts checks BEFORE this accept. The relative file order
# (10 < 50) ensures the panel's restrictive rules evaluate first.
cat > /etc/nftables.d/10-network.nft <<EOF
# Managed by gateway installer (10-network)
table inet gateway {
    chain input {
        # Allow DHCP and DNS requests from the LAN.
        iifname "${GATEWAY_LAN_IFACE}" udp dport { 53, 67 } accept
        iifname "${GATEWAY_LAN_IFACE}" tcp dport 53 accept
    }

    chain forward {
        # MSS clamping. Crucial when WAN has a smaller MTU than 1500 — VPNs,
        # PPPoE, GRE, etc. Without this, internal hosts advertise MSS=1460,
        # the path silently drops oversize packets, and long-lived TCP flows
        # (cloudflared HTTP/2, SSH sessions, large transfers) appear "degraded".
        # \`size set rt mtu\` adapts to the actual route MTU on every SYN.
        tcp flags syn tcp option maxseg size set rt mtu

        # First, give the panel-managed lan_egress chain a chance to apply
        # the "restricted private subnets" allowlist. It accepts allowlisted
        # destinations, drops restricted ones, and returns for everything else.
        iifname "${GATEWAY_LAN_IFACE}" jump lan_egress

        # Catch-all: LAN hosts may reach WAN (i.e. the internet, given that
        # private subnets that need restricting were already drop'd above).
        iifname "${GATEWAY_LAN_IFACE}" oifname "${GATEWAY_WAN_IFACE}" \
            ip saddr != @blocked_hosts accept
    }

    chain postrouting {
        oifname "${GATEWAY_WAN_IFACE}" masquerade
    }
}
EOF

# Validate the full ruleset and reload.
nft -c -f /etc/nftables.conf
systemctl reload nftables 2>/dev/null || nft -f /etc/nftables.conf

echo "[10-network] ok — LAN ${GATEWAY_LAN_IFACE}=${GATEWAY_LAN_CIDR}, NAT via ${GATEWAY_WAN_IFACE}"
