#!/usr/bin/env bash
# 00-base: OS prerequisites, sysctl, directories, base nftables skeleton.
# Idempotent.
set -euo pipefail

# --- OS check ---
# Debian 12 is the reference target. Ubuntu 22.04 / 24.04 work too: same apt
# package names, same systemd, same nftables/wireguard/tor kernel bits. The
# only meaningful difference is LAN bring-up (ifupdown vs netplan), handled
# in 10-network.sh.
if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
fi
case "${ID:-}" in
    debian)
        [[ "${VERSION_ID:-}" =~ ^12 ]] || {
            echo "this installer requires Debian 12 (got: debian ${VERSION_ID:-?})" >&2
            exit 1
        }
        ;;
    ubuntu)
        [[ "${VERSION_ID:-}" =~ ^(22\.04|24\.04)$ ]] || {
            echo "this installer requires Ubuntu 22.04 or 24.04 (got: ubuntu ${VERSION_ID:-?})" >&2
            exit 1
        }
        ;;
    *)
        echo "this installer requires Debian 12 or Ubuntu 22.04/24.04 (got: ${ID:-unknown} ${VERSION_ID:-?})" >&2
        exit 1
        ;;
esac

# --- packages ---
PKGS=(
    nftables
    dnsmasq
    curl jq
    sqlite3
    python3 python3-venv python3-pip
    iproute2 iputils-ping conntrack
    ca-certificates
    tcpdump
    rsync
    dnsmasq-utils
)

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends "${PKGS[@]}" >/dev/null

# --- sysctl ---
cat > /etc/sysctl.d/99-gateway.conf <<'EOF'
# Managed by gateway installer
net.ipv4.ip_forward = 1
# Loose RPF: required so fwmark-redirected Tor traffic doesn't get dropped
# when reply path differs from receive interface.
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2

# Conntrack timeouts. The kernel default for UDP (30s) kills long-lived UDP
# flows like QUIC and cloudflared tunnels: a brief idle window expires the
# NAT mapping, the next packet gets a fresh source port, the remote sees a
# "different" connection and disconnects. The TCP established default
# (5 days) is fine; we set it explicitly for clarity.
net.netfilter.nf_conntrack_udp_timeout = 120
net.netfilter.nf_conntrack_udp_timeout_stream = 600
net.netfilter.nf_conntrack_tcp_timeout_established = 86400
EOF
# Apply ONLY our file. `sysctl --system` walks every sysctl.d/ file and barks
# on keys it can't touch in containers/restricted environments — those aren't
# ours. If any of OUR keys fail, that's a real problem worth surfacing.
sysctl -p /etc/sysctl.d/99-gateway.conf >/dev/null

# --- directories ---
install -d -m 0755 /etc/gateway
install -d -m 0755 /etc/nftables.d
install -d -m 0750 /var/lib/gateway
install -d -m 0750 /var/lib/gateway/snapshots
install -d -m 0755 /var/log/gateway

# --- system user for the panel (created early so later modules can chown) ---
if ! id -u gateway >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/gateway --shell /usr/sbin/nologin gateway
fi
chown -R gateway:gateway /var/lib/gateway /var/log/gateway

# --- free port 53 from systemd-resolved (dnsmasq needs it) ---
if systemctl list-unit-files systemd-resolved.service >/dev/null 2>&1 \
   && systemctl is-active --quiet systemd-resolved; then
    install -d -m 0755 /etc/systemd/resolved.conf.d
    cat > /etc/systemd/resolved.conf.d/gateway.conf <<EOF
[Resolve]
DNSStubListener=no
EOF
    systemctl restart systemd-resolved
    # Make sure the host itself can still resolve. We point it at public DNS
    # rather than 127.0.0.1 because dnsmasq isn't up yet at this point.
    if [[ -L /etc/resolv.conf ]] || ! grep -q '^nameserver ' /etc/resolv.conf 2>/dev/null; then
        rm -f /etc/resolv.conf
        printf 'nameserver 1.1.1.1\nnameserver 9.9.9.9\n' > /etc/resolv.conf
    fi
fi

# --- base nftables ruleset ---
# Modules append fragments under /etc/nftables.d/. The skeleton declares the
# table, sets, and the always-on chains. Rules that depend on dynamic state
# (peer IPs, ACLs, host marks) live in the panel-rendered fragment, which
# does NOT exist yet — that's fine, the include is a glob.
cat > /etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f
flush ruleset

table inet gateway {
    set blocked_peers   { type ipv4_addr; flags interval; }
    set tor_peers       { type ipv4_addr; flags interval; }
    set tor_hosts       { type ipv4_addr; flags interval; }
    set blocked_hosts   { type ipv4_addr; flags interval; }

    chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        ct state invalid drop
        iifname "lo" accept
        ip protocol icmp accept
        # SSH on all interfaces. TIGHTEN before exposing the VM to untrusted networks.
        tcp dport 22 accept
        # Module fragments add their listening ports (WG udp/51820, panel tcp/8443
        # only on wg0, etc.) by extending this chain.
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
        ct state established,related accept
        ct state invalid drop
    }

    # Regular (non-base) chain populated by the panel applier. Jumped from
    # WireGuard forward rules before the broad WG->LAN accept.
    chain panel_forward { }

    chain prerouting_mangle {
        type filter hook prerouting priority mangle;
    }

    # Regular (non-base) chain populated by the panel applier. Jumped from
    # `forward` for traffic leaving the internal LAN — used to enforce the
    # "restricted private subnets" allowlist. Empty by default = no restriction.
    chain lan_egress { }

    chain prerouting_nat {
        type nat hook prerouting priority dstnat;
    }

    chain postrouting {
        type nat hook postrouting priority srcnat;
    }
}

include "/etc/nftables.d/*.nft"
EOF

# Validate before activating.
nft -c -f /etc/nftables.conf

systemctl enable --now nftables >/dev/null 2>&1 || true
nft -f /etc/nftables.conf

echo "[00-base] ok"
