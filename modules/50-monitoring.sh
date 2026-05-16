#!/usr/bin/env bash
# 50-monitoring: lightweight metrics — node_exporter + vnstat for traffic per iface.
# Idempotent. Optional module.
set -euo pipefail

: "${WIREGUARD_PEER_CIDR:?missing [wireguard].peer_cidr in toml}"

export DEBIAN_FRONTEND=noninteractive
apt-get install -y --no-install-recommends prometheus-node-exporter vnstat >/dev/null

systemctl enable --now prometheus-node-exporter >/dev/null 2>&1 || true
systemctl enable --now vnstat >/dev/null 2>&1 || true

# Node exporter binds 0.0.0.0:9100 by default. Restrict to wg0 only.
WG_MONITOR_IP="$(python3 -c "import ipaddress,sys; n=ipaddress.ip_network(sys.argv[1]); print(next(n.hosts()))" "$WIREGUARD_PEER_CIDR")"
mkdir -p /etc/default
if grep -q '^ARGS=' /etc/default/prometheus-node-exporter 2>/dev/null; then
    sed -i "s|^ARGS=.*|ARGS=\"--web.listen-address=${WG_MONITOR_IP}:9100\"|" /etc/default/prometheus-node-exporter
else
    printf 'ARGS="--web.listen-address=%s:9100"\n' "$WG_MONITOR_IP" >> /etc/default/prometheus-node-exporter
fi
systemctl restart prometheus-node-exporter

cat > /etc/nftables.d/50-monitoring.nft <<'EOF'
# Managed by gateway installer (50-monitoring)
table inet gateway {
    chain input {
        iifname "wg0" tcp dport 9100 accept
    }
}
EOF

nft -c -f /etc/nftables.conf
systemctl reload nftables 2>/dev/null || nft -f /etc/nftables.conf

echo "[50-monitoring] ok — node_exporter on ${WG_MONITOR_IP}:9100, vnstat collecting"
