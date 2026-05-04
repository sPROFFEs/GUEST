#!/usr/bin/env bash
# 50-monitoring: lightweight metrics — node_exporter + vnstat for traffic per iface.
# Idempotent. Optional module.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get install -y --no-install-recommends prometheus-node-exporter vnstat >/dev/null

systemctl enable --now prometheus-node-exporter >/dev/null 2>&1 || true
systemctl enable --now vnstat >/dev/null 2>&1 || true

# Node exporter binds 0.0.0.0:9100 by default. Restrict to wg0 only.
mkdir -p /etc/default
sed -i 's|^ARGS=.*|ARGS="--web.listen-address=10.66.66.1:9100"|' /etc/default/prometheus-node-exporter || true
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

echo "[50-monitoring] ok — node_exporter on wg0:9100, vnstat collecting"
