#!/usr/bin/env bash
# Reverts what install.sh sets up. Does NOT remove apt packages by default
# (other things on the host may use them). Pass --purge to remove packages too.
set -euo pipefail

PURGE=0
[[ "${1:-}" == "--purge" ]] && PURGE=1

[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 1; }

echo "[*] stopping services"
for svc in gateway-panel gateway-scanner.timer wgdashboard tor dnsmasq; do
    systemctl disable --now "$svc" 2>/dev/null || true
done

echo "[*] removing config fragments"
rm -f /etc/nftables.d/*.nft
rm -f /etc/dnsmasq.d/gateway.conf /etc/dnsmasq.d/gateway-hosts.conf
rm -f /etc/network/interfaces.d/gateway-lan
rm -f /etc/sysctl.d/99-gateway.conf
rm -f /etc/systemd/resolved.conf.d/gateway.conf
rm -f /etc/systemd/system/gateway-panel.service
rm -f /etc/systemd/system/gateway-scanner.service
rm -f /etc/systemd/system/gateway-scanner.timer

# Revert /etc/nftables.conf to a permissive default. Operator can replace later.
cat > /etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f
flush ruleset
EOF
nft -f /etc/nftables.conf || true

echo "[*] removing state directories"
rm -rf /var/lib/gateway /var/log/gateway /etc/gateway

if id -u gateway >/dev/null 2>&1; then
    userdel gateway 2>/dev/null || true
fi

systemctl daemon-reload

if [[ $PURGE -eq 1 ]]; then
    echo "[*] purging packages"
    apt-get purge -y nftables dnsmasq tor wireguard 2>/dev/null || true
    apt-get autoremove -y 2>/dev/null || true
fi

sysctl --system >/dev/null

echo "[+] uninstall complete"
