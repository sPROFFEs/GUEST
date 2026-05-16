# Gateway

A modular VPN + firewall gateway you snapshot once and clone forever. Each instance is a small Debian 12 VM that:

- terminates WireGuard for a set of dev peers (managed via WGDashboard);
- isolates an internal LAN behind it (Proxmox UI, lab VMs, anything you want sealed off);
- enforces per-peer ACLs so a peer can only reach the destinations you whitelist (e.g. `192.168.100.211:8006` and nothing else);
- optionally routes specific peers or specific internal hosts through Tor;
- gives you a small web panel to manage all of the above without SSHing in.

The design and rationale are in [ARCHITECTURE.md](ARCHITECTURE.md). This document is the operator guide.

---

## 1. Requirements

- A **VM** (not LXC). KVM/Proxmox VM, ESXi, anything with a real kernel. WireGuard, nftables fwmark routing, and `CAP_NET_ADMIN` don't work cleanly in unprivileged containers.
- **Debian 12** (Bookworm) minimal install.
- **Two NICs** attached to the VM:
  - `WAN` — the network the gateway uses to reach the rest of the world. Often a management bridge in Proxmox; can also be the real internet.
  - `LAN-internal` — a bridge with **no uplink**, where Proxmox/lab VMs live. Isolating this bridge is what makes the whole setup fail-closed: if the gateway is down, the VMs can't escape.
- Outgoing internet from the WAN side at install time (apt + pip + git clone).

Hardware: 1 vCPU, 512 MB RAM, 8 GB disk is plenty.

---

## 2. Quick install

```bash
# On the VM, as root or with sudo:
git clone <this-repo> gateway
cd gateway
cp gateway.toml.example gateway.toml
$EDITOR gateway.toml          # see §4 below
sudo ./install.sh
```

That's it. The installer prints a one-time admin password at the end of the panel module — copy it before the terminal scrolls.

If anything fails mid-way, fix it and re-run. Every module is idempotent — it picks up where it left off.

---

## 3. Per-module install

Useful when you want to validate one piece at a time, or skip a module:

```bash
sudo ./install.sh --module 00-base
sudo ./install.sh --module 10-network
sudo ./install.sh --module 20-wireguard
sudo ./install.sh --module 30-tor          # only if [modules].tor = true
sudo ./install.sh --module 40-panel
sudo ./install.sh --module 50-monitoring   # only if [modules].monitoring = true
```

Or syntax-check everything without touching the system:

```bash
sudo ./install.sh --dry-run
```

What each module does:

| Module          | Installs                                                | Touches                                    |
|-----------------|---------------------------------------------------------|--------------------------------------------|
| `00-base`       | nftables, dnsmasq, sqlite3, python3, rsync, openssl…    | sysctl, `/etc/nftables.conf` skeleton, `gateway` user |
| `10-network`    | LAN static IP, dnsmasq DHCP/DNS, NAT masquerade         | `/etc/network/interfaces.d/`, `/etc/dnsmasq.d/`        |
| `20-wireguard`  | WireGuard kernel module + WGDashboard                   | `/etc/wireguard/wg0.conf`, `/opt/wgdashboard`          |
| `30-tor`        | Tor with TransPort + DNSPort, policy routing for `0x1`  | `/etc/tor/torrc.d/`, ip rule, route table 100          |
| `40-panel`      | Custom FastAPI panel + scanner timer                    | `/opt/gateway-panel`, `/var/lib/gateway/`, sudoers     |
| `50-monitoring` | node_exporter (wg0:9100) + vnstat                       | `/etc/default/prometheus-node-exporter`                |

---

## 4. Configuration (`gateway.toml`)

```toml
[gateway]
name      = "gw-isolated-01"   # used in the cert CN, panel header, audit log
wan_iface = "ens18"            # internet-facing or upstream NIC inside the VM
lan_iface = "ens19"            # NIC connected to the isolated bridge
lan_cidr  = "192.168.100.1/24" # the gateway's IP on the LAN (CIDR form)

[modules]
wireguard  = true              # WG + WGDashboard
tor        = false             # Tor TransPort + nft fwmark redirect
dhcp       = true              # dnsmasq on lan_iface
monitoring = false             # node_exporter + vnstat

[wireguard]
listen_port = 51820
peer_cidr   = "10.66.66.0/24"  # tunnel subnet — peer IPs come from here
endpoint    = "vpn.example:51820"  # baked into peer config files

[dhcp]
range = "192.168.100.100,192.168.100.200,12h"

[panel]
bind_addr     = "10.66.66.1"   # see §5 (Access)
bind_port     = 8443
wgd_bind_addr = "10.66.66.1"
wgd_bind_port = 10086
expose_on_wan = false          # also open ports on wan_iface in nft
tls           = false          # serve panel over HTTPS with self-signed cert

[tor]
trans_port = 9040
dns_port   = 5353
```

### Module toggles vs. config values

The values in `gateway.toml` are read at install time and at panel start. Two categories:

- **Network identity** (interfaces, CIDRs, ports) — immutable post-install. Changing them requires re-running the relevant module.
- **Module on/off** — also flippable at runtime from the panel. The TOML provides the initial state; the panel writes its own state into the SQLite DB.

---

## 5. Accessing the panels

There are two web UIs:

- **Custom panel** (`bind_port`, default `8443`) — peers, ACLs, hosts, Tor toggles, apply.
- **WGDashboard** (`wgd_bind_port`, default `10086`) — peer creation, QR codes, config download.

Where they listen depends on `[panel].bind_addr` and `[panel].expose_on_wan`:

| Scenario                                       | `bind_addr`  | `expose_on_wan` | Reachable from                     |
|------------------------------------------------|--------------|-----------------|-------------------------------------|
| Default — only existing peers can manage       | `10.66.66.1` | `false`         | inside the WG tunnel only           |
| WAN is an internal mgmt LAN, you want easy access | `0.0.0.0` | `true`          | both the WG tunnel and the WAN side |
| WAN is the public internet, no admin from outside | `10.66.66.1` | `false`       | inside the WG tunnel only — keep it this way |

**Never** combine `expose_on_wan = true` with a public-internet WAN unless you fully understand what you're doing — `tls = false` over the public internet would expose passwords on the wire.

### Bootstrap — the chicken & egg

The default config (wg-only) is secure but creates a bootstrapping problem: you need a WG peer to reach WGDashboard, but WGDashboard is what creates peers. Two ways out:

**A. SSH local-forward** (recommended, zero extra exposure):
```bash
ssh -L 10086:10.66.66.1:10086 -L 8443:10.66.66.1:8443 root@<gateway-wan-ip>
# then open http://localhost:10086 in your browser
```
Create your peer there, import the config into your WG client, then disconnect SSH and use the tunnel from then on.

**B. Temporarily flip `expose_on_wan = true`**, install your peer, flip it back, re-run module 20:
```bash
$EDITOR gateway.toml      # expose_on_wan = true
sudo ./install.sh --module 20-wireguard
# create peer in WGDashboard at http://<wan>:10086
$EDITOR gateway.toml      # expose_on_wan = false
sudo ./install.sh --module 20-wireguard
```

---

## 6. TLS

When you set `[panel].tls = true`, module 40:

1. Creates `/etc/gateway/tls/panel.{crt,key}` with `openssl req -x509 -nodes -days 3650`. CN = `[gateway].name`, SAN includes `[panel].bind_addr`.
2. Adds `--ssl-keyfile` and `--ssl-certfile` to the `gateway-panel` systemd unit.
3. Switches the session cookie to `Secure` automatically (the panel detects the request scheme).

Browsers will warn on first visit — accept the exception, or import the cert into your trust store. To rotate, delete both files and re-run module 40:

```bash
sudo rm /etc/gateway/tls/panel.{crt,key}
sudo ./install.sh --module 40-panel
```

WGDashboard has its own TLS toggle in its Settings page — turn it on there if you want HTTPS on `:10086` too.

---

## 7. Day-to-day flow

1. **Add a peer** in WGDashboard, hand the QR/config file to the dev.
2. **Open the custom panel**, go to *Peers*, find the new peer, give it a label.
3. **Click "edit" under ACLs**, add what they're allowed to reach. Example for the Proxmox UI:
   - `dst_cidr`: `192.168.100.211/32`
   - `proto`: `tcp`
   - `dport`: `8006`
   - `action`: `accept`
4. **Click Apply** when the yellow "Pending changes" banner shows up.

That's it. Without an explicit ACL, a peer can reach **nothing** on the LAN — the `panel_forward` chain ends in an implicit drop.

To take a peer offline temporarily, hit *Block: yes* on their row. To send their traffic via Tor, hit *Tor: on* (and make sure the Tor module is installed and enabled).

---

## 8. Internal hosts (LAN side)

The scanner runs every 30 seconds (`gateway-scanner.timer`) and populates the *Hosts* tab with whatever it sees on `lan_iface` via `ip neigh`. From the panel you can:

- **Pin an IP** (toggle `dhcp` → `fixed`, edit the IP) — writes a `dhcp-host=` line to `/etc/dnsmasq.d/gateway-hosts.conf` on Apply.
- **Block** a host — drops all forwarded traffic from that IP (it can still talk to the gateway itself for DHCP/DNS).
- **Tor-route** a host — every packet from that IP gets `fwmark 0x1` and is redirected to Tor's TransPort. UDP gets dropped (Tor doesn't carry it; you'll need to handle DNS over TCP or accept Tor's DNSPort as the resolver).

For Tor-routing to be honest, the host must not be able to spoof its own IP. DHCP-fixed binding by MAC is the lightweight protection; harder isolation would need ebtables on the bridge.

---

## 9. Replicating to other gateways

The whole point of this design — clone the VM, change one file:

```bash
# On Proxmox host:
qm clone <template-id> <new-id> --name gw-iso-02

# On the new VM:
$EDITOR /home/<you>/gateway/gateway.toml    # change name, lan_cidr, modules…
sudo ./install.sh                           # re-runs modules with new config
```

Use cases:

- **Same template, no WireGuard** (pure isolation gateway): set `[modules].wireguard = false` before re-running. The panel hides peer/ACL UI, no WG service starts, no WGDashboard.
- **Same template, with Tor for one host**: enable `[modules].tor = true`, install, then in the panel toggle Tor on for the specific internal host's MAC.
- **Multiple isolation tiers**: clone twice, give each its own `lan_cidr` and own WG peer pool — no overlap, no shared state.

---

## 10. Common issues

**`sysctl: permission denied on key kernel.pid_max` during `00-base`.**
You're inside an LXC, not a VM. Move to a real VM. The whole stack assumes a real kernel.

**`ifup: unknown interface ensXY` during `10-network`.**
The interface name in `gateway.toml` doesn't match what the VM actually has. Check with `ip -br link show`.

**`pip ... Failed to resolve files.pythonhosted.org`.**
DNS is broken in the VM. Check `/etc/resolv.conf` — if it's pointing to `127.0.0.53`, write public DNS instead:
```bash
sudo rm /etc/resolv.conf
echo -e "nameserver 1.1.1.1\nnameserver 9.9.9.9" | sudo tee /etc/resolv.conf
```
Then re-run module 40.

**Panel returns 502 / refuses connection from WAN.**
Check both layers:
- `systemctl status gateway-panel` — service running?
- `ss -ltnp | grep <port>` — bound on the right address? If `bind_addr = 10.66.66.1` you can't reach it from the WAN side; flip `bind_addr` to `0.0.0.0` and `expose_on_wan = true`, re-run modules 20 and 40.

**Apply fails with nft validation error.**
The panel snapshots before applying and rolls back on failure. Look at *Audit* in the UI for the error detail, or `journalctl -u gateway-panel`. Most often: a CIDR with bad syntax in an ACL rule.

**Tor toggle does nothing.**
Module 30 not installed. Check `[modules].tor = true` and re-run `--module 30-tor`. Also make sure Tor itself is healthy: `systemctl status tor`.

**Lost the admin password.**
Reset it from the VM (the `cd` matters — `python -m app.cli` only finds the
`app` package when invoked from the install dir):
```bash
sudo sqlite3 /var/lib/gateway/db.sqlite \
    "DELETE FROM users WHERE username='admin'"
cd /opt/gateway-panel && sudo runuser -u gateway -- \
    /opt/gateway-panel/venv/bin/python -m app.cli create-admin \
    --db /var/lib/gateway/db.sqlite \
    --username admin --password 'NEW_PASSWORD_HERE'
```

---

## 11. Uninstalling

```bash
sudo ./uninstall.sh           # remove configs, services, state — keep packages
sudo ./uninstall.sh --purge   # also `apt purge` the packages we installed
```

---

## 12. What's *not* in here yet

Things I deliberately left out for v0 — call them out if you want them:

- TOTP / 2FA for the panel (only password right now).
- OIDC / SSO integration.
- Remote backup of `db.sqlite` to another host.
- Per-host Tor routing protection against in-VM IP spoofing (would need ebtables on the bridge).
- Alembic-style migrations — there's only one `0001_init.sql` for now.
- IPv6 (the firewall is `inet`-family but no v6 NAT/forward rules are emitted).

The architecture is meant to absorb all of these — they're slots in the existing design, not redesigns.
