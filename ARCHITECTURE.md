# Gateway VM — Arquitectura

VM Debian 12 minimal que actúa como gateway VPN+firewall+DHCP para una red interna aislada, con panel web propio y opción de enrutar tráfico por Tor. Se snapshotea como template en Proxmox y se replica clonando + cambiando `gateway.toml`.

---

## 1. Topología de red

```
                      ┌─────────────────────────────────────┐
                      │         Gateway VM (esta)           │
                      │                                     │
   Internet  ─ vmbr0 ─┤ eth0 (WAN, DHCP del host)           │
                      │                                     │
   Peers WG ─────────►│ wg0  (10.66.66.1/24)                │
                      │                                     │
                      │ eth1 (LAN-int, 192.168.100.1/24) ───┼─ vmbr-iso ─┬─ Proxmox  192.168.100.211:8006
                      │                                     │            ├─ VM-A     192.168.100.50
                      │ tor (TransPort 9040, DNS 5353)      │            └─ VM-B     192.168.100.51
                      └─────────────────────────────────────┘
```

- **vmbr0**: bridge del host con salida a internet.
- **vmbr-iso**: bridge interno de Proxmox sin uplink físico — solo VMs + el `eth1` del gateway.
- **wg0**: subred privada para los peers. Cada peer recibe una IP fija de este pool.
- **Reenvío IP**: `net.ipv4.ip_forward=1`, `net.ipv4.conf.all.rp_filter=2` (loose, necesario por las marcas de Tor).

### Por qué dos NICs y no una

Aislar `eth1` en su propio bridge sin uplink garantiza que las VMs internas **no pueden salir a internet** si el gateway está caído o tiene WG/Tor desactivados. La política por defecto es "fail-closed".

---

## 2. Componentes en el host

Todo corre nativo bajo systemd. No hay Docker.

| Servicio              | Paquete             | Rol                                                      |
|-----------------------|---------------------|----------------------------------------------------------|
| `wg-quick@wg0`        | wireguard           | Túnel VPN para peers                                     |
| `wgdashboard`         | WGDashboard (pip)   | Panel web SOLO de gestión WG (alta peers, QR, descargas) |
| `dnsmasq`             | dnsmasq             | DHCP + DNS para `eth1` (192.168.100.0/24)                |
| `nftables`            | nftables            | Firewall, NAT, marcado para policy routing               |
| `tor`                 | tor                 | TransPort+DNSPort (solo si `[modules.tor] enabled=true`) |
| `gateway-panel`       | (nuestro)           | FastAPI + htmx, panel custom                             |
| `gateway-scanner`     | (nuestro, timer)    | Escaneo periódico de hosts (`ip neigh`, ARP)             |

**División de responsabilidades importante**: WGDashboard se queda como está, gestionando su `wg0.conf` y su SQLite propia. Nuestro panel **lee** la DB de WGDashboard (sólo lectura) para listar peers, y guarda metadata propia (ACLs, toggle Tor, etiquetas) referenciada por la pubkey del peer. Así no duplicamos lógica de WG ni peleamos por escribir el mismo fichero.

---

## 3. Modelo de firewall (nftables)

Un único fichero `/etc/nftables.d/gateway.nft` renderizado desde la DB. Nunca se edita a mano.

```nft
table inet gateway {
    # Sets generados desde la DB
    set blocked_peers   { type ipv4_addr; flags interval; }
    set tor_peers       { type ipv4_addr; flags interval; }
    set tor_hosts       { type ipv4_addr; flags interval; }   # VMs internas vía Tor
    map peer_acl        { type ipv4_addr . ipv4_addr . inet_proto . inet_service : verdict; }

    chain forward {
        type filter hook forward priority 0; policy drop;

        ct state established,related accept
        ip saddr @blocked_peers drop

        # ACL por peer: (src_peer, dst_ip, proto, dport) → accept
        ip saddr . ip daddr . meta l4proto . th dport vmap @peer_acl

        # Tráfico WG → LAN-interna sin ACL específica = drop (queda en policy drop)
    }

    chain prerouting_mangle {
        type filter hook prerouting priority mangle;
        ip saddr @tor_peers meta mark set 0x1
        ip saddr @tor_hosts meta mark set 0x1
    }

    chain prerouting_nat {
        type nat hook prerouting priority dstnat;
        # Redirección transparente a Tor para tráfico marcado
        meta mark 0x1 ip protocol tcp redirect to :9040
        meta mark 0x1 udp dport 53 redirect to :5353
        meta mark 0x1 udp drop                 # Tor no soporta UDP
    }

    chain postrouting {
        type nat hook postrouting priority srcnat;
        oifname "eth0" meta mark != 0x1 masquerade
    }
}
```

**Consecuencias de este diseño**:
- Política por defecto `drop` en forward → sin ACL explícita, un peer no llega a nada.
- Bloquear un peer = añadirlo al set `blocked_peers`. Reload atómico de set, no recarga toda la regla.
- Activar Tor para un peer/host = añadirlo al set correspondiente.
- El `vmap` permite ACLs muy granulares (peer X puede a 192.168.100.211:8006 TCP, y nada más) en O(1).

---

## 4. Routing por Tor

```
ip rule add fwmark 0x1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
```

Los paquetes marcados nunca salen por `eth0` directamente: la regla `redirect to :9040` los entrega al Tor local, que los reinyecta por `eth0` ya tor-ificados. Si `tor.service` no está corriendo y el toggle está activo, el panel se niega a aplicar (fail-closed) para no exponer tráfico claro.

**Limitación honesta**: UDP no pasa por Tor (ni juegos, ni QUIC, ni WireGuard-sobre-UDP). El panel lo avisa al activar el toggle.

---

## 5. Esquema de base de datos (SQLite, WAL)

```sql
-- Metadata por peer WG (pubkey es FK lógica a la DB de WGDashboard)
CREATE TABLE peer_meta (
    pubkey       TEXT PRIMARY KEY,
    label        TEXT,
    blocked      INTEGER NOT NULL DEFAULT 0,
    tor_routed   INTEGER NOT NULL DEFAULT 0,
    notes        TEXT,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);

-- ACLs por peer. Una fila = una regla "peer X puede llegar a dst:port"
CREATE TABLE acl_rules (
    id           INTEGER PRIMARY KEY,
    peer_pubkey  TEXT NOT NULL REFERENCES peer_meta(pubkey) ON DELETE CASCADE,
    dst_cidr     TEXT NOT NULL,           -- "192.168.100.211/32"
    proto        TEXT NOT NULL,           -- "tcp" | "udp" | "any"
    dport        INTEGER,                 -- NULL = cualquiera
    action       TEXT NOT NULL,           -- "accept" | "drop"
    enabled      INTEGER NOT NULL DEFAULT 1,
    created_at   TEXT NOT NULL
);
CREATE INDEX idx_acl_peer ON acl_rules(peer_pubkey);

-- Hosts en la LAN interna (descubiertos + manuales)
CREATE TABLE internal_hosts (
    mac          TEXT PRIMARY KEY,
    ip           TEXT,
    hostname     TEXT,
    static       INTEGER NOT NULL DEFAULT 0,   -- DHCP fijo
    tor_routed   INTEGER NOT NULL DEFAULT 0,
    blocked      INTEGER NOT NULL DEFAULT 0,
    notes        TEXT,
    last_seen    TEXT
);

-- Toggles globales (modulares)
CREATE TABLE settings (
    key          TEXT PRIMARY KEY,
    value        TEXT NOT NULL
);
-- valores: wg_enabled, tor_enabled, dhcp_enabled, scan_interval_s,
--          wan_iface, lan_iface, lan_cidr, dhcp_range_start, dhcp_range_end

-- Auditoría
CREATE TABLE audit_log (
    id           INTEGER PRIMARY KEY,
    ts           TEXT NOT NULL,
    actor        TEXT NOT NULL,           -- usuario del panel
    action       TEXT NOT NULL,           -- "peer.block", "acl.add", "apply", ...
    target       TEXT,
    detail       TEXT                     -- JSON
);
CREATE INDEX idx_audit_ts ON audit_log(ts);

-- Usuarios del panel
CREATE TABLE users (
    username     TEXT PRIMARY KEY,
    pw_hash      TEXT NOT NULL,           -- argon2
    totp_secret  TEXT,                    -- opcional
    role         TEXT NOT NULL DEFAULT 'admin'
);
```

---

## 6. API del panel (FastAPI)

Sesión por cookie firmada, login con usuario+password (+TOTP opcional). Toda mutación pasa por audit_log.

| Método | Ruta                                  | Descripción                                            |
|--------|---------------------------------------|--------------------------------------------------------|
| GET    | `/api/status`                         | Estado de wg/tor/dnsmasq, contadores tráfico, uptime   |
| GET    | `/api/peers`                          | Lista de peers (join WGDashboard + peer_meta)          |
| PATCH  | `/api/peers/{pubkey}`                 | Toggle blocked/tor_routed, editar label/notes          |
| GET    | `/api/peers/{pubkey}/acl`             | Reglas ACL del peer                                    |
| POST   | `/api/peers/{pubkey}/acl`             | Añadir regla ACL                                       |
| DELETE | `/api/acl/{id}`                       | Borrar regla ACL                                       |
| GET    | `/api/hosts`                          | Hosts internos (descubiertos + manuales)               |
| POST   | `/api/hosts`                          | Alta manual (MAC + IP fija)                            |
| PATCH  | `/api/hosts/{mac}`                    | Cambiar IP, toggle static/tor/blocked, label, notes    |
| DELETE | `/api/hosts/{mac}`                    | Borrar entrada manual                                  |
| GET    | `/api/settings`                       | Toggles + config de red                                |
| PATCH  | `/api/settings`                       | Cambiar toggles                                        |
| POST   | `/api/apply`                          | Renderiza templates + recarga servicios (idempotente)  |
| GET    | `/api/audit?limit=100`                | Log de auditoría                                       |
| POST   | `/api/auth/login`  /  `/auth/logout`  | Sesión                                                 |

**Patrón "stage + apply"**: las mutaciones tocan la DB y marcan `dirty=true` en memoria. El usuario ve un banner "hay cambios sin aplicar" y pulsa **Apply** para que el `applier` regenere ficheros y recargue. Esto evita reloads en cascada al hacer 10 cambios seguidos y permite previsualizar el diff de `nft` antes de aplicar.

---

## 7. Pipeline de "apply"

```
DB ──► render Jinja ──► /etc/nftables.d/gateway.nft.new
   ──►                ──► /etc/dnsmasq.d/gateway.conf.new
   ──►                ──► /etc/wireguard/wg0.conf       (sólo si gestionamos WG; si lo gestiona WGDashboard, se omite)
   ──►                ──► /etc/tor/torrc.d/gateway.new

   validate (nft -c -f, dnsmasq --test)
       │
       ├─ ok  ──► swap atómico ──► systemctl reload nftables / dnsmasq / tor
       │                       ──► audit_log "apply ok"
       │
       └─ fail ──► descartar .new, NO tocar producción, devolver error con stderr
```

Si el reload falla post-swap, hay un **rollback automático** al último snapshot (`/var/lib/gateway/snapshots/<ts>/`).

---

## 8. Módulos y `gateway.toml`

```toml
# Identidad y red
[gateway]
name        = "gw-isolated-01"
wan_iface   = "eth0"
lan_iface   = "eth1"
lan_cidr    = "192.168.100.1/24"

# Toggles modulares — lo que install.sh activa, y lo que el panel deja modificar en runtime
[modules]
wireguard   = true
tor         = false
dhcp        = true
monitoring  = false

[wireguard]
listen_port = 51820
peer_cidr   = "10.66.66.0/24"
endpoint    = "vpn.example.com:51820"

[dhcp]
range       = "192.168.100.100,192.168.100.200,12h"

[panel]
bind        = "0.0.0.0:8443"
admin_user  = "admin"
# password se pide interactivamente en install.sh y se guarda hasheada

[tor]
trans_port  = 9040
dns_port    = 5353
```

Mismo TOML lo lee `install.sh` (qué módulos correr) y el panel al arrancar (estado inicial de toggles + config inmutable de red). Cambiar `lan_cidr` post-install requiere reinstalar — los toggles se cambian en caliente desde el panel.

---

## 9. Árbol del repo

```
gateway/
├── ARCHITECTURE.md                  ← este documento
├── README.md
├── install.sh                       ← orquestador idempotente
├── uninstall.sh
├── gateway.toml.example
│
├── modules/                         ← cada módulo es un script bash idempotente
│   ├── 00-base.sh                   ← sysctl, nftables base, paquetes comunes
│   ├── 10-network.sh                ← config eth0/eth1, dnsmasq
│   ├── 20-wireguard.sh              ← wg + WGDashboard (pip + systemd unit)
│   ├── 30-tor.sh                    ← tor + ip rule + tabla 100
│   ├── 40-panel.sh                  ← venv del panel, systemd unit, primera migración
│   └── 50-monitoring.sh             ← node_exporter + vnstat (opcional)
│
├── panel/
│   ├── pyproject.toml               ← FastAPI, jinja2, sqlmodel, argon2-cffi
│   ├── app/
│   │   ├── main.py
│   │   ├── config.py                ← lee gateway.toml
│   │   ├── db.py                    ← engine + migraciones (alembic-light propia)
│   │   ├── models.py
│   │   ├── auth.py
│   │   ├── routers/
│   │   │   ├── peers.py
│   │   │   ├── acl.py
│   │   │   ├── hosts.py
│   │   │   ├── settings.py
│   │   │   ├── status.py
│   │   │   └── audit.py
│   │   ├── services/
│   │   │   ├── applier.py           ← stage+apply, snapshots, rollback
│   │   │   ├── nft_render.py
│   │   │   ├── dnsmasq_render.py
│   │   │   ├── tor_apply.py
│   │   │   ├── wg_sync.py           ← lee la SQLite de WGDashboard
│   │   │   └── scanner.py           ← `ip neigh` + ARP, escribe internal_hosts
│   │   ├── templates_cfg/           ← Jinja para nft/dnsmasq/torrc
│   │   │   ├── nftables.j2
│   │   │   ├── dnsmasq.j2
│   │   │   └── torrc.j2
│   │   └── web/                     ← htmx + tailwind (CDN, sin build step)
│   │       ├── templates/
│   │       └── static/
│   └── migrations/
│       └── 0001_init.sql
│
├── systemd/
│   ├── gateway-panel.service
│   ├── gateway-scanner.service
│   └── gateway-scanner.timer        ← cada 30s
│
└── packer/                          ← (futuro) build automatizado del template Proxmox
    └── debian-gateway.pkr.hcl
```

---

## 10. Ciclo de replicación de un gateway nuevo

1. `qm clone <template-id> <new-id>` en Proxmox.
2. Editar `gateway.toml` dentro de la VM clonada (nombre, CIDRs, módulos a desactivar).
3. `sudo gateway-reconfigure` → re-corre los módulos cuyo estado en TOML cambió.
4. Panel arranca; primer login pide cambio de password.

Para un "gateway de aislamiento puro sin VPN": en `gateway.toml`, `[modules] wireguard=false`. El panel oculta esa sección, `install.sh` no instala WG ni WGDashboard, y `nft` se renderiza sin cadenas WG. Mismo binario, configuración distinta.

---

## 11. Decisiones abiertas (revisar antes de codear)

1. **WGDashboard vs `wg-easy`**: WGDashboard tiene más features (estadísticas, múltiples interfaces) pero más superficie. `wg-easy` es minimalista y tiene mejor API. Tu requisito original era WGDashboard, mantengo a menos que prefieras revisarlo.
2. **Auth del panel**: ¿basta con user+pass+TOTP, o quieres OIDC (Authelia/Authentik delante)? Para 2-3 devs, TOTP local es suficiente.
3. **Acceso al panel**: ¿se expone en `eth0` (WAN, con cert Let's Encrypt) o sólo a través del propio túnel WG en `wg0`? Recomiendo **sólo wg0** — los devs ya tienen VPN, no hace falta exponer otro panel a internet.
4. **WGDashboard se expone igual**: misma decisión, recomiendo lo mismo (sólo wg0).
5. **Tor por host interno**: requiere conocer el origen estable. DHCP fijo por MAC lo resuelve, pero hay que prohibir cambiar IP a mano dentro de la VM tor-ificada (un usuario que se cambia la IP escapa de la marca). ¿Aceptamos esta limitación o forzamos algo más estricto a nivel de bridge (ebtables)?
6. **Backups**: snapshot de `/var/lib/gateway/db.sqlite` cada apply + rotación. ¿Quieres también export periódico a otro host?

---

## 12. Siguiente paso propuesto

Si te encaja la arquitectura, el orden natural es:

1. `install.sh` + `modules/00-base.sh` + `10-network.sh` → VM funcional como router NAT puro, sin panel ni WG todavía. Validación de la base.
2. `20-wireguard.sh` → WGDashboard funcionando, peers conectan, sin ACLs (todo permitido).
3. `40-panel.sh` con sólo `peers` + `acl` + `apply` → empezamos a restringir.
4. `hosts` + scanner → visibilidad de la LAN interna.
5. `30-tor.sh` + toggles Tor → última capa.
6. `packer/` para automatizar la creación del template.

Cada paso entrega algo usable. Si en cualquier punto el diseño no encaja con la realidad, ajustamos antes de seguir.
