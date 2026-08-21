#!/usr/bin/env bash
# GUEST installer wrapper/fixed version.
# Adds:
#   - --reset: reset/create the panel admin password safely
#   - sudo/kmod/openssl bootstrap dependencies
#   - explicit nf_conntrack loading before 00-base sysctl
#   - firewall verification/fallback for panel exposure on WAN
#   - panel listener/service verification
set -Eeuo pipefail

SELF_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SELF_DIR}/gateway.toml"
ONLY_MODULE=""
DRY_RUN=0
RESET_MODE=0

blue=$'\033[1;34m'
green=$'\033[1;32m'
yellow=$'\033[1;33m'
red=$'\033[1;31m'
reset=$'\033[0m'

log()  { printf '%s[*]%s %s\n' "$blue" "$reset" "$*"; }
ok()   { printf '%s[+]%s %s\n' "$green" "$reset" "$*"; }
warn() { printf '%s[!]%s %s\n' "$yellow" "$reset" "$*" >&2; }
fail() { printf '%s[x]%s %s\n' "$red" "$reset" "$*" >&2; exit 1; }

usage() {
    cat <<EOF_USAGE
Uso: $0 [opciones]

Opciones:
  --config FILE     gateway.toml a utilizar
  --module NAME     ejecutar solo un modulo
  --dry-run         validar sintaxis sin aplicar cambios
  --reset           cambiar la contrasena del usuario admin del panel
  -h, --help        mostrar esta ayuda

Ejemplos:
  sudo $0
  sudo $0 --module 40-panel
  sudo $0 --reset
EOF_USAGE
}

while (( $# )); do
    case "$1" in
        --config)
            [[ $# -ge 2 ]] || fail "falta FILE tras --config"
            CONFIG_FILE="$2"
            shift 2
            ;;
        --module)
            [[ $# -ge 2 ]] || fail "falta NAME tras --module"
            ONLY_MODULE="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --reset)
            RESET_MODE=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            fail "argumento desconocido: $1"
            ;;
    esac
done

[[ ${EUID} -eq 0 ]] || fail "ejecuta el instalador como root (sudo $0 ...)"

# ---------------------------------------------------------------------------
# --reset
# ---------------------------------------------------------------------------
# The upstream panel CLI exposes create-admin but no reset-password command.
# We therefore use the panel's own auth.hash_password() and update pw_hash
# directly. This preserves the existing user row instead of deleting it.
reset_admin_password() {
    local db="/var/lib/gateway/db.sqlite"
    local app_dir="/opt/gateway-panel"
    local py="${app_dir}/venv/bin/python"
    local username="admin"
    local pass1 pass2 backup

    [[ -f "$db" ]] || fail "no existe la base de datos del panel: $db"
    [[ -d "$app_dir" ]] || fail "no existe el panel instalado: $app_dir"
    [[ -x "$py" ]] || fail "no existe el Python del panel: $py"
    id gateway >/dev/null 2>&1 || fail "no existe el usuario de sistema gateway"
    command -v runuser >/dev/null 2>&1 || fail "falta runuser (paquete util-linux)"

    if ! command -v sqlite3 >/dev/null 2>&1; then
        log "instalando sqlite3 para poder hacer backup de la base de datos"
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y --no-install-recommends sqlite3
    fi

    printf 'Nueva contrasena para %s: ' "$username"
    IFS= read -r -s pass1
    printf '\nRepite la nueva contrasena: '
    IFS= read -r -s pass2
    printf '\n'

    [[ -n "$pass1" ]] || fail "la contrasena no puede estar vacia"
    [[ "$pass1" == "$pass2" ]] || fail "las contrasenas no coinciden"

    backup="${db}.bak.$(date +%Y%m%d-%H%M%S)"

    if ! sqlite3 "$db" ".backup '$backup'"; then
        unset pass1 pass2
        fail "no se pudo crear la copia de seguridad de $db"
    fi

    chown --reference="$db" "$backup" 2>/dev/null || true
    chmod --reference="$db" "$backup" 2>/dev/null || true

    ok "backup creado: $backup"

    # Password is sent on stdin so it is not exposed as a command-line argument.
    if ! printf '%s' "$pass1" | (
        cd "$app_dir"

        runuser -u gateway -- "$py" -c '
import sys
from pathlib import Path
from app import auth, db as dbmod

db_path = Path(sys.argv[1])
username = sys.argv[2]
password = sys.stdin.read()

if not password:
    raise SystemExit("empty password")

conn = dbmod.connect(db_path)

try:
    row = conn.execute(
        "SELECT username FROM users WHERE username = ?",
        (username,),
    ).fetchone()

    pw_hash = auth.hash_password(password)

    if row is None:
        conn.execute(
            "INSERT INTO users(username, pw_hash, role) VALUES(?, ?, ?)",
            (username, pw_hash, "admin"),
        )
        action = "created"
    else:
        conn.execute(
            "UPDATE users SET pw_hash = ?, role = ? WHERE username = ?",
            (pw_hash, "admin", username),
        )
        action = "updated"

    conn.commit()

finally:
    conn.close()

print(f"admin password {action}: {username}")
' "$db" "$username"

    ); then
        unset pass1 pass2
        fail "no se pudo cambiar la contrasena; el backup queda en: $backup"
    fi

    unset pass1 pass2

    if systemctl cat gateway-panel.service >/dev/null 2>&1; then
        systemctl restart gateway-panel || \
            fail "password cambiada, pero gateway-panel no pudo reiniciarse"

        ok "gateway-panel reiniciado"
    else
        warn "gateway-panel.service no existe; la contrasena se cambio igualmente"
    fi

    ok "contrasena del usuario admin cambiada correctamente"
    printf 'Usuario: %s\n' "$username"
}

if (( RESET_MODE )); then
    [[ -z "$ONLY_MODULE" ]] || \
        fail "--reset no se puede combinar con --module"

    (( ! DRY_RUN )) || \
        fail "--reset no se puede combinar con --dry-run"

    reset_admin_password
    exit 0
fi


# ---------------------------------------------------------------------------
# Normal installation
# ---------------------------------------------------------------------------

[[ -f "$CONFIG_FILE" ]] || \
    fail "no existe la configuracion: $CONFIG_FILE"

[[ -f "${SELF_DIR}/lib/toml-to-env.py" ]] || \
    fail "falta ${SELF_DIR}/lib/toml-to-env.py"


ensure_bootstrap_packages() {
    local need=()

    command -v python3  >/dev/null 2>&1 || need+=(python3)
    command -v modprobe >/dev/null 2>&1 || need+=(kmod)
    command -v visudo   >/dev/null 2>&1 || need+=(sudo)
    command -v openssl  >/dev/null 2>&1 || need+=(openssl)

    if ((${#need[@]})); then
        log "instalando prerrequisitos que faltan: ${need[*]}"

        export DEBIAN_FRONTEND=noninteractive

        apt-get update -qq

        apt-get install -y \
            --no-install-recommends \
            "${need[@]}"
    fi

    # 40-panel.sh writes a sudoers drop-in here.
    install -d \
        -m 0750 \
        -o root \
        -g root \
        /etc/sudoers.d
}


ensure_conntrack() {
    log "comprobando nf_conntrack"

    if ! modprobe nf_conntrack 2>/dev/null; then
        fail "no se pudo cargar nf_conntrack; comprueba el kernel/entorno de virtualizacion"
    fi

    local key

    for key in \
        nf_conntrack_udp_timeout \
        nf_conntrack_udp_timeout_stream \
        nf_conntrack_tcp_timeout_established
    do

        [[ -e "/proc/sys/net/netfilter/${key}" ]] || \
            fail "falta /proc/sys/net/netfilter/${key} incluso despues de cargar nf_conntrack"

    done

    ok "nf_conntrack disponible"
}


ensure_bootstrap_packages
ensure_conntrack


ENV_FILE="$(mktemp)"

trap 'rm -f "$ENV_FILE"' EXIT


python3 \
    "${SELF_DIR}/lib/toml-to-env.py" \
    "$CONFIG_FILE" \
    > "$ENV_FILE" || \
    fail "no se pudo leer $CONFIG_FILE"


set -a

# shellcheck disable=SC1090
source "$ENV_FILE"

set +a


log "config: ${CONFIG_FILE}"

log \
    "WAN: ${GATEWAY_WAN_IFACE:-?} | LAN: ${GATEWAY_LAN_IFACE:-?}"

log \
    "panel: ${PANEL_BIND_ADDR:-?}:${PANEL_BIND_PORT:-?} | expose_on_wan=${PANEL_EXPOSE_ON_WAN:-false} | tls=${PANEL_TLS:-false}"


MODULES=(
    00-base
    10-network
)

[[ "${MODULES_WIREGUARD:-false}" == true ]] && \
    MODULES+=(20-wireguard)

[[ "${MODULES_TOR:-false}" == true ]] && \
    MODULES+=(30-tor)

MODULES+=(40-panel)

[[ "${MODULES_MONITORING:-false}" == true ]] && \
    MODULES+=(50-monitoring)


run_module() {
    local name="$1"
    local file="${SELF_DIR}/modules/${name}.sh"

    [[ -f "$file" ]] || {
        warn "modulo inexistente: $name; se omite"
        return 0
    }

    log "ejecutando modulo $name"

    if (( DRY_RUN )); then
        bash -n "$file"

        ok "$name: sintaxis OK"

        return 0
    fi

    bash "$file" || \
        fail "$name fallo"

    ok "$name"
}


# 20-wireguard.sh should create this rule when expose_on_wan=true.
# This verifies that the rule is actually present and supplies a persistent
# fallback when necessary.
ensure_panel_wan_firewall() {

    [[ "${PANEL_EXPOSE_ON_WAN:-false}" == true ]] || {

        rm -f \
            /etc/nftables.d/25-panel-wan-fallback.nft

        return 0
    }


    [[ -n "${GATEWAY_WAN_IFACE:-}" ]] || \
        fail "GATEWAY_WAN_IFACE vacio"


    [[ -n "${PANEL_BIND_PORT:-}" ]] || \
        fail "PANEL_BIND_PORT vacio"


    local ports="${PANEL_BIND_PORT}"


    if [[ "${MODULES_WIREGUARD:-false}" == true && \
          -n "${PANEL_WGD_BIND_PORT:-}" ]]
    then

        ports="${PANEL_BIND_PORT}, ${PANEL_WGD_BIND_PORT}"

    fi


    # If the official fragment already includes the WAN rule,
    # avoid duplicates.
    if [[ -f /etc/nftables.d/20-wireguard.nft ]] && \
       grep -Fq \
           "iifname \"${GATEWAY_WAN_IFACE}\" tcp dport" \
           /etc/nftables.d/20-wireguard.nft
    then

        rm -f \
            /etc/nftables.d/25-panel-wan-fallback.nft

        ok \
            "20-wireguard.nft ya contiene la apertura WAN del panel"

    else

        warn \
            "no se encontro la apertura WAN del panel; creando fallback persistente"


        install -d \
            -m 0755 \
            /etc/nftables.d


        cat > /etc/nftables.d/25-panel-wan-fallback.nft <<EOF_NFT
# Autogenerado por install-fixed-reset.sh
# Fallback para [panel].expose_on_wan = true

table inet gateway {

    chain input {

        iifname "${GATEWAY_WAN_IFACE}" tcp dport { ${ports} } accept

    }

}
EOF_NFT

    fi


    nft -c \
        -f /etc/nftables.conf || \
        fail "la configuracion nftables resultante no es valida"


    systemctl reload nftables 2>/dev/null || \
        nft -f /etc/nftables.conf


    if nft list chain inet gateway input 2>/dev/null | \
       grep -Fq \
           "iifname \"${GATEWAY_WAN_IFACE}\" tcp dport"
    then

        ok \
            "firewall WAN del panel activo en ${GATEWAY_WAN_IFACE}"

    else

        fail \
            "el ruleset sigue sin permitir el panel por ${GATEWAY_WAN_IFACE}"

    fi
}


verify_panel() {

    (( DRY_RUN )) && \
        return 0


    [[ -n "${PANEL_BIND_PORT:-}" ]] || \
        return 0


    if systemctl is-active \
        --quiet \
        gateway-panel
    then

        ok \
            "gateway-panel esta activo"

    else

        warn \
            "gateway-panel no esta activo"


        systemctl status \
            gateway-panel \
            --no-pager \
            -l || true


        return 1

    fi


    if ss -lntH | \
       awk '{print $4}' | \
       grep -Eq \
           "(^|:)${PANEL_BIND_PORT}$"
    then

        ok \
            "panel escuchando en TCP/${PANEL_BIND_PORT}"

    else

        warn \
            "no se detecta ningun listener en TCP/${PANEL_BIND_PORT}"

        return 1

    fi
}


if [[ -n "$ONLY_MODULE" ]]; then

    run_module \
        "$ONLY_MODULE"

else

    for m in "${MODULES[@]}"; do

        run_module \
            "$m"

    done

fi


if (( ! DRY_RUN )); then

    # Only run panel-specific post checks when a complete install
    # or a related module was requested.
    if [[ -z "$ONLY_MODULE" || \
          "$ONLY_MODULE" == "20-wireguard" || \
          "$ONLY_MODULE" == "40-panel" ]]
    then

        ensure_panel_wan_firewall

        verify_panel || true

    fi

fi


ok \
    "instalacion completada"


if [[ -z "$ONLY_MODULE" || \
      "$ONLY_MODULE" == "40-panel" || \
      "$ONLY_MODULE" == "20-wireguard" ]]
then

    if [[ "${PANEL_TLS:-false}" == true ]]; then

        printf \
            'Panel: https://<IP-de-%s>:%s\n' \
            "${GATEWAY_WAN_IFACE:-WAN}" \
            "${PANEL_BIND_PORT:-8443}"

    else

        printf \
            'Panel: http://<IP-de-%s>:%s\n' \
            "${GATEWAY_WAN_IFACE:-WAN}" \
            "${PANEL_BIND_PORT:-8443}"

    fi

fi
