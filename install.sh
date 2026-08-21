#!/usr/bin/env bash
set -Eeuo pipefail

SELF_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SELF_DIR}/gateway.toml"
ONLY_MODULE=""
DRY_RUN=0

blue=$'\033[1;34m'; green=$'\033[1;32m'; yellow=$'\033[1;33m'; red=$'\033[1;31m'; reset=$'\033[0m'
log()  { printf '%s[*]%s %s\n' "$blue" "$reset" "$*"; }
ok()   { printf '%s[+]%s %s\n' "$green" "$reset" "$*"; }
warn() { printf '%s[!]%s %s\n' "$yellow" "$reset" "$*" >&2; }
fail() { printf '%s[x]%s %s\n' "$red" "$reset" "$*" >&2; exit 1; }

usage() {
    cat <<EOF_USAGE
Uso: $0 [opciones]
  --config FILE     gateway.toml a utilizar
  --module NAME     ejecutar solo un modulo
  --dry-run         validar sintaxis sin aplicar cambios
  -h, --help        ayuda
EOF_USAGE
}

while (( $# )); do
    case "$1" in
        --config) [[ $# -ge 2 ]] || fail "falta FILE tras --config"; CONFIG_FILE="$2"; shift 2 ;;
        --module) [[ $# -ge 2 ]] || fail "falta NAME tras --module"; ONLY_MODULE="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) fail "argumento desconocido: $1" ;;
    esac
done

[[ ${EUID} -eq 0 ]] || fail "ejecuta el instalador como root"
[[ -f "$CONFIG_FILE" ]] || fail "no existe la configuracion: $CONFIG_FILE"
[[ -f "${SELF_DIR}/lib/toml-to-env.py" ]] || fail "falta ${SELF_DIR}/lib/toml-to-env.py"

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
        apt-get install -y --no-install-recommends "${need[@]}"
    fi

    # 40-panel.sh escribe un drop-in aqui.
    install -d -m 0750 -o root -g root /etc/sudoers.d
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
python3 "${SELF_DIR}/lib/toml-to-env.py" "$CONFIG_FILE" > "$ENV_FILE" || \
    fail "no se pudo leer $CONFIG_FILE"
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

log "config: ${CONFIG_FILE}"
log "WAN: ${GATEWAY_WAN_IFACE:-?} | LAN: ${GATEWAY_LAN_IFACE:-?}"
log "panel: ${PANEL_BIND_ADDR:-?}:${PANEL_BIND_PORT:-?} | expose_on_wan=${PANEL_EXPOSE_ON_WAN:-false} | tls=${PANEL_TLS:-false}"

MODULES=(00-base 10-network)
[[ "${MODULES_WIREGUARD:-false}" == true ]] && MODULES+=(20-wireguard)
[[ "${MODULES_TOR:-false}" == true ]] && MODULES+=(30-tor)
MODULES+=(40-panel)
[[ "${MODULES_MONITORING:-false}" == true ]] && MODULES+=(50-monitoring)

run_module() {
    local name="$1"
    local file="${SELF_DIR}/modules/${name}.sh"
    [[ -f "$file" ]] || { warn "modulo inexistente: $name; se omite"; return 0; }

    log "ejecutando modulo $name"
    if (( DRY_RUN )); then
        bash -n "$file"
        ok "$name: sintaxis OK"
        return 0
    fi

    bash "$file" || fail "$name fallo"
    ok "$name"
}

# Fallback de firewall. 20-wireguard deberia crear esta regla, pero esta
# comprobacion hace que el instalador se autocorrija si el fragmento no la deja activa.
ensure_panel_wan_firewall() {
    [[ "${PANEL_EXPOSE_ON_WAN:-false}" == true ]] || {
        rm -f /etc/nftables.d/25-panel-wan-fallback.nft
        return 0
    }

    [[ -n "${GATEWAY_WAN_IFACE:-}" ]] || fail "GATEWAY_WAN_IFACE vacio"
    [[ -n "${PANEL_BIND_PORT:-}" ]] || fail "PANEL_BIND_PORT vacio"

    local ports="${PANEL_BIND_PORT}"
    if [[ "${MODULES_WIREGUARD:-false}" == true && -n "${PANEL_WGD_BIND_PORT:-}" ]]; then
        ports="${PANEL_BIND_PORT}, ${PANEL_WGD_BIND_PORT}"
    fi

    # Si el fragmento oficial ya contiene la apertura WAN, no duplicamos reglas.
    if [[ -f /etc/nftables.d/20-wireguard.nft ]] && \
       grep -Fq "iifname \"${GATEWAY_WAN_IFACE}\" tcp dport" /etc/nftables.d/20-wireguard.nft; then
        rm -f /etc/nftables.d/25-panel-wan-fallback.nft
    else
        warn "20-wireguard.nft no contiene la apertura WAN; creando fallback persistente"
        cat > /etc/nftables.d/25-panel-wan-fallback.nft <<EOF_NFT
# Autogenerado por install-fixed.sh
# Fallback para [panel].expose_on_wan = true
table inet gateway {
    chain input {
        iifname "${GATEWAY_WAN_IFACE}" tcp dport { ${ports} } accept
    }
}
EOF_NFT
    fi

    nft -c -f /etc/nftables.conf || fail "la configuracion nftables resultante no es valida"
    nft -f /etc/nftables.conf

    if nft list chain inet gateway input 2>/dev/null | \
       grep -Fq "iifname \"${GATEWAY_WAN_IFACE}\" tcp dport"; then
        ok "firewall WAN del panel activo"
    else
        fail "el ruleset sigue sin permitir el panel por ${GATEWAY_WAN_IFACE}"
    fi
}

verify_panel() {
    (( DRY_RUN )) && return 0
    [[ -n "${PANEL_BIND_PORT:-}" ]] || return 0

    if systemctl is-active --quiet gateway-panel; then
        ok "gateway-panel esta activo"
    else
        warn "gateway-panel no esta activo"
        systemctl status gateway-panel --no-pager -l || true
        return 1
    fi

    if ss -lntH | awk '{print $4}' | grep -Eq "(^|:)${PANEL_BIND_PORT}$"; then
        ok "panel escuchando en TCP/${PANEL_BIND_PORT}"
    else
        warn "no se detecta ningun listener en TCP/${PANEL_BIND_PORT}"
        return 1
    fi
}

if [[ -n "$ONLY_MODULE" ]]; then
    run_module "$ONLY_MODULE"
else
    for m in "${MODULES[@]}"; do
        run_module "$m"
    done
fi

if (( ! DRY_RUN )); then
    ensure_panel_wan_firewall
    verify_panel || true
fi

ok "instalacion completada"

if [[ "${PANEL_TLS:-false}" == true ]]; then
    printf 'Panel: https://<IP-de-%s>:%s\n' "${GATEWAY_WAN_IFACE:-WAN}" "${PANEL_BIND_PORT:-8443}"
else
    printf 'Panel: http://<IP-de-%s>:%s\n' "${GATEWAY_WAN_IFACE:-WAN}" "${PANEL_BIND_PORT:-8443}"
fi
