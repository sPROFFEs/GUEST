#!/usr/bin/env bash
# Gateway installer — orchestrates module scripts based on gateway.toml.
# Idempotent: safe to re-run. Each module is responsible for its own idempotency.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/gateway.toml"
ONLY_MODULE=""
DRY_RUN=0

usage() {
    cat <<EOF
Usage: $0 [options]

Options:
  --config FILE     Path to gateway.toml (default: ./gateway.toml)
  --module NAME     Run only this module (e.g. 00-base, 10-network)
  --dry-run         Validate config and module syntax, change nothing
  -h, --help        Show this help

Modules run in this order (00-base and 10-network always; rest by toggle):
  00-base          packages, sysctl, dirs, base nftables skeleton
  10-network       LAN interface, dnsmasq, NAT (masquerade)
  20-wireguard     wg + WGDashboard (if [modules].wireguard = true)
  30-tor           tor TransPort + policy routing (if [modules].tor)
  40-panel         custom FastAPI panel + scanner timer (always)
  50-monitoring    node_exporter + vnstat (if [modules].monitoring)
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --config)   CONFIG_FILE="$2"; shift 2 ;;
        --module)   ONLY_MODULE="$2"; shift 2 ;;
        --dry-run)  DRY_RUN=1; shift ;;
        -h|--help)  usage; exit 0 ;;
        *)          echo "unknown arg: $1" >&2; usage >&2; exit 2 ;;
    esac
done

# --- log helpers ---
c_blue=$'\e[1;34m'; c_green=$'\e[1;32m'; c_yel=$'\e[1;33m'; c_red=$'\e[1;31m'; c_off=$'\e[0m'
log()  { printf '%s[*]%s %s\n' "$c_blue"  "$c_off" "$*"; }
ok()   { printf '%s[+]%s %s\n' "$c_green" "$c_off" "$*"; }
warn() { printf '%s[!]%s %s\n' "$c_yel"   "$c_off" "$*" >&2; }
err()  { printf '%s[x]%s %s\n' "$c_red"   "$c_off" "$*" >&2; }

# --- preflight ---
[[ $EUID -eq 0 ]] || { err "must run as root"; exit 1; }

if [[ ! -f "$CONFIG_FILE" ]]; then
    err "config not found: $CONFIG_FILE"
    err "copy gateway.toml.example to gateway.toml and edit it"
    exit 1
fi

# Load TOML into the env. We need python3 for this; on a fresh Debian 12 it's
# pre-installed in standard images, so this should never fail in practice.
command -v python3 >/dev/null || { err "python3 required (apt install python3)"; exit 1; }

ENV_FILE="$(mktemp)"
trap 'rm -f "$ENV_FILE"' EXIT

if ! python3 "${SCRIPT_DIR}/lib/toml-to-env.py" "$CONFIG_FILE" > "$ENV_FILE"; then
    err "failed to parse $CONFIG_FILE"
    exit 1
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

log "config loaded from: $CONFIG_FILE"
log "gateway name:       ${GATEWAY_NAME:-?}"
log "wan iface:          ${GATEWAY_WAN_IFACE:-?}"
log "lan iface:          ${GATEWAY_LAN_IFACE:-?}  (${GATEWAY_LAN_CIDR:-?})"
log "modules: wg=${MODULES_WIREGUARD:-false} tor=${MODULES_TOR:-false} dhcp=${MODULES_DHCP:-true} mon=${MODULES_MONITORING:-false}"

# --- module selection ---
declare -a MODULES
MODULES+=("00-base")
MODULES+=("10-network")
[[ "${MODULES_WIREGUARD:-false}" == "true" ]] && MODULES+=("20-wireguard")
[[ "${MODULES_TOR:-false}"       == "true" ]] && MODULES+=("30-tor")
MODULES+=("40-panel")
[[ "${MODULES_MONITORING:-false}" == "true" ]] && MODULES+=("50-monitoring")

run_module() {
    local mod="$1"
    local path="${SCRIPT_DIR}/modules/${mod}.sh"
    if [[ ! -f "$path" ]]; then
        warn "module not implemented yet: $mod (skipping)"
        return 0
    fi
    log "── running module: $mod ──"
    if [[ $DRY_RUN -eq 1 ]]; then
        bash -n "$path" && ok "$mod (syntax ok, dry-run)"
        return 0
    fi
    if bash "$path"; then
        ok "$mod"
    else
        err "$mod failed"
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

ok "install complete"
