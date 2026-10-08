#!/usr/bin/env bash
# ==============================================================================
# DefenSys — Generic Linux SSH Hardening Remediation Script
# Lead Maintainer: Member 1 (System & Configuration Security Lead)
# Platform Target: RHEL / Fedora / CentOS / Rocky / Alma / Debian / Ubuntu / Kali
#
# Description:
#   Hardens OpenSSH daemon settings in a distro-agnostic way:
#   - Sets PermitRootLogin no
#   - Sets PasswordAuthentication no
#   - Sets PubkeyAuthentication yes
#   - Writes changes to /etc/ssh/sshd_config.d/99-defensys.conf (preferred)
#     or falls back to editing /etc/ssh/sshd_config when drop-ins are unavailable
#   - Validates syntax with `sshd -t`
#   - Restarts the correct SSH service unit (ssh vs sshd)
#   - Provides --verify for DefenSys Module 3 rollback engine
#
# Exit Codes:
#   0 = Success / Verification Passed
#   1 = General Error / Invalid Arguments
#   2 = Permission Denied (Root Required)
#   3 = SSH Verification Failed (Triggers Module 3 Rollback)
# ==============================================================================

set -eo pipefail

# ------------------------------------------------------------------------------
# Output Formatting & Color Palette
# ------------------------------------------------------------------------------
if [[ -t 1 ]]; then
    COLOR_RESET="\033[0m"
    COLOR_RED="\033[1;31m"
    COLOR_GREEN="\033[1;32m"
    COLOR_YELLOW="\033[1;33m"
    COLOR_BLUE="\033[1;34m"
    COLOR_CYAN="\033[1;36m"
else
    COLOR_RESET=""
    COLOR_RED=""
    COLOR_GREEN=""
    COLOR_YELLOW=""
    COLOR_BLUE=""
    COLOR_CYAN=""
fi

log_info()    { echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} [$(date +'%Y-%m-%d %H:%M:%S')] $1"; }
log_success() { echo -e "${COLOR_GREEN}[SUCCESS]${COLOR_RESET} [$(date +'%Y-%m-%d %H:%M:%S')] $1"; }
log_warn()    { echo -e "${COLOR_YELLOW}[WARN]${COLOR_RESET} [$(date +'%Y-%m-%d %H:%M:%S')] $1"; }
log_error()   { echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} [$(date +'%Y-%m-%d %H:%M:%S')] $1" >&2; }

SSHD_CONFIG="${SSHD_CONFIG:-/etc/ssh/sshd_config}"
SSHD_DROPIN_DIR="${SSHD_DROPIN_DIR:-/etc/ssh/sshd_config.d}"
DEFENSYS_DROPIN="${DEFENSYS_DROPIN:-${SSHD_DROPIN_DIR}/99-defensys.conf}"
SUDO_CMD=""

# ------------------------------------------------------------------------------
# Pre-Flight Checks & Privilege Escalation
# ------------------------------------------------------------------------------
check_privileges() {
    if [[ $EUID -ne 0 ]]; then
        if command -v sudo >/dev/null 2>&1; then
            log_warn "Script not executed as root. Commands will be elevated with sudo."
            SUDO_CMD="sudo"
        else
            log_error "Root privileges are required to modify SSH configuration. Please run with sudo or as root."
            exit 2
        fi
    else
        SUDO_CMD=""
    fi
}

detect_os_family() {
    local id_like=""
    local os_id=""
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        id_like="${ID_LIKE:-}"
        os_id="${ID:-}"
    fi

    case "${os_id} ${id_like}" in
        *debian*|*ubuntu*|*kali*)
            echo "debian"
            ;;
        *rhel*|*fedora*|*centos*|*rocky*|*almalinux*|*amzn*)
            echo "rhel"
            ;;
        *)
            echo "generic"
            ;;
    esac
}

detect_ssh_service() {
    # Prefer distro-correct unit names; fall back to whatever is installed.
    local family
    family="$(detect_os_family)"

    if [[ "$family" == "debian" ]]; then
        if systemctl list-unit-files 2>/dev/null | grep -Eq '^ssh\.service'; then
            echo "ssh"
            return
        fi
        if systemctl list-unit-files 2>/dev/null | grep -Eq '^sshd\.service'; then
            echo "sshd"
            return
        fi
    else
        if systemctl list-unit-files 2>/dev/null | grep -Eq '^sshd\.service'; then
            echo "sshd"
            return
        fi
        if systemctl list-unit-files 2>/dev/null | grep -Eq '^ssh\.service'; then
            echo "ssh"
            return
        fi
    fi

    # Last-resort heuristics without systemctl
    if command -v service >/dev/null 2>&1; then
        if [[ -f /etc/init.d/ssh ]]; then
            echo "ssh"
            return
        fi
        if [[ -f /etc/init.d/sshd ]]; then
            echo "sshd"
            return
        fi
    fi

    echo "sshd"
}

sshd_binary() {
    if command -v sshd >/dev/null 2>&1; then
        command -v sshd
        return
    fi
    for candidate in /usr/sbin/sshd /sbin/sshd /usr/local/sbin/sshd; do
        if [[ -x "$candidate" ]]; then
            echo "$candidate"
            return
        fi
    done
    echo ""
}

# ------------------------------------------------------------------------------
# Verification (Module 3 rollback hook)
# ------------------------------------------------------------------------------
verify_ssh() {
    local sshd_bin
    sshd_bin="$(sshd_binary)"

    log_info "Running SSH configuration syntax verification..."

    if [[ -z "$sshd_bin" ]]; then
        log_error "Verification Failed: sshd binary not found on PATH."
        return 3
    fi

    if ! $SUDO_CMD "$sshd_bin" -t; then
        log_error "Verification Failed: sshd -t reported a configuration syntax error."
        return 3
    fi

    local service_name
    service_name="$(detect_ssh_service)"

    if command -v systemctl >/dev/null 2>&1; then
        if ! $SUDO_CMD systemctl is-active --quiet "${service_name}"; then
            log_warn "SSH service '${service_name}' is not active (syntax is valid)."
        else
            log_success "SSH service '${service_name}' is active."
        fi
    fi

    log_success "SSH configuration verification passed (sshd -t OK)."
    return 0
}

# ------------------------------------------------------------------------------
# Remediation helpers
# ------------------------------------------------------------------------------
write_defensys_dropin() {
    local content
    content=$(cat <<'EOF'
# Managed by DefenSys Module 1 — do not edit manually unless intentional
# Generated remediation overlay (highest lexical priority under sshd_config.d)
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
EOF
)

    if [[ ! -d "$SSHD_DROPIN_DIR" ]]; then
        log_info "Creating drop-in directory: ${SSHD_DROPIN_DIR}"
        $SUDO_CMD mkdir -p "$SSHD_DROPIN_DIR"
    fi

    log_info "Writing hardened overlay to ${DEFENSYS_DROPIN}"
    echo "$content" | $SUDO_CMD tee "$DEFENSYS_DROPIN" >/dev/null
    $SUDO_CMD chmod 644 "$DEFENSYS_DROPIN"
}

# Update or append a directive inside the main sshd_config (fallback path)
set_sshd_directive() {
    local key="$1"
    local value="$2"
    local file="$3"

    if $SUDO_CMD grep -Eq "^[[:space:]]*#?[[:space:]]*${key}([[:space:]]+|$)" "$file"; then
        # Comment out all existing occurrences, then append the hardened value once
        $SUDO_CMD sed -i -E "s/^[[:space:]]*#?[[:space:]]*${key}([[:space:]].*)?$/# &/" "$file"
    fi

    if ! $SUDO_CMD grep -Eq "^[[:space:]]*${key}[[:space:]]+${value}[[:space:]]*$" "$file"; then
        echo "${key} ${value}" | $SUDO_CMD tee -a "$file" >/dev/null
    fi
}

harden_main_sshd_config() {
    if [[ ! -f "$SSHD_CONFIG" ]]; then
        log_error "SSH main config not found: ${SSHD_CONFIG}"
        exit 1
    fi

    local backup="${SSHD_CONFIG}.bak_defensys_$(date +%Y%m%d%H%M%S)"
    log_info "Backing up ${SSHD_CONFIG} -> ${backup}"
    $SUDO_CMD cp -a "$SSHD_CONFIG" "$backup"

    set_sshd_directive "PermitRootLogin" "no" "$SSHD_CONFIG"
    set_sshd_directive "PasswordAuthentication" "no" "$SSHD_CONFIG"
    set_sshd_directive "PubkeyAuthentication" "yes" "$SSHD_CONFIG"
}

restart_ssh_service() {
    local service_name
    service_name="$(detect_ssh_service)"
    log_info "Restarting SSH service unit: ${service_name}"

    if command -v systemctl >/dev/null 2>&1; then
        if ! $SUDO_CMD systemctl restart "${service_name}"; then
            log_error "Failed to restart ${service_name} via systemctl."
            return 1
        fi
        return 0
    fi

    if command -v service >/dev/null 2>&1; then
        if ! $SUDO_CMD service "${service_name}" restart; then
            log_error "Failed to restart ${service_name} via service."
            return 1
        fi
        return 0
    fi

    log_warn "Neither systemctl nor service found; skipping restart (config still written)."
    return 0
}

execute_harden() {
    local family
    family="$(detect_os_family)"
    log_info "Detected OS family: ${family}"

    # Prefer drop-in overlay so we do not clobber vendor/cloud-init main configs
    if [[ -d "$SSHD_DROPIN_DIR" ]] || mkdir -p "$SSHD_DROPIN_DIR" 2>/dev/null || $SUDO_CMD mkdir -p "$SSHD_DROPIN_DIR"; then
        write_defensys_dropin
    else
        log_warn "Drop-in directory unavailable; falling back to ${SSHD_CONFIG}"
        harden_main_sshd_config
    fi

    log_info "Validating configuration before restart..."
    if ! verify_ssh; then
        log_error "Pre-restart verification failed. Refusing to restart SSH."
        exit 3
    fi

    restart_ssh_service

    log_info "Post-restart verification..."
    if ! verify_ssh; then
        log_error "Post-restart verification failed. Module 3 rollback recommended."
        exit 3
    fi

    log_success "SSH hardening applied successfully."
}

# ------------------------------------------------------------------------------
# Usage Guidance
# ------------------------------------------------------------------------------
show_help() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Options:
  --harden                     Apply baseline SSH hardening (root login off, password auth off, pubkey on)
  --verify, --check            Run syntax verification via sshd -t (used by Module 3 Rollback Engine)
  --dry-run                    Simulate remediation actions without making system changes
  -h, --help                   Display this help message

Examples:
  sudo ./scripts/remediate_ssh.sh --harden
  sudo ./scripts/remediate_ssh.sh --verify
EOF
}

# ------------------------------------------------------------------------------
# Main Entry Point
# ------------------------------------------------------------------------------
main() {
    echo -e "${COLOR_CYAN}====================================================${COLOR_RESET}"
    echo -e "${COLOR_CYAN}   DefenSys — Automated SSH Remediation Engine       ${COLOR_RESET}"
    echo -e "${COLOR_CYAN}====================================================${COLOR_RESET}"

    local action="harden"
    local dry_run=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --harden)
                action="harden"
                shift
                ;;
            --verify|--check)
                action="verify"
                shift
                ;;
            --dry-run)
                dry_run=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    check_privileges

    if [[ "$dry_run" == true ]]; then
        log_warn "[DRY-RUN] Simulation mode enabled. No SSH configuration will be modified."
        log_info "Action to perform: ${action}"
        log_info "Target drop-in   : ${DEFENSYS_DROPIN}"
        log_info "Detected service : $(detect_ssh_service)"
        exit 0
    fi

    case "$action" in
        verify)
            verify_ssh
            exit $?
            ;;
        harden)
            execute_harden
            ;;
    esac
}

main "$@"
