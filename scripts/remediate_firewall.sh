#!/usr/bin/env bash
# ==============================================================================
# DefenSys — Adaptive Firewall Remediation Script
# Lead Maintainer: Member 2 (Network & Firewall Security Lead)
# Platform Target: RHEL / Fedora / CentOS / Rocky / Alma / Debian / Ubuntu / Kali
#
# Description:
#   Dynamically detects the active host firewall manager (firewalld, ufw, iptables)
#   and applies adaptive hardening rules:
#   - Enables and starts dormant firewall daemons.
#   - Enforces default DENY / DROP inbound policies.
#   - Preserves secure management connectivity (SSH port 22).
#   - Purges cleartext protocols (Telnet, FTP, TFTP, RSH) and database ports
#     (MySQL 3306, Redis 6379, MongoDB 27017, Postgres 5432).
#   - Provides syntax verification (--verify) for DefenSys Module 3 rollback engine.
#
# Exit Codes:
#   0 = Success / Verification Passed
#   1 = General Error / Invalid Arguments
#   2 = Permission Denied (Root Required)
#   3 = Firewall Verification Failed (Triggers Module 3 Rollback)
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

# ------------------------------------------------------------------------------
# Pre-Flight Checks & Privilege Escalation
# ------------------------------------------------------------------------------
check_privileges() {
    if [[ $EUID -ne 0 ]]; then
        if command -v sudo >/dev/null 2>&1; then
            log_warn "Script not executed as root. Commands will be elevated with sudo."
            SUDO_CMD="sudo"
        else
            log_error "Root privileges are required to configure firewall rules. Please run with sudo or as root."
            exit 2
        fi
    else
        SUDO_CMD=""
    fi
}

# ------------------------------------------------------------------------------
# Dynamic Firewall Manager Detection
# ------------------------------------------------------------------------------
FIREWALL_TYPE="none"

detect_firewall() {
    if command -v firewall-cmd >/dev/null 2>&1; then
        FIREWALL_TYPE="firewalld"
    elif command -v ufw >/dev/null 2>&1; then
        FIREWALL_TYPE="ufw"
    elif command -v nft >/dev/null 2>&1; then
        FIREWALL_TYPE="nftables"
    elif command -v iptables >/dev/null 2>&1; then
        FIREWALL_TYPE="iptables"
    else
        FIREWALL_TYPE="none"
    fi
    log_info "Detected Host Firewall Manager: ${COLOR_CYAN}${FIREWALL_TYPE}${COLOR_RESET}"
}

# ------------------------------------------------------------------------------
# Verification Engine (For DefenSys Module 3 Syntax Verification & Rollback)
# ------------------------------------------------------------------------------
verify_firewall() {
    log_info "Running syntax and operational verification for: ${FIREWALL_TYPE}"

    case "$FIREWALL_TYPE" in
        firewalld)
            if ! $SUDO_CMD firewall-cmd --state >/dev/null 2>&1; then
                log_error "Verification Failed: firewalld daemon is not running."
                return 3
            fi
            if $SUDO_CMD firewall-cmd --check-config >/dev/null 2>&1; then
                log_success "firewalld configuration syntax check: VALID."
            else
                log_error "Verification Failed: firewalld reports configuration syntax errors."
                return 3
            fi
            ;;
        ufw)
            local status_out
            status_out=$($SUDO_CMD ufw status 2>&1)
            if echo "$status_out" | grep -qi "Status: active"; then
                log_success "UFW operational check: ACTIVE."
            else
                log_error "Verification Failed: UFW is inactive or syntax error encountered."
                return 3
            fi
            ;;
        iptables)
            if $SUDO_CMD iptables -S INPUT >/dev/null 2>&1; then
                log_success "iptables rule table check: VALID."
            else
                log_error "Verification Failed: iptables query failed."
                return 3
            fi
            ;;
        nftables)
            if $SUDO_CMD nft -c -f /etc/nftables.conf >/dev/null 2>&1 || $SUDO_CMD nft list ruleset >/dev/null 2>&1; then
                log_success "nftables ruleset check: VALID."
            else
                log_error "Verification Failed: nftables ruleset verification failed."
                return 3
            fi
            ;;
        *)
            log_error "Verification Failed: No supported firewall subsystem detected."
            return 3
            ;;
    esac

    log_success "All firewall verification checks passed successfully."
    return 0
}

# ------------------------------------------------------------------------------
# RHEL / Fedora / CentOS: Firewalld Remediation Actions
# ------------------------------------------------------------------------------
remediate_firewalld_harden() {
    log_info "Hardening RHEL / Fedora Firewalld environment..."

    # 1. Ensure firewalld is running and enabled
    if ! $SUDO_CMD systemctl is-active --quiet firewalld; then
        log_info "Starting firewalld service..."
        $SUDO_CMD systemctl enable --now firewalld
    fi

    # 2. Get active / default zone
    local zone
    zone=$($SUDO_CMD firewall-cmd --get-default-zone 2>/dev/null || echo "public")
    log_info "Targeting default zone: ${zone}"

    # 3. Ensure SSH management port remains accessible
    log_info "Preserving SSH management access in zone '${zone}'..."
    $SUDO_CMD firewall-cmd --permanent --zone="${zone}" --add-service=ssh || true

    # 4. Remove insecure / cleartext legacy services
    local insecure_services=("telnet" "ftp" "tftp" "rsh" "rlogin" "rexec")
    for srv in "${insecure_services[@]}"; do
        if $SUDO_CMD firewall-cmd --permanent --zone="${zone}" --query-service="${srv}" >/dev/null 2>&1; then
            log_warn "Removing cleartext service '${srv}' from zone '${zone}'..."
            $SUDO_CMD firewall-cmd --permanent --zone="${zone}" --remove-service="${srv}"
        fi
    done

    # 5. Remove exposed sensitive database and cache ports
    local sensitive_ports=("3306/tcp" "5432/tcp" "6379/tcp" "27017/tcp" "11211/tcp" "9200/tcp" "2375/tcp")
    for prt in "${sensitive_ports[@]}"; do
        if $SUDO_CMD firewall-cmd --permanent --zone="${zone}" --query-port="${prt}" >/dev/null 2>&1; then
            log_warn "Closing exposed sensitive port '${prt}' in zone '${zone}'..."
            $SUDO_CMD firewall-cmd --permanent --zone="${zone}" --remove-port="${prt}"
        fi
    done

    # 6. Reload rules
    log_info "Reloading firewalld configuration..."
    $SUDO_CMD firewall-cmd --reload

    log_success "firewalld baseline hardening complete."
}

remove_service_firewalld() {
    local service="$1"
    local zone
    zone=$($SUDO_CMD firewall-cmd --get-default-zone 2>/dev/null || echo "public")
    log_info "Removing service '${service}' from zone '${zone}'..."
    $SUDO_CMD firewall-cmd --permanent --zone="${zone}" --remove-service="${service}"
    $SUDO_CMD firewall-cmd --reload
    log_success "Service '${service}' removed from firewalld."
}

block_port_firewalld() {
    local port="$1"
    local proto="${2:-tcp}"
    local zone
    zone=$($SUDO_CMD firewall-cmd --get-default-zone 2>/dev/null || echo "public")
    log_info "Removing port '${port}/${proto}' from zone '${zone}'..."
    $SUDO_CMD firewall-cmd --permanent --zone="${zone}" --remove-port="${port}/${proto}" || true
    $SUDO_CMD firewall-cmd --reload
    log_success "Port '${port}/${proto}' closed in firewalld."
}

# ------------------------------------------------------------------------------
# Debian / Ubuntu / Kali: UFW Remediation Actions
# ------------------------------------------------------------------------------
remediate_ufw_harden() {
    log_info "Hardening Debian / Ubuntu / Kali UFW environment..."

    # 1. Set default policy: Deny incoming, Allow outgoing
    log_info "Setting default incoming policy: DENY"
    $SUDO_CMD ufw default deny incoming

    log_info "Setting default outgoing policy: ALLOW"
    $SUDO_CMD ufw default allow outgoing

    # 2. Preserve SSH management access (rate-limited if supported)
    log_info "Allowing SSH management access (port 22/tcp)..."
    $SUDO_CMD ufw allow 22/tcp comment 'DefenSys: Secure SSH'

    # 3. Explicitly deny cleartext and sensitive database ports
    local deny_ports=("21/tcp" "23/tcp" "69/udp" "3306/tcp" "5432/tcp" "6379/tcp" "27017/tcp" "11211/tcp")
    for prt in "${deny_ports[@]}"; do
        log_info "Denying inbound traffic on port ${prt}..."
        $SUDO_CMD ufw deny "${prt}" comment 'DefenSys: Block Insecure Service'
    done

    # 4. Enable UFW non-interactively
    log_info "Enabling UFW..."
    $SUDO_CMD ufw --force enable

    log_success "UFW baseline hardening complete."
}

remove_service_ufw() {
    local service="$1"
    log_info "Denying service '${service}' via UFW..."
    $SUDO_CMD ufw deny "${service}"
    log_success "Service '${service}' denied in UFW."
}

block_port_ufw() {
    local port="$1"
    local proto="${2:-tcp}"
    log_info "Denying port '${port}/${proto}' via UFW..."
    $SUDO_CMD ufw deny "${port}/${proto}"
    log_success "Port '${port}/${proto}' denied in UFW."
}

# ------------------------------------------------------------------------------
# Raw iptables Fallback Remediation Actions
# ------------------------------------------------------------------------------
remediate_iptables_harden() {
    log_info "Applying baseline hardening via raw iptables..."

    # 1. Allow established/related incoming traffic
    $SUDO_CMD iptables -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
    $SUDO_CMD iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # 2. Allow localhost traffic
    $SUDO_CMD iptables -C INPUT -i lo -j ACCEPT 2>/dev/null || \
    $SUDO_CMD iptables -A INPUT -i lo -j ACCEPT

    # 3. Allow SSH management port
    $SUDO_CMD iptables -C INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || \
    $SUDO_CMD iptables -A INPUT -p tcp --dport 22 -j ACCEPT

    # 4. Drop dangerous database and cleartext ports explicitly
    local drop_ports=(21 23 3306 6379 27017)
    for p in "${drop_ports[@]}"; do
        $SUDO_CMD iptables -C INPUT -p tcp --dport "$p" -j DROP 2>/dev/null || \
        $SUDO_CMD iptables -I INPUT 1 -p tcp --dport "$p" -j DROP
    done

    # 5. Set default inbound policy to DROP
    log_info "Setting iptables INPUT policy to DROP..."
    $SUDO_CMD iptables -P INPUT DROP

    log_success "iptables baseline hardening complete."
}

block_port_iptables() {
    local port="$1"
    local proto="${2:-tcp}"
    log_info "Dropping port '${port}/${proto}' via iptables..."
    $SUDO_CMD iptables -I INPUT 1 -p "$proto" --dport "$port" -j DROP
    log_success "Port '${port}/${proto}' blocked in iptables."
}

# ------------------------------------------------------------------------------
# Action Dispatcher
# ------------------------------------------------------------------------------
execute_harden() {
    case "$FIREWALL_TYPE" in
        firewalld) remediate_firewalld_harden ;;
        ufw)       remediate_ufw_harden ;;
        iptables)  remediate_iptables_harden ;;
        *)
            log_error "No supported firewall detected. Please install firewalld (RHEL) or ufw (Debian/Kali)."
            exit 1
            ;;
    esac
}

execute_block_port() {
    local port="$1"
    local proto="${2:-tcp}"
    case "$FIREWALL_TYPE" in
        firewalld) block_port_firewalld "$port" "$proto" ;;
        ufw)       block_port_ufw "$port" "$proto" ;;
        iptables)  block_port_iptables "$port" "$proto" ;;
        *)
            log_error "No supported firewall detected."
            exit 1
            ;;
    esac
}

execute_remove_service() {
    local service="$1"
    case "$FIREWALL_TYPE" in
        firewalld) remove_service_firewalld "$service" ;;
        ufw)       remove_service_ufw "$service" ;;
        *)
            log_error "Service removal not supported for '${FIREWALL_TYPE}'."
            exit 1
            ;;
    esac
}

# ------------------------------------------------------------------------------
# Usage Guidance
# ------------------------------------------------------------------------------
show_help() {
    cat << EOF
DefenSys — Adaptive Firewall Remediation Utility
Usage: $(basename "$0") [OPTIONS]

Options:
  --harden                     Apply baseline firewall hardening (enable daemon, default deny, allow SSH, close risky ports)
  --block-port <PORT> [PROTO]  Block/remove inbound port (default protocol: tcp)
  --remove-service <SERVICE>   Remove firewall service (e.g., telnet, ftp, http)
  --enable-firewall            Enable and start the detected firewall daemon
  --verify, --check            Run syntax and status verification check (used by Module 3 Rollback Engine)
  --dry-run                    Simulate remediation actions without making system changes
  -h, --help                   Display this help message

Examples:
  sudo ./scripts/remediate_firewall.sh --harden
  sudo ./scripts/remediate_firewall.sh --block-port 3306 tcp
  sudo ./scripts/remediate_firewall.sh --remove-service telnet
  sudo ./scripts/remediate_firewall.sh --verify
EOF
}

# ------------------------------------------------------------------------------
# Main Entry Point
# ------------------------------------------------------------------------------
main() {
    echo -e "${COLOR_CYAN}====================================================${COLOR_RESET}"
    echo -e "${COLOR_CYAN}   DefenSys — Automated Firewall Remediation Engine  ${COLOR_RESET}"
    echo -e "${COLOR_CYAN}====================================================${COLOR_RESET}"

    if [[ $# -eq 0 ]]; then
        # Default action when invoked by DefenSys without flags is full hardening
        ACTION="harden"
    fi

    local action="harden"
    local target_port=""
    local target_proto="tcp"
    local target_service=""
    local dry_run=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --harden)
                action="harden"
                shift
                ;;
            --block-port|--close-port)
                action="block_port"
                target_port="$2"
                if [[ -n "${3:-}" && "$3" != --* ]]; then
                    target_proto="$3"
                    shift 2
                else
                    shift
                fi
                ;;
            --remove-service)
                action="remove_service"
                target_service="$2"
                shift 2
                ;;
            --enable-firewall)
                action="enable"
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
    detect_firewall

    if [[ "$dry_run" == true ]]; then
        log_warn "[DRY-RUN] Simulation mode enabled. No firewall rules will be modified."
        log_info "Action to perform: ${action}"
        exit 0
    fi

    case "$action" in
        verify)
            verify_firewall
            exit $?
            ;;
        harden)
            execute_harden
            ;;
        block_port)
            if [[ -z "$target_port" ]]; then
                log_error "Missing port argument for --block-port"
                exit 1
            fi
            execute_block_port "$target_port" "$target_proto"
            ;;
        remove_service)
            if [[ -z "$target_service" ]]; then
                log_error "Missing service argument for --remove-service"
                exit 1
            fi
            execute_remove_service "$target_service"
            ;;
        enable)
            execute_harden
            ;;
    esac

    # Run verification after modification to ensure syntax validity
    log_info "Validating configuration after changes..."
    verify_firewall
    local verify_status=$?

    if [[ $verify_status -eq 0 ]]; then
        log_success "Remediation applied and verified successfully."
    else
        log_error "Remediation verification failed. Module 3 rollback recommended."
        exit 3
    fi
}

main "$@"
