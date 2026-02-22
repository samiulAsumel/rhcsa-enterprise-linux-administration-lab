#!/usr/bin/env bash
set -euo pipefail

# Enterprise User and Group Management System
# Version: 2.1.1
# Purpose: Production-grade user/group management with security policies

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_FILE="${BASE_DIR}/etc/user-mgmt.conf"
LOG_FILE="/var/log/user-mgmt.log"

# Source libraries
source "${BASE_DIR}/lib/logging.sh"
source "${BASE_DIR}/lib/validation.sh"
source "${BASE_DIR}/lib/user-operations.sh"

# Default configuration
declare -A CONFIG=(
    [default_shell]="/bin/bash"
    [home_base]="/home"
    [password_max_days]=90
    [password_min_days]=3
    [password_warn_days]=5
    [inactive_days]=30
    [sudoers_dir]="/etc/sudoers.d"
)

# Load configuration
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        # shellcheck source=/dev/null
        source "$CONFIG_FILE"
        log_info "Loaded configuration from ${CONFIG_FILE}"
    else
        log_warning "Configuration file not found, using default values"
    fi
}

# Display help menu
show_help() {
    cat << EOF
    Enterprise User and Group Management System

    Usage: $0 [OPTIONS] COMMAND [ARGS]

    Commands:
    create-user USERNAME    Create a single user with specified name
    create-users           Create standard development users
    create-groups          Create required groups
    assign-groups          Assign users to appropriate groups
    configure-sudo         Configure sudo access for admins
    set-password-policies  Apply password expiration policies
    lock-user   USER       Lock specified user account
    unlock-user USER       Unlock specified user account
    status                 Show current user and group configuration
    validate-config        Validate current setup against requirements

    Options:
    -c, --config FILE       Use alternative configuration file
    -l, --log FILE          Specify log file location
    -d, --dry-run           Show what would be done without making changes
    -q, --quiet             Suppress non-error output
    -v, --verbose           Enable verbose output
    -h, --help              Display this help message
    --version               Display version information

    Examples:
    $0 create-user john
    $0 create-user alice --group developers
    $0 create-users
    $0 --dry-run configure-sudo
    $0 lock-user dev2
    $0 set-password-policy --force

    Exit codes:
    0 - Success
    1 - General error
    2 - Invalid input
    3 - Permission denied
    4 - Configuration error
    5 - User/group operation failed
EOF
}

# Parse command line arguments
parse_args() {
    DRY_RUN=false
    VERBOSE=false
    QUIET=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -l|--log)
                LOG_FILE="$2"
                shift 2
                ;;
            -d|--dry-run)
                DRY_RUN=true
                shift
                ;;
            -q|--quiet)
                QUIET=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            --version)
                echo "User Management Script v2.1.1"
                exit 0
                ;;
            create-user|create-users|create-groups|assign-groups|configure-sudo|set-password-policy|lock-user|unlock-user|status|validate)
    COMMAND="$1"
    shift
    # Handle command-specific arguments
    case $COMMAND in
        lock-user|unlock-user)
            if [[ $# -lt 1 ]]; then
                log_error "Username required for $COMMAND"
                exit 2
            fi
            TARGET_USER="$1"
            shift
            ;;
        create-user)
            if [[ $# -lt 1 ]]; then
                log_error "Username required for create-user"
                exit 2
            fi
            TARGET_USER="$1"
            shift
            ;;
        esac
        ;;
        *)
            log_error "Unknown option or command: $1"
            show_help
            exit 2
            ;;
    esac
done

if [[ -z "${COMMAND:-}" ]]; then
    log_error "No command specified"
    show_help
    exit 2
fi
}

# Initialize logging
init_logging() {
    LOG_LEVEL="INFO"
    $VERBOSE && LOG_LEVEL="DEBUG"
    $QUIET && LOG_LEVEL="ERROR"

    # Ensure log directory exists
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
}

# main execution
main() {
    init_logging
    load_config

    log_debug "Starting user-mgmt with command: $COMMAND"
    log_debug "Dry run: $DRY_RUN"

    case $COMMAND in
        create-user)
            create_single_user "$TARGET_USER"
            ;;
        create-users)
            create_development_users
            ;;
        create-groups)
            create_required_groups
            ;;
        assign-groups)
            assign_users_to_groups
            ;;
        configure-sudo)
            configure_sudo_access
            ;;
        set-password-policy)
            apply_password_policies
            ;;
        lock-user)
            lock_user_account "$TARGET_USER"
            ;;
        unlock-user)
            unlock_user_account "$TARGET_USER"
            ;;
        status)
            show_system_status
            ;;
        validate)
            validate_configuration
            ;;
    esac

    log_info "Command '$COMMAND' completed successfully"
}

# Trap errors
trap 'log_error "Error on line $LINENO"; exit 1' ERR

# Run main if not sources
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    parse_args "$@"
    main
fi