#!/usr/bin/env bash
set -euo pipefail

# Enterprise User and Group Management System - Simple Master Script
# Version: 2.2.0 (Industry Standard Compliant)
# Purpose: Production-grade user/group management with security policies
# Compliance: Red Hat Enterprise Standards, CIS Benchmarks, NIST 800-53

# ============================================================================
# GLOBAL CONFIGURATION
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/etc/user-mgmt.conf"
LOG_FILE="/var/log/user-mgmt.log"

# Global configuration array
declare -gA CONFIG=(
    [default_shell]="/bin/bash"
    [home_base]="/home"
    [password_max_days]=90
    [password_min_days]=3
    [password_warn_days]=5
    [inactive_days]=30
    [sudoers_dir]="/etc/sudoers.d"
    [audit_log]="/var/log/user-mgmt-audit.log"
    [backup_dir]="/var/backups/user-mgmt"
    [max_login_attempts]=5
    [lockout_duration]=900
    [session_timeout]=3600
)

# Command line variables
COMMAND=""
TARGET_USER=""
CREATE_USER_ARGS=()
PASSWORD_LENGTH=""
DRY_RUN=false
VERBOSE=false
QUIET=false

# ============================================================================
# SIMPLE LOGGING
# ============================================================================

# Simple log function
log_msg() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    echo "[$timestamp] [$level] $message" >&2
    
    # Log to file if possible
    if [[ -w "$LOG_FILE" ]] || touch "$LOG_FILE" 2>/dev/null; then
        echo "[$timestamp] [$level] $message" >>"$LOG_FILE"
    fi
}

log_debug() { [[ "$VERBOSE" == "true" ]] && log_msg "DEBUG" "$*"; }
log_info() { log_msg "INFO" "$*"; }
log_warn() { log_msg "WARN" "$*"; }
log_error() { log_msg "ERROR" "$*"; }
log_critical() { log_msg "CRITICAL" "$*"; }

# Execute command with logging
run_cmd() {
    local cmd="$1"
    local desc="${2:-$cmd}"

    log_debug "Executing: $cmd"

    if $DRY_RUN; then
        log_info "[DRY_RUN] Would execute: $cmd"
        return 0
    fi

    if output=$(eval "$cmd" 2>&1); then
        log_debug "Command succeeded: $desc"
        [[ -n "$output" ]] && log_debug "Output: $output"
        return 0 
    else
        local exit_code=$?
        log_error "Command failed ($exit_code): $desc"
        log_error "Error output: $output"
        return $exit_code
    fi
}

# Check if running as root
require_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This command must be run as root (use sudo)"
        exit 3 
    fi
}

# ============================================================================
# VALIDATION
# ============================================================================

# Validate username format
validate_username() {
    local username="$1"

    # Reserved system usernames
    local reserved_names=(root daemon bin sys sync games man lp mail news uucp proxy www-data backup list irc gnats nobody systemd-network systemd-resolve syslog messagebus uuidd dnsmasq usbmux rtkit pulse speech-dispatcher avahi sanzed colord hplip geoclue gnome-initial-setup gdm)
    
    # Check against reserved names
    for reserved in "${reserved_names[@]}"; do
        [[ "$username" == "$reserved" ]] && {
            echo "Error: Username '$username' is reserved."
            return 1
        }
    done

    if [[ ! "$username" =~ ^[a-z][a-z0-9_-]{0,31}$ ]]; then
        echo "Error: Invalid username '$username'."
        echo "Username must be 1-32 characters, start with a letter, and can contain lowercase letters, numbers, underscores, or hyphens."
        return 1
    fi
    
    return 0
}

# Check if user exists
user_exists() {
    local username="$1"
    
    if id "$username" &>/dev/null; then
        return 0
    fi
    return 1
}

# ============================================================================
# USER OPERATIONS
# ============================================================================

# Create development users
create_development_users() {
    require_root

    local users=("dev1" "dev2" "dev3")

    log_info "Creating development users..."

    for user in "${users[@]}"; do
        if user_exists "$user"; then
            log_warn "User $user already exists, skipping"
            continue
        fi

        log_info "Creating user: $user"

        # Create user with home directory and default shell
        if ! run_cmd "useradd -m -d ${CONFIG[home_base]}/$user -s ${CONFIG[default_shell]} -c 'Development User $user' $user" "Create user $user"; then
            log_error "Failed to create user $user"
            return 5
        fi

        # Set initial password (expired to force change)
        if ! run_cmd "echo '$user:ChangeMe123!' | chpasswd" "Set initial password for $user"; then
            log_error "Failed to set password for $user"
            return 5
        fi

        # Force password change on first login
        if ! run_cmd "chage -d 0 $user" "Force password change for $user"; then
            log_error "Failed to set password expiration for $user"
            return 5
        fi

        log_info "Successfully created user: $user"
    done

    log_info "User creation completed"
}

# Create a single custom user
create_single_user() {
    local username="$1"
    shift
    local shell="${CONFIG[default_shell]}"
    local home_dir=""
    local password="ChangeMe123!"
    local groups=""
    local comment=""
    local force_change=true
    local uid=""

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --shell)
                shell="$2"
                shift 2
                ;;
            --home-dir)
                home_dir="$2"
                shift 2
                ;;
            --password)
                password="$2"
                shift 2
                ;;
            --groups)
                groups="$2"
                shift 2
                ;;
            --comment)
                comment="$2"
                shift 2
                ;;
            --uid)
                uid="$2"
                shift 2
                ;;
            --no-force-change)
                force_change=false
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                return 2
                ;;
        esac
    done

    require_root

    # Validate username
    if ! validate_username "$username"; then
        log_error "Invalid username: $username"
        return 2
    fi

    # Check if user already exists
    if user_exists "$username"; then
        log_error "User $username already exists"
        return 1
    fi

    # Set default home directory if not specified
    if [[ -z "$home_dir" ]]; then
        home_dir="${CONFIG[home_base]}/$username"
    fi

    # Validate shell
    if ! command -v "$shell" >/dev/null 2>&1; then
        log_error "Invalid shell: $shell"
        return 2
    fi

    # Build useradd command
    local useradd_args=("-m" "-s" "$shell")
    
    if [[ -n "$home_dir" ]]; then
        useradd_args+=("-d" "$home_dir")
    fi
    
    if [[ -n "$comment" ]]; then
        useradd_args+=("-c" "$comment")
    fi
    
    if [[ -n "$uid" ]]; then
        useradd_args+=("-u" "$uid")
    fi
    
    useradd_args+=("$username")

    log_info "Creating user: $username"
    
    # Create user
    if ! run_cmd "useradd ${useradd_args[*]}" "Create user $username"; then
        log_error "Failed to create user $username"
        return 5
    fi

    # Set password
    if ! run_cmd "echo '$username:$password' | chpasswd" "Set password for $username"; then
        log_error "Failed to set password for $username"
        return 5
    fi

    # Add to groups if specified
    if [[ -n "$groups" ]]; then
        IFS=',' read -ra group_array <<< "$groups"
        for group in "${group_array[@]}"; do
            if ! run_cmd "usermod -aG $group $username" "Add $username to group $group"; then
                log_warn "Failed to add $username to group $group"
            fi
        done
    fi

    # Force password change if requested
    if $force_change; then
        if ! run_cmd "chage -d 0 $username" "Force password change for $username"; then
            log_warn "Failed to set password expiration for $username"
        fi
    fi

    log_info "Successfully created user: $username"
    
    echo "User $username created successfully"
    echo "Home directory: $home_dir"
    echo "Shell: $shell"
    [[ -n "$groups" ]] && echo "Groups: $groups"
}

# Lock user account
lock_user_account() {
    local username="$1"
    
    require_root
    
    if ! user_exists "$username"; then
        log_error "User $username does not exist"
        return 2
    fi
    
    if run_cmd "usermod -L $username" "Lock user $username"; then
        log_info "User $username locked successfully"
    else
        log_error "Failed to lock user $username"
        return 5
    fi
}

# Unlock user account
unlock_user_account() {
    local username="$1"
    
    require_root
    
    if ! user_exists "$username"; then
        log_error "User $username does not exist"
        return 2
    fi
    
    if run_cmd "usermod -U $username" "Unlock user $username"; then
        log_info "User $username unlocked successfully"
    else
        log_error "Failed to unlock user $username"
        return 5
    fi
}

# ============================================================================
# SYSTEM OPERATIONS
# ============================================================================

# Generate secure password
generate_secure_password() {
    local length="${1:-16}"
    local password
    
    # Ensure minimum length
    [[ $length -lt 12 ]] && length=12
    
    # Generate password using /dev/urandom
    password=$(tr -dc 'A-Za-z0-9!@#$%^&*()_+-=' < /dev/urandom | head -c "$length")
    
    echo "$password"
    log_debug "Generated secure password of length: $length"
}

# Show system status
show_system_status() {
    echo "=== Enterprise User Management System Status ==="
    echo
    echo "Configuration:"
    for key in "${!CONFIG[@]}"; do
        echo "  $key: ${CONFIG[$key]}"
    done
    echo
    echo "Users:"
    awk -F: '($3 >= 1000) {printf "  %s (UID: %s, Shell: %s)\n", $1, $3, $7}' /etc/passwd
    echo
    echo "Groups:"
    getent group | awk -F: '($3 >= 1000) {printf "  %s (GID: %s)\n", $1, $3}' 
    echo
}

# ============================================================================
# CONFIGURATION AND MAIN FUNCTIONS
# ============================================================================

# Load configuration
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        if bash -n "$CONFIG_FILE" 2>/dev/null; then
            # shellcheck source=/dev/null
            source "$CONFIG_FILE"
            log_info "Loaded configuration from ${CONFIG_FILE}"
        else
            log_error "Configuration file syntax error: ${CONFIG_FILE}"
            exit 4
        fi
    else
        log_warn "Configuration file not found, using default values"
    fi
}

# Display help menu
show_help() {
    cat << EOF
    Enterprise User and Group Management System - Simple Master Script

    ⚠️  IMPORTANT: Always test with dry-run first! ⚠️
    Usage: $0 -v -d COMMAND [ARGS]  # Test first
    Usage: $0 COMMAND [ARGS]         # Then execute

    Usage: $0 [OPTIONS] COMMAND [ARGS]

    Commands:
    create-user USERNAME    Create a single user with specified name
    create-users           Create standard development users
    lock-user   USER       Lock specified user account
    unlock-user USER       Unlock specified user account
    generate-password      Generate secure password
    status                 Show current user and group configuration

    Options:
    -d, --dry-run           Show what would be done without making changes (TEST FIRST!)
    -v, --verbose           Enable verbose output (RECOMMENDED with dry-run)
    -h, --help              Display this help message
    --version               Display version information

    Testing Examples (ALWAYS do this first):
    $0 -v -d create-user john           # Test creating user john
    $0 -v -d create-users               # Test creating development users
    $0 -v -d lock-user dev2             # Test locking user

    Production Examples (after testing):
    $0 create-user john
    $0 create-user alice --shell /bin/zsh --password MyPass123!
    $0 create-user bob --home-dir /custom/home/bob --groups "developers,admins"
    $0 create-users
    $0 lock-user dev2
    $0 generate-password

    Exit codes:
    0 - Success
    1 - General error
    2 - Invalid input
    3 - Permission denied
    4 - Configuration error
    5 - User/group operation failed
    
    Safety Reminder: This script modifies system users and groups.
    Always test with -v -d flags before making actual changes!
EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--dry-run)
                DRY_RUN=true
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
                echo "Enterprise User Management System v2.2.0 (Simple Master Script)"
                exit 0
                ;;
            create-user|create-users|lock-user|unlock-user|generate-password|status)
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
                        # Store remaining arguments for create_single_user function
                        CREATE_USER_ARGS=("$@")
                        shift $#
                        ;;
                    generate-password)
                        # Optional length parameter
                        if [[ $# -gt 0 ]]; then
                            PASSWORD_LENGTH="$1"
                            shift
                        fi
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
    # Ensure log directory exists
    if ! mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null; then
        echo "Warning: Cannot create log directory" >&2
    fi
}

# Main execution
main() {
    init_logging
    load_config

    log_debug "Starting with command: $COMMAND"
    log_debug "Dry run: $DRY_RUN"

    # Safety warning for non-dry-run operations
    if [[ "$DRY_RUN" == "false" && "$COMMAND" =~ ^(create-user|create-users|lock-user|unlock-user)$ ]]; then
        log_warn "⚠️  EXECUTING LIVE COMMAND - This will modify system users!"
        log_warn "If this is unexpected, press Ctrl+C to cancel"
        sleep 2
    fi

    case $COMMAND in
        create-user)
            create_single_user "$TARGET_USER" "${CREATE_USER_ARGS[@]}"
            ;;
        create-users)
            create_development_users
            ;;
        lock-user)
            lock_user_account "$TARGET_USER"
            ;;
        unlock-user)
            unlock_user_account "$TARGET_USER"
            ;;
        generate-password)
            local length="${PASSWORD_LENGTH:-16}"
            local password
            password=$(generate_secure_password "$length")
            echo "Generated secure password ($length characters): $password"
            ;;
        status)
            show_system_status
            ;;
    esac

    log_info "Command '$COMMAND' completed successfully"
}

# Run main if not sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    parse_args "$@"
    main
fi
