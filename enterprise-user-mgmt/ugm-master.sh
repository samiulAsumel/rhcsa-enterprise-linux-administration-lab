#!/usr/bin/env bash
set -euo pipefail

# Enterprise User and Group Management System - Master Script
# Version: 2.2.0 (Industry Standard Compliant)
# Purpose: Production-grade user/group management with security policies
# Compliance: Red Hat Enterprise Standards, CIS Benchmarks, NIST 800-53
# This script combines all library functionality into a single file

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
# LOGGING LIBRARY
# ============================================================================

# Log levels following syslog convention
declare -gA LOG_LEVELS=(
    [DEBUG]=0
    [INFO]=1
    [WARN]=2
    [ERROR]=3
    [CRITICAL]=4
)

# Initialize default log level
LOG_LEVEL="INFO"

# Enterprise color codes (if terminal supports)
if [[ -t 2 ]] && [[ "$TERM" != "dumb" ]]; then
    declare -g COLOR_RESET='\033[0m'
    declare -g COLOR_DEBUG='\033[36m' # Cyan
    declare -g COLOR_INFO='\033[32m'  # Green
    declare -g COLOR_WARN='\033[33m'  # Yellow
    declare -g COLOR_ERROR='\033[31m' # Red
    declare -g COLOR_CRITICAL='\033[35m' # Magenta
else
    declare -g COLOR_RESET=''
    declare -g COLOR_DEBUG=''
    declare -g COLOR_INFO=''
    declare -g COLOR_WARN=''
    declare -g COLOR_ERROR=''
    declare -g COLOR_CRITICAL=''
fi

# Enterprise log function with audit capabilities
log() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local hostname
    hostname=$(hostname)
    local pid=$$

    # Check if we should log this level
    if [[ ${LOG_LEVELS[$level]} -ge ${LOG_LEVELS[$LOG_LEVEL]:-1} ]]; then
        local color_var="COLOR_$level"
        local color="${!color_var}"

        # Console output (stderr) with structured format
        echo -e "${color}[$timestamp] [$hostname:$pid] [$level] $message${COLOR_RESET}" >&2

        # File output (if writable)
        if [[ -w "$LOG_FILE" ]] || touch "$LOG_FILE" 2>/dev/null; then
            echo "[$timestamp] [$hostname:$pid] [$level] $message" >>"$LOG_FILE"
        fi
        
        # Critical messages also go to audit log
        if [[ "$level" == "CRITICAL" ]] && [[ -n "${CONFIG[audit_log]:-}" ]]; then
            if [[ -w "${CONFIG[audit_log]}" ]] || touch "${CONFIG[audit_log]}" 2>/dev/null; then
                echo "[$timestamp] [$hostname:$pid] [AUDIT] [CRITICAL] $message" >>"${CONFIG[audit_log]}"
            fi
        fi
    fi
}

# Convenience logging functions
log_debug() { log "DEBUG" "$*"; }
log_info() { log "INFO" "$*"; }
log_warn() { log "WARN" "$*"; }
log_warning() { log "WARN" "$*"; }
log_error() { log "ERROR" "$*"; }
log_critical() { log "CRITICAL" "$*"; }

# Audit logging for security events
log_audit() {
    local event="$1"
    local user="$2"
    local action="$3"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local hostname
    hostname=$(hostname)
    local pid=$$
    
    if [[ -n "${CONFIG[audit_log]:-}" ]]; then
        if [[ -w "${CONFIG[audit_log]}" ]] || touch "${CONFIG[audit_log]}" 2>/dev/null; then
            echo "[$timestamp] [$hostname:$pid] [AUDIT] [EVENT:$event] [USER:$user] [ACTION:$action]" >>"${CONFIG[audit_log]}"
        fi
    fi
    
    # Also log to regular log
    log_info "AUDIT: $event - User: $user - Action: $action"
}

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
# VALIDATION LIBRARY
# ============================================================================

# Validate username format with enterprise rules
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
    
    # Additional security checks
    if [[ "$username" =~ \.{2,} ]] || [[ "$username" =~ \.$ ]]; then
        echo "Error: Username cannot contain consecutive dots or end with a dot."
        return 1
    fi
    
    return 0
}

# Validate group name with enterprise rules
validate_groupname() {
    local groupname="$1"

    # Reserved system group names
    local reserved_groups=(root daemon bin sys adm cdrom sudo dip plugdev lpadmin sambashare)
    
    # Check against reserved names
    for reserved in "${reserved_groups[@]}"; do
        [[ "$groupname" == "$reserved" ]] && {
            echo "Error: Group name '$groupname' is reserved."
            return 1
        }
    done

    if [[ ! $groupname =~ ^[a-z][a-z0-9_-]{0,31}$ ]]; then
        echo "Error: Invalid group name '$groupname'."
        echo "Group name must be 1-32 characters, start with a letter, and can contain lowercase letters, numbers, underscores, or hyphens."
        return 1
    fi
    return 0
}

# Enhanced check if user exists with validation
user_exists() {
    local username="$1"
    
    # Validate username first
    if ! validate_username "$username"; then
        return 2
    fi
    
    if id "$username" &>/dev/null; then
        return 0
    fi
    return 1
}

# Enhanced check if group exists with validation
group_exists() {
    local groupname="$1"
    
    # Validate groupname first
    if ! validate_groupname "$groupname"; then
        return 2
    fi
    
    if getent group "$groupname" &>/dev/null; then
        return 0
    fi
    return 1
}

# Validate sudoers syntax
validate_sudoers() {
    local file="$1"

    if [[ ! -f "$file" ]]; then
        log_error "Sudoers file '$file' does not exist."
        return 1
    fi

    if visudo -cf "$file" &>/dev/null; then
        log_debug "Sudoers file '$file' syntax is valid."
        return 0
    else
        log_error "Sudoers file '$file' syntax is invalid."
        return 1
    fi
}

# Validate password policy parameters
validate_password_policy() {
    local max_days="$1"
    local min_days="$2"
    local warn_days="$3"
    local inactive_days="$4"

    # Basic range checks
    [[ "$max_days" -ge 1 && "$max_days" -le 99999 ]] || { log_error "Max days must be between 1 and 99999."; return 1; }
    [[ "$min_days" -ge 0 && "$min_days" -le "$max_days" ]] || { log_error "Min days must be between 0 and max days."; return 1; }
    [[ "$warn_days" -ge 0 && "$warn_days" -le "$max_days" ]] || { log_error "Warn days must be between 0 and max days."; return 1; }
    [[ "$inactive_days" -ge 0 && "$inactive_days" -le 99999 ]] || { log_error "Inactive days must be between 0 and 99999."; return 1; }

    return 0
}

# ============================================================================
# SECURITY LIBRARY
# ============================================================================

# Security constants for CIS compliance
readonly CIS_PASSWORD_MIN_LENGTH=12
readonly CIS_PASSWORD_MAX_DAYS=90
readonly CIS_PASSWORD_MIN_DAYS=1
readonly CIS_PASSWORD_WARN_DAYS=7
readonly CIS_INACTIVE_DAYS=30
readonly CIS_UMASK=027
readonly CIS_MAX_LOGIN_ATTEMPTS=5
readonly CIS_LOCKOUT_DURATION=900

# NIST 800-53 security constants
readonly NIST_SESSION_TIMEOUT=3600
readonly NIST_AUDIT_RETENTION_DAYS=2555  # 7 years
readonly NIST_MIN_PASSWORD_ENTROPY=60

# Common password patterns to block (CIS Control 16)
readonly COMMON_PASSWORDS=(
    "password" "123456" "12345678" "qwerty" "abc123"
    "password123" "admin" "letmein" "welcome" "monkey"
    "1234567890" "password1" "qwerty123" "admin123"
)

# Reserved system usernames (CIS Control 5)
readonly RESERVED_USERNAMES=(
    "root" "daemon" "bin" "sys" "sync" "games" "man" "lp"
    "mail" "news" "uucp" "proxy" "www-data" "backup" "list"
    "irc" "gnats" "nobody" "systemd-network" "systemd-resolve"
    "syslog" "messagebus" "uuidd" "dnsmasq" "usbmux" "rtkit"
    "pulse" "speech-dispatcher" "avahi" "colord" "hplip" "geoclue"
    "gnome-initial-setup" "gdm" "sshd" "ntp" "postfix" "mysql"
    "postgres" "oracle" "apache" "nginx" "tomcat" "redis"
)

# Validate password strength against enterprise requirements
validate_password_strength() {
    local password="$1"
    local username="${2:-}"
    local errors=0
    
    log_debug "Validating password strength for user: ${username:-unknown}"
    
    # Check minimum length (CIS requirement)
    if [[ ${#password} -lt ${CIS_PASSWORD_MIN_LENGTH} ]]; then
        log_error "Password must be at least ${CIS_PASSWORD_MIN_LENGTH} characters"
        ((errors++))
    fi
    
    # Check maximum length
    if [[ ${#password} -gt 128 ]]; then
        log_error "Password must not exceed 128 characters"
        ((errors++))
    fi
    
    # Check complexity requirements (NIST 800-53)
    if ! [[ "$password" =~ [A-Z] ]]; then
        log_error "Password must contain at least one uppercase letter"
        ((errors++))
    fi
    
    if ! [[ "$password" =~ [a-z] ]]; then
        log_error "Password must contain at least one lowercase letter"
        ((errors++))
    fi
    
    if ! [[ "$password" =~ [0-9] ]]; then
        log_error "Password must contain at least one digit"
        ((errors++))
    fi
    
    # Check for special characters using a simpler pattern
    if [[ "$password" =~ ^[A-Za-z0-9]+$ ]]; then
        log_error "Password must contain at least one special character"
        ((errors++))
    fi
    
    # Check for common passwords (CIS Control 16)
    local lower_password="${password,,}"
    for common in "${COMMON_PASSWORDS[@]}"; do
        if [[ "$lower_password" == *"$common"* ]]; then
            log_error "Password contains common pattern: $common"
            ((errors++))
        fi
    done
    
    # Check for sequential characters
    if [[ "$password" =~ (abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789) ]]; then
        log_error "Password contains sequential characters"
        ((errors++))
    fi
    
    # Check for repeated characters
    if [[ "$password" =~ (.)\1{2,} ]]; then
        log_error "Password contains repeated characters"
        ((errors++))
    fi
    
    # Check if password contains username (CIS requirement)
    if [[ -n "$username" && "$lower_password" == *"${username,,}"* ]]; then
        log_error "Password cannot contain username"
        ((errors++))
    fi
    
    # Calculate password entropy (NIST requirement)
    local entropy
    entropy=$(calculate_password_entropy "$password")
    if [[ $entropy -lt $NIST_MIN_PASSWORD_ENTROPY ]]; then
        log_error "Password entropy too low: $entropy (minimum: $NIST_MIN_PASSWORD_ENTROPY)"
        ((errors++))
    fi
    
    log_debug "Password validation complete. Errors: $errors"
    return $errors
}

# Calculate password entropy for NIST compliance
calculate_password_entropy() {
    local password="$1"
    local charset_size=0
    
    # Determine character set size
    [[ "$password" =~ [a-z] ]] && ((charset_size += 26))
    [[ "$password" =~ [A-Z] ]] && ((charset_size += 26))
    [[ "$password" =~ [0-9] ]] && ((charset_size += 10))
    # Check for special characters using grep
    if echo "$password" | grep -q '[!@#$%^&*()_+=\\-]'; then
        ((charset_size += 32))
    fi
    
    # Calculate entropy: log2(charset_size) * length
    local entropy
    entropy=$(echo "scale=2; ${#password} * l($charset_size)/l(2)" | bc -l 2>/dev/null || echo "0")
    
    # Convert to integer
    echo "${entropy%.*}"
}

# Generate cryptographically secure password
generate_secure_password() {
    local length="${1:-16}"
    local password
    
    # Ensure minimum length
    [[ $length -lt $CIS_PASSWORD_MIN_LENGTH ]] && length=$CIS_PASSWORD_MIN_LENGTH
    
    # Generate password using /dev/urandom
    password=$(tr -dc 'A-Za-z0-9!@#$%^&*()_+-=' < /dev/urandom | head -c "$length")
    
    # Validate generated password
    if ! validate_password_strength "$password"; then
        # Regenerate if validation fails
        generate_secure_password "$length"
        return
    fi
    
    echo "$password"
    log_debug "Generated secure password of length: $length"
}

# Harden user account security (CIS Control 4)
harden_user_account() {
    local username="$1"
    local errors=0
    
    log_info "Hardening security for user: $username"
    
    # Validate user exists
    if ! id "$username" &>/dev/null; then
        log_error "User $username does not exist"
        return 1
    fi
    
    # Set secure umask in user's profile
    local user_home
    user_home=$(getent passwd "$username" | cut -d: -f6)
    
    if [[ -d "$user_home" ]]; then
        # Add umask setting to bash profile
        if ! grep -q "umask $CIS_UMASK" "$user_home/.bashrc" 2>/dev/null; then
            echo "umask $CIS_UMASK" >> "$user_home/.bashrc"
            log_info "Set secure umask $CIS_UMASK for $username"
        fi
        
        # Set secure permissions on home directory
        chmod 750 "$user_home"
        log_info "Set secure permissions on $user_home"
        
        # Remove world-readable files from home directory
        find "$user_home" -type f -perm /o+r -exec chmod o-r {} \; 2>/dev/null || true
        log_debug "Removed world-readable permissions from files in $user_home"
    fi
    
    # Set password aging policies (CIS requirement)
    chage -M "$CIS_PASSWORD_MAX_DAYS" "$username"
    chage -m "$CIS_PASSWORD_MIN_DAYS" "$username" 
    chage -W "$CIS_PASSWORD_WARN_DAYS" "$username"
    chage -I "$CIS_INACTIVE_DAYS" "$username"
    log_info "Set password aging policies for $username"
    
    # Force password change on next login for new accounts
    chage -d 0 "$username"
    log_info "Forced password change for $username"
    
    log_audit "USER_HARDENING" "username=$username" "action=account_hardened"
    
    return $errors
}

# ============================================================================
# USER OPERATIONS LIBRARY
# ============================================================================

# User operation result codes
readonly USER_OP_SUCCESS=0
readonly USER_OP_EXISTS=1
readonly USER_OP_NOT_FOUND=2
readonly USER_OP_PERMISSION_DENIED=3
readonly USER_OP_INVALID_INPUT=4
readonly USER_OP_SYSTEM_ERROR=5

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

# Create a single custom user with full control options
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

    # Apply security hardening
    if ! harden_user_account "$username"; then
        log_warn "Security hardening failed for $username"
    fi

    log_audit "CREATE_USER" "$username" "success"
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
        log_audit "LOCK_USER" "$username" "success"
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
        log_audit "UNLOCK_USER" "$username" "success"
        log_info "User $username unlocked successfully"
    else
        log_error "Failed to unlock user $username"
        return 5
    fi
}

# ============================================================================
# GROUP OPERATIONS LIBRARY
# ============================================================================

# Group operation result codes
readonly GROUP_OP_SUCCESS=0
readonly GROUP_OP_EXISTS=1
readonly GROUP_OP_NOT_FOUND=2
readonly GROUP_OP_PERMISSION_DENIED=3
readonly GROUP_OP_INVALID_INPUT=4
readonly GROUP_OP_SYSTEM_ERROR=5

# Create group
create_group() {
    local groupname=""
    local gid=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
        --gid)
            gid="$2"
            shift 2
            ;;
        *)
            groupname="$1"
            shift
            ;;
        esac
    done

    validate_groupname "$groupname" || return 1

    if group_exists "$groupname"; then
        log_warn "Group '${groupname}' already exists — skipping creation."
        return 0
    fi

    local groupadd_args=()
    if [[ -n "$gid" ]]; then
        if [[ "$gid" =~ ^[0-9]+$ ]] && [[ "$gid" -gt 0 ]]; then
            groupadd_args+=(-g "$gid")
        else
            log_error "Invalid GID: $gid"
            return 1
        fi
    fi

    log_info "Creating group '${groupname}'..."
    if groupadd "${groupadd_args[@]}" "$groupname"; then
        log_info "Group '${groupname}' created."
        log_audit "create_group" "$groupname" "ok"
    else
        log_error "Failed to create group '${groupname}'."
        log_audit "create_group" "$groupname" "fail"
        return 1
    fi
}

# Create required groups
create_required_groups() {
    require_root
    
    local groups=("developers" "admins" "users")
    
    log_info "Creating required groups..."
    
    for group in "${groups[@]}"; do
        create_group "$group"
    done
    
    log_info "Group creation completed"
}

# ============================================================================
# SYSTEM OPERATIONS
# ============================================================================

# Assign users to appropriate groups
assign_users_to_groups() {
    require_root
    
    log_info "Assigning users to groups..."
    
    # Assign dev users to developers group
    for user in dev1 dev2 dev3; do
        if user_exists "$user"; then
            run_cmd "usermod -aG developers $user" "Add $user to developers group"
        fi
    done
    
    log_info "User group assignment completed"
}

# Configure sudo access for admins
configure_sudo_access() {
    require_root
    
    local sudoers_file="${CONFIG[sudoers_dir]}/user-mgmt"
    
    log_info "Configuring sudo access..."
    
    # Create sudoers file
    cat > "$sudoers_file" << 'EOF'
# User management sudo configuration
%admins ALL=(ALL:ALL) NOPASSWD: ALL
%developers ALL=(ALL:ALL) /usr/bin/useradd, /usr/bin/usermod, /usr/bin/userdel, /usr/bin/groupadd, /usr/bin/groupmod, /usr/bin/groupdel
EOF
    
    # Validate sudoers file
    if validate_sudoers "$sudoers_file"; then
        chmod 440 "$sudoers_file"
        log_info "Sudo access configured successfully"
        log_audit "SUDO_CONFIG" "system" "sudo_access_configured"
    else
        log_error "Sudoers configuration validation failed"
        rm -f "$sudoers_file"
        return 5
    fi
}

# Apply password policies
apply_password_policies() {
    require_root
    
    log_info "Applying password policies..."
    
    # Set system-wide password policies
    run_cmd "chage -M ${CONFIG[password_max_days]} -m ${CONFIG[password_min_days]} -W ${CONFIG[password_warn_days]} -I ${CONFIG[inactive_days]} $(awk -F: '($3 >= 1000) {print $1}' /etc/passwd)" "Apply password policies"
    
    log_info "Password policies applied successfully"
    log_audit "PASSWORD_POLICY" "system" "policies_applied"
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

# Validate configuration values
validate_configuration() {
    local errors=0
    
    # Validate shell exists
    if ! command -v "${CONFIG[default_shell]}" >/dev/null 2>&1; then
        log_error "Invalid shell: ${CONFIG[default_shell]}"
        ((errors++))
    fi
    
    # Validate home directory
    if [[ ! -d "${CONFIG[home_base]}" ]]; then
        log_error "Home base directory does not exist: ${CONFIG[home_base]}"
        ((errors++))
    fi
    
    # Validate password policy
    if ! validate_password_policy "${CONFIG[password_max_days]}" "${CONFIG[password_min_days]}" "${CONFIG[password_warn_days]}" "${CONFIG[inactive_days]}"; then
        ((errors++))
    fi
    
    # Validate sudoers directory
    if [[ ! -d "${CONFIG[sudoers_dir]}" ]]; then
        log_error "Sudoers directory does not exist: ${CONFIG[sudoers_dir]}"
        ((errors++))
    fi
    
    return $errors
}

# Load configuration with validation
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        # Validate configuration file syntax
        if bash -n "$CONFIG_FILE" 2>/dev/null; then
            # shellcheck source=/dev/null
            source "$CONFIG_FILE"
            log_info "Loaded configuration from ${CONFIG_FILE}"
            
            # Validate critical configuration values
            validate_configuration || {
                log_error "Configuration validation failed"
                exit 4
            }
        else
            log_error "Configuration file syntax error: ${CONFIG_FILE}"
            exit 4
        fi
    else
        log_warning "Configuration file not found, using default values"
    fi
}

# Display help menu
show_help() {
    cat << EOF
    Enterprise User and Group Management System - Master Script

    Usage: $0 [OPTIONS] COMMAND [ARGS]

    Commands:
    create-user USERNAME    Create a single user with specified name
    create-users           Create standard development users
    create-groups          Create required groups
    assign-groups          Assign users to appropriate groups
    configure-sudo         Configure sudo access for admins
    set-password-policy    Apply password expiration policies
    lock-user   USER       Lock specified user account
    unlock-user USER       Unlock specified user account
    harden-user USER       Apply security hardening to user account
    audit-user  USER       Perform security audit on user account
    generate-password      Generate secure password
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
    $0 create-user alice --shell /bin/zsh --password MyPass123!
    $0 create-user bob --home-dir /custom/home/bob --groups "developers,admins"
    $0 create-user sarah --comment "Developer Account" --uid 1500 --no-force-change
    $0 create-users
    $0 --dry-run configure-sudo
    $0 lock-user dev2
    $0 harden-user dev1
    $0 audit-user dev1
    $0 generate-password
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
                echo "Enterprise User Management System v2.2.0 (Master Script - Industry Standard Compliant)"
                exit 0
                ;;
            create-user|create-users|create-groups|assign-groups|configure-sudo|set-password-policy|lock-user|unlock-user|harden-user|audit-user|generate-password|status|validate-config)
                COMMAND="$1"
                shift
                # Handle command-specific arguments
                case $COMMAND in
                    lock-user|unlock-user|harden-user|audit-user)
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

# Initialize logging with enterprise standards
init_logging() {
    # Export LOG_LEVEL for library functions
    export LOG_LEVEL="INFO"
    $VERBOSE && export LOG_LEVEL="DEBUG"
    $QUIET && export LOG_LEVEL="ERROR"

    # Ensure log directory exists with proper permissions
    if ! mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null; then
        echo "Warning: Cannot create log directory" >&2
    fi
    
    # Ensure audit log directory exists
    if ! mkdir -p "$(dirname "${CONFIG[audit_log]}")" 2>/dev/null; then
        echo "Warning: Cannot create audit log directory" >&2
    fi
    
    # Set secure permissions on log files
    [[ -f "$LOG_FILE" ]] && chmod 600 "$LOG_FILE"
    [[ -f "${CONFIG[audit_log]}" ]] && chmod 600 "${CONFIG[audit_log]}"
}

# Audit user security
audit_user_security() {
    local username="$1"
    
    if ! user_exists "$username"; then
        log_error "User $username does not exist"
        return 2
    fi
    
    echo "=== Security Audit for User: $username ==="
    echo
    
    # User information
    echo "User Information:"
    getent passwd "$username" | cut -d: -f1,3,4,6,7 | while IFS=: read -r uid gid home shell; do
        echo "  UID: $uid"
        echo "  GID: $gid"
        echo "  Home: $home"
        echo "  Shell: $shell"
    done
    echo

    # Group memberships
    echo "Group Memberships:"
    groups "$username" 2>/dev/null || echo "  Unable to retrieve group information"
    echo

    # Password information
    echo "Password Information:"
    chage -l "$username" 2>/dev/null || echo "  Unable to retrieve password information"
    echo

    # Home directory permissions
    local user_home
    user_home=$(getent passwd "$username" | cut -d: -f6)
    if [[ -d "$user_home" ]]; then
        echo "Home Directory Permissions:"
        ls -ld "$user_home"
        echo
    fi

    # Last login information
    echo "Last Login Information:"
    lastlog -u "$username" 2>/dev/null | tail -n +2 || echo "  No login information available"
    echo

    log_audit "USER_AUDIT" "$username" "security_audit_completed"
}

# Hard user account (alias for harden_user_account)
harden_account() {
    harden_user_account "$1"
}

# Main execution
main() {
    init_logging
    load_config

    log_debug "Starting enterprise-user-mgmt with command: $COMMAND"
    log_debug "Dry run: $DRY_RUN"

    case $COMMAND in
        create-user)
            create_single_user "$TARGET_USER" "${CREATE_USER_ARGS[@]}"
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
        harden-user)
            harden_account "$TARGET_USER"
            ;;
        audit-user)
            audit_user_security "$TARGET_USER"
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
        validate-config)
            validate_configuration
            ;;
    esac

    log_info "Command '$COMMAND' completed successfully"
}

# Trap errors
trap 'log_error "Error on line $LINENO"; exit 1' ERR

# Run main if not sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    parse_args "$@"
    main
fi
