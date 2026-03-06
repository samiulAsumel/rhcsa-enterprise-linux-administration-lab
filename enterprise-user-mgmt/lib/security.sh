#!/usr/bin/env bash
# Enterprise Security Library
# Version: 2.2.0 - Industry Standard Compliant
# Purpose: Security functions, hardening, and compliance utilities
# Compliance: CIS Benchmarks, NIST 800-53, Red Hat Enterprise Standards

set -euo pipefail

# Security constants for CIS compliance
# shellcheck disable=SC2034
[[ -z "${CIS_PASSWORD_MIN_LENGTH:-}" ]] && readonly CIS_PASSWORD_MIN_LENGTH=12
[[ -z "${CIS_PASSWORD_MAX_DAYS:-}" ]] && readonly CIS_PASSWORD_MAX_DAYS=90
[[ -z "${CIS_PASSWORD_MIN_DAYS:-}" ]] && readonly CIS_PASSWORD_MIN_DAYS=1
[[ -z "${CIS_PASSWORD_WARN_DAYS:-}" ]] && readonly CIS_PASSWORD_WARN_DAYS=7
[[ -z "${CIS_INACTIVE_DAYS:-}" ]] && readonly CIS_INACTIVE_DAYS=30
[[ -z "${CIS_UMASK:-}" ]] && readonly CIS_UMASK=027
# shellcheck disable=SC2034
[[ -z "${CIS_MAX_LOGIN_ATTEMPTS:-}" ]] && readonly CIS_MAX_LOGIN_ATTEMPTS=5
# shellcheck disable=SC2034
[[ -z "${CIS_LOCKOUT_DURATION:-}" ]] && readonly CIS_LOCKOUT_DURATION=900

# NIST 800-53 security constants
# shellcheck disable=SC2034
[[ -z "${NIST_SESSION_TIMEOUT:-}" ]] && readonly NIST_SESSION_TIMEOUT=3600
# shellcheck disable=SC2034
[[ -z "${NIST_AUDIT_RETENTION_DAYS:-}" ]] && readonly NIST_AUDIT_RETENTION_DAYS=2555  # 7 years
[[ -z "${NIST_MIN_PASSWORD_ENTROPY:-}" ]] && readonly NIST_MIN_PASSWORD_ENTROPY=60

# Common password patterns to block (CIS Control 16)
if ! declare -p COMMON_PASSWORDS &>/dev/null; then
    readonly COMMON_PASSWORDS=(
        "password" "123456" "12345678" "qwerty" "abc123"
        "password123" "admin" "letmein" "welcome" "monkey"
        "1234567890" "password1" "qwerty123" "admin123"
    )
fi

# Reserved system usernames (CIS Control 5)
if ! declare -p RESERVED_USERNAMES &>/dev/null; then
    readonly RESERVED_USERNAMES=(
        "root" "daemon" "bin" "sys" "sync" "games" "man" "lp"
        "mail" "news" "uucp" "proxy" "www-data" "backup" "list"
        "irc" "gnats" "nobody" "systemd-network" "systemd-resolve"
        "syslog" "messagebus" "uuidd" "dnsmasq" "usbmux" "rtkit"
        "pulse" "speech-dispatcher" "avahi" "colord" "hplip" "geoclue"
        "gnome-initial-setup" "gdm" "sshd" "ntp" "postfix" "mysql"
        "postgres" "oracle" "apache" "nginx" "tomcat" "redis"
    )
fi

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
    # Get user home directory
    user_home=$(getent passwd "$username" | cut -d: -f6)
    readonly user_home
    
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

# Validate SSH key security
validate_ssh_key() {
    local key_file="$1"
    local username="${2:-}"
    local errors=0
    
    log_debug "Validating SSH key: $key_file"
    
    # Check file exists and is readable
    if [[ ! -r "$key_file" ]]; then
        log_error "SSH key file not readable: $key_file"
        ((errors++))
        return $errors
    fi
    
    # Check file permissions (should be 600 or 400)
    local file_perms
    file_perms=$(stat -c "%a" "$key_file" 2>/dev/null || echo "000")
    if [[ "$file_perms" != "600" && "$file_perms" != "400" ]]; then
        log_warning "SSH key permissions should be 600 or 400, currently: $file_perms"
        chmod 600 "$key_file"
        log_info "Fixed SSH key permissions to 600"
    fi
    
    # Validate key format
    if ! ssh-keygen -l -f "$key_file" &>/dev/null; then
        log_error "Invalid SSH key format: $key_file"
        ((errors++))
        return $errors
    fi
    
    # Check key strength (minimum 2048 bits for RSA)
    local key_bits
    key_bits=$(ssh-keygen -l -f "$key_file" 2>/dev/null | awk '{print $1}')
    
    if [[ "$key_file" == *"rsa"* && $key_bits -lt 2048 ]]; then
        log_error "RSA key too weak: $key_bits bits (minimum: 2048)"
        ((errors++))
    fi
    
    log_debug "SSH key validation complete. Errors: $errors"
    return $errors
}

# Perform comprehensive security audit (CIS Control 16)
audit_user_security() {
    local username="$1"
    local audit_file
    audit_file="/tmp/user_audit_${username}_$(date +%s).txt"
    
    log_info "Performing security audit for user: $username"
    
    {
        echo "=== User Security Audit Report ==="
        echo "Generated: $(date)"
        echo "Username: $username"
        echo ""
        
        echo "=== User Information ==="
        id "$username" 2>/dev/null || echo "User not found"
        getent passwd "$username" 2>/dev/null || echo "No passwd entry"
        echo ""
        
        echo "=== Password Information ==="
        chage -l "$username" 2>/dev/null || echo "No password aging info"
        echo ""
        
        echo "=== Group Memberships ==="
        groups "$username" 2>/dev/null || echo "No group info"
        echo ""
        
        echo "=== Home Directory Security ==="
        local user_home
        user_home=$(getent passwd "$username" | cut -d: -f6 2>/dev/null || echo "N/A")
        readonly user_home
        echo "Home directory: $user_home"
        
        if [[ -d "$user_home" ]]; then
            ls -ld "$user_home"
            echo "Directory permissions: $(stat -c "%a" "$user_home")"
            echo ""
            echo "Files with world read permissions:"
            find "$user_home" -type f -perm /o+r -ls 2>/dev/null || echo "None found"
        fi
        echo ""
        
        echo "=== SSH Keys ==="
        if [[ -d "$user_home/.ssh" ]]; then
            echo "SSH directory exists: $user_home/.ssh"
            ls -la "$user_home/.ssh" 2>/dev/null || echo "Cannot list SSH directory"
            
            for key_file in "$user_home/.ssh"/*.pub; do
                if [[ -f "$key_file" ]]; then
                    echo "Public key: $key_file"
                    ssh-keygen -l -f "$key_file" 2>/dev/null || echo "Cannot read key"
                fi
            done
        else
            echo "No SSH directory found"
        fi
        echo ""
        
        echo "=== Last Login Activity ==="
        lastlog -u "$username" 2>/dev/null || echo "No last login info"
        echo ""
        
        echo "=== Process Activity ==="
        ps -u "$username" -o pid,ppid,cmd,etime 2>/dev/null || echo "No processes found"
        echo ""
        
        echo "=== Security Recommendations ==="
        echo "1. Ensure password meets complexity requirements"
        echo "2. Enable two-factor authentication if available"
        echo "3. Review and remove unnecessary group memberships"
        echo "4. Secure SSH keys with strong passphrases"
        echo "5. Monitor for suspicious login activity"
        echo "6. Regular security audits recommended"
        
    } > "$audit_file"
    
    log_audit "USER_AUDIT" "username=$username" "audit_file=$audit_file"
    log_info "Security audit completed: $audit_file"
    
    echo "$audit_file"
}

# Check if username is reserved (CIS Control 5)
is_reserved_username() {
    local username="$1"
    local lower_username="${username,,}"
    
    for reserved in "${RESERVED_USERNAMES[@]}"; do
        if [[ "$lower_username" == "$reserved" ]]; then
            return 0
        fi
    done
    
    return 1
}

# Validate user against security policies
validate_user_security() {
    local username="$1"
    local errors=0
    
    log_debug "Validating security for user: $username"
    
    # Check if username is reserved
    if is_reserved_username "$username"; then
        log_error "Username '$username' is reserved for system use"
        ((errors++))
    fi
    
    # Check username format (CIS requirement)
    if [[ ! "$username" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
        log_error "Username must start with letter or underscore, contain only lowercase letters, numbers, hyphens, and underscores"
        ((errors++))
    fi
    
    # Check username length
    if [[ ${#username} -lt 2 || ${#username} -gt 32 ]]; then
        log_error "Username must be 2-32 characters long"
        ((errors++))
    fi
    
    # Check for security-sensitive patterns
    if [[ "$username" =~ (admin|root|test|temp|guest|service|account) ]]; then
        log_warning "Username contains security-sensitive pattern: $username"
    fi
    
    log_debug "User security validation complete. Errors: $errors"
    return $errors
}

# Initialize security module
init_security() {
    log_debug "Initializing security module"
    
    # Validate required system tools
    local required_tools=("chage" "getent" "stat" "ssh-keygen")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            log_error "Required tool not found: $tool"
            return 1
        fi
    done
    
    # Check for bc calculator (for entropy calculation)
    if ! command -v bc >/dev/null 2>&1; then
        log_warning "bc calculator not found, password entropy calculation disabled"
    fi
    
    log_info "Security module initialized successfully"
    return 0
}

# Export functions for use in other modules
export -f validate_password_strength
export -f calculate_password_entropy
export -f generate_secure_password
export -f harden_user_account
export -f validate_ssh_key
export -f audit_user_security
export -f is_reserved_username
export -f validate_user_security
export -f init_security

# Auto-initialize when sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Security library must be sourced, not executed"
    exit 1
fi

init_security
