#!/usr/bin/env bash
# Enterprise Security utilities for user-mgmt system
# Compliance: CIS Benchmarks, NIST 800-53, Security hardening

# Security constants
# shellcheck disable=SC2034  # Constants reserved for future security enhancements
readonly MIN_PASSWORD_LENGTH=12
readonly MAX_PASSWORD_LENGTH=128
readonly PASSWORD_COMPLEXITY_REQUIRED=true
readonly ACCOUNT_LOCKOUT_THRESHOLD=5
readonly SESSION_TIMEOUT_MINUTES=30

# Validate password strength against enterprise standards
validate_password_strength() {
    local password="$1"
    local username="$2"
    
    # Length validation
    if [[ ${#password} -lt $MIN_PASSWORD_LENGTH ]]; then
        echo "Error: Password must be at least $MIN_PASSWORD_LENGTH characters"
        return 1
    fi
    
    if [[ ${#password} -gt $MAX_PASSWORD_LENGTH ]]; then
        echo "Error: Password must not exceed $MAX_PASSWORD_LENGTH characters"
        return 1
    fi
    
    # Complexity requirements
    local has_upper=false
    local has_lower=false
    local has_digit=false
    local has_special=false
    
    [[ "$password" =~ [A-Z] ]] && has_upper=true
    [[ "$password" =~ [a-z] ]] && has_lower=true
    [[ "$password" =~ [0-9] ]] && has_digit=true
    # Check for special characters using grep
    if echo "$password" | grep -q '[^a-zA-Z0-9]'; then
        has_special=true
    fi
    
    if [[ "$PASSWORD_COMPLEXITY_REQUIRED" == "true" ]]; then
        if ! $has_upper || ! $has_lower || ! $has_digit || ! $has_special; then
            echo "Error: Password must contain uppercase, lowercase, digit, and special characters"
            return 1
        fi
    fi
    
    # Security checks
    # Password cannot contain username
    if [[ "$password" =~ ${username,,} ]]; then
        echo "Error: Password cannot contain username"
        return 1
    fi
    
    # Common password patterns check
    local common_patterns=("password" "123456" "qwerty" "admin" "welcome" "changeme")
    for pattern in "${common_patterns[@]}"; do
        if [[ "$password" =~ ${pattern,,} ]]; then
            echo "Error: Password contains common pattern: $pattern"
            return 1
        fi
    done
    
    # Repeated characters check
    if [[ "$password" =~ (.)\1{2,} ]]; then
        echo "Error: Password cannot contain 3 or more repeated characters"
        return 1
    fi
    
    # Sequential characters check
    if echo "$password" | grep -qiE "(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789)"; then
        echo "Error: Password cannot contain sequential characters"
        return 1
    fi
    
    return 0
}

# Secure password generation
generate_secure_password() {
    local length="${1:-16}"
    local password=""
    
    # Ensure minimum length
    [[ $length -lt $MIN_PASSWORD_LENGTH ]] && length=$MIN_PASSWORD_LENGTH
    
    # Character sets
    local uppercase="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    local lowercase="abcdefghijklmnopqrstuvwxyz"
    local digits="0123456789"
    local special="!@#$%^&*()_+-=[]{};':\"|,.<>/?"
    
    # Ensure at least one character from each set
    password+=$(echo "$uppercase" | fold -w1 | shuf | head -n1)
    password+=$(echo "$lowercase" | fold -w1 | shuf | head -n1)
    password+=$(echo "$digits" | fold -w1 | shuf | head -n1)
    password+=$(echo "$special" | fold -w1 | shuf | head -n1)
    
    # Fill remaining length with random characters
    local all_chars="$uppercase$lowercase$digits$special"
    local remaining=$((length - 4))
    
    for ((i=0; i<remaining; i++)); do
        password+=$(echo "$all_chars" | fold -w1 | shuf | head -n1)
    done
    
    # Shuffle the password
    echo "$password" | fold -w1 | shuf | tr -d '\n'
}

# Check account security status
check_account_security() {
    local username="$1"
    
    if ! user_exists "$username"; then
        echo "Error: User '$username' does not exist"
        return 1
    fi
    
    echo "Security audit for user: $username"
    echo "================================"
    
    # Check password age
    local password_age
    password_age=$(chage -l "$username" | grep "Last password change" | cut -d: -f2 | tr -d ' ')
    echo "Last password change: $password_age"
    
    # Check password expiration
    local password_expire
    password_expire=$(chage -l "$username" | grep "Password expires" | cut -d: -f2 | tr -d ' ')
    echo "Password expires: $password_expire"
    
    # Check account expiration
    local account_expire
    account_expire=$(chage -l "$username" | grep "Account expires" | cut -d: -f2 | tr -d ' ')
    echo "Account expires: $account_expire"
    
    # Check failed login attempts
    local failed_attempts
    failed_attempts=$(faillog -u "$username" | grep "$username" | awk '{print $2}')
    echo "Failed login attempts: ${failed_attempts:-0}"
    
    # Check if account is locked
    if passwd -S "$username" 2>/dev/null | grep -q "locked"; then
        echo "Account status: LOCKED"
    else
        echo "Account status: ACTIVE"
    fi
    
    # Check group memberships
    echo "Group memberships:"
    groups "$username" 2>/dev/null || echo "Unable to retrieve groups"
    
    # Check sudo access
    if sudo -l -U "$username" 2>/dev/null | grep -q "may run"; then
        echo "Sudo access: YES"
    else
        echo "Sudo access: NO"
    fi
}

# Harden user account security
harden_account() {
    local username="$1"
    
    if ! user_exists "$username"; then
        log_error "User '$username' does not exist"
        return 1
    fi
    
    log_info "Hardening account: $username"
    
    # Set secure umask in user's profile
    local user_home
    user_home=$(getent passwd "$username" | cut -d: -f6)
    
    if [[ -d "$user_home" ]]; then
        # Add secure umask to bashrc
        if ! grep -q "umask 027" "$user_home/.bashrc" 2>/dev/null; then
            echo "umask 027" >> "$user_home/.bashrc"
            chown "$username:$username" "$user_home/.bashrc"
            chmod 644 "$user_home/.bashrc"
        fi
        
        # Set secure permissions on home directory
        chmod 750 "$user_home"
        
        # Remove world-readable permissions from sensitive files
        find "$user_home" -type f -name "*.sh" -exec chmod 700 {} \; 2>/dev/null || true
        find "$user_home" -type f -name "*.pem" -exec chmod 600 {} \; 2>/dev/null || true
        find "$user_home" -type f -name "*.key" -exec chmod 600 {} \; 2>/dev/null || true
        find "$user_home" -type f -name "authorized_keys" -exec chmod 600 {} \; 2>/dev/null || true
    fi
    
    # Apply password policy
    chage -M "${CONFIG[password_max_days]}" "$username"
    chage -m "${CONFIG[password_min_days]}" "$username"
    chage -W "${CONFIG[password_warn_days]}" "$username"
    chage -I "${CONFIG[inactive_days]}" "$username"
    
    log_audit "ACCOUNT_HARDEN" "$username" "Security hardening applied"
    
    log_info "Account hardening completed for: $username"
}

# Validate SSH key security
validate_ssh_key() {
    local key_file="$1"
    local username="$2"
    
    if [[ ! -f "$key_file" ]]; then
        echo "Error: SSH key file does not exist: $key_file"
        return 1
    fi
    
    # Check file permissions
    local file_perms
    file_perms=$(stat -c "%a" "$key_file")
    if [[ "$file_perms" != "600" ]] && [[ "$file_perms" != "400" ]]; then
        echo "Warning: SSH key file has insecure permissions: $file_perms (should be 600 or 400)"
    fi
    
    # Validate key format
    if ! ssh-keygen -l -f "$key_file" &>/dev/null; then
        echo "Error: Invalid SSH key format"
        return 1
    fi
    
    # Check key strength
    local key_info
    key_info=$(ssh-keygen -l -f "$key_file")
    local key_bits
    key_bits=$(echo "$key_info" | awk '{print $1}')
    
    if [[ $key_bits -lt 2048 ]]; then
        echo "Warning: SSH key is less than 2048 bits: $key_bits"
    fi
    
    echo "SSH key validation passed for user: $username"
    return 0
}

# Security audit function
audit_user_security() {
    local username="$1"
    local audit_file="${CONFIG[audit_log]}"
    
    if ! user_exists "$username"; then
        log_error "User '$username' does not exist"
        return 1
    fi
    
    log_audit "SECURITY_AUDIT" "$username" "Security audit initiated"
    
    # Perform comprehensive security check
    check_account_security "$username" > "/tmp/security_audit_$username.$$"
    
    # Log audit results
    if [[ -n "$audit_file" ]]; then
        {
            echo "=== SECURITY AUDIT RESULTS ==="
            date
            echo "User: $username"
            echo "================================"
            cat "/tmp/security_audit_$$"
            echo "================================"
            echo ""
        } >> "$audit_file"
    fi
    
    # Display results
    cat "/tmp/security_audit_$$"
    rm -f "/tmp/security_audit_$$"
    
    log_audit "SECURITY_AUDIT" "$username" "Security audit completed"
}
