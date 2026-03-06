#!/usr/bin/env bash
# Enterprise User Operations Library
# Version: 2.2.0 - Industry Standard Compliant
# Purpose: Core user and group management operations with enterprise security
# Compliance: CIS Benchmarks, NIST 800-53, Red Hat Enterprise Standards

set -euo pipefail

# Import required libraries
# shellcheck disable=SC1090
source "${BASH_SOURCE[0]%/*}/logging.sh"
# shellcheck disable=SC1090
source "${BASH_SOURCE[0]%/*}/validation.sh"
# shellcheck disable=SC1090
source "${BASH_SOURCE[0]%/*}/security.sh"

# User operation result codes
readonly USER_OP_SUCCESS=0
readonly USER_OP_EXISTS=1
readonly USER_OP_NOT_FOUND=2
readonly USER_OP_PERMISSION_DENIED=3
readonly USER_OP_INVALID_INPUT=4
readonly USER_OP_SYSTEM_ERROR=5

# Group operation result codes
readonly GROUP_OP_SUCCESS=0
readonly GROUP_OP_EXISTS=1
readonly GROUP_OP_NOT_FOUND=2
readonly GROUP_OP_PERMISSION_DENIED=3
readonly GROUP_OP_INVALID_INPUT=4
readonly GROUP_OP_SYSTEM_ERROR=5

# Create enterprise user with security hardening
create_enterprise_user() {
    local username="$1"
    local options="${2:-}"
    local errors=0
    
    log_info "Creating enterprise user: $username"
    
    # Validate input
    if ! validate_user_security "$username"; then
        log_error "Invalid username: $username"
        return $USER_OP_INVALID_INPUT
    fi
    
    # Check if user already exists
    if id "$username" &>/dev/null; then
        log_error "User $username already exists"
        return $USER_OP_EXISTS
    fi
    
    # Parse options
    local shell="${CONFIG[default_shell]}"
    local groups=""
    local comment=""
    local home_dir="${CONFIG[home_base]}/$username"
    local password=""
    local generate_password=false
    
    # Parse command line options
    while IFS='=' read -r key value; do
        case "$key" in
            shell) shell="$value" ;;
            groups) groups="$value" ;;
            comment) comment="$value" ;;
            home) home_dir="$value" ;;
            password) password="$value" ;;
            generate_password) generate_password=true ;;
        esac
    done <<< "$options"
    
    # Validate shell
    if ! command -v "$shell" >/dev/null 2>&1; then
        log_error "Invalid shell: $shell"
        ((errors++))
    fi
    
    # Validate groups
    if [[ -n "$groups" ]]; then
        IFS=',' read -ra group_array <<< "$groups"
        for group in "${group_array[@]}"; do
            if ! getent group "$group" &>/dev/null; then
                log_error "Group $group does not exist"
                ((errors++))
            fi
        done
    fi
    
    # Validate home directory
    if [[ -n "$home_dir" && ! -d "$(dirname "$home_dir")" ]]; then
        log_error "Parent directory for home does not exist: $(dirname "$home_dir")"
        ((errors++))
    fi
    
    # Validate password if provided
    if [[ -n "$password" ]]; then
        if ! validate_password_strength "$password" "$username"; then
            log_error "Password does not meet security requirements"
            ((errors++))
        fi
    fi
    
    if [[ $errors -gt 0 ]]; then
        return $USER_OP_INVALID_INPUT
    fi
    
    # Generate password if requested
    if [[ "$generate_password" == true ]]; then
        password=$(generate_secure_password)
        log_info "Generated secure password for $username"
    fi
    
    # Build useradd command
    local useradd_cmd=("useradd" "-m" "-s" "$shell")
    
    if [[ -n "$comment" ]]; then
        useradd_cmd+=("-c" "$comment")
    fi
    
    if [[ -n "$home_dir" && "$home_dir" != "${CONFIG[home_base]}/$username" ]]; then
        useradd_cmd+=("-d" "$home_dir")
    fi
    
    useradd_cmd+=("$username")
    
    # Execute user creation
    if ! run_cmd "${useradd_cmd[@]}"; then
        log_error "Failed to create user $username"
        return $USER_OP_SYSTEM_ERROR
    fi
    
    # Set password if provided
    if [[ -n "$password" ]]; then
        if ! echo "$username:$password" | chpasswd 2>/dev/null; then
            log_error "Failed to set password for $username"
            # Clean up created user
            userdel -r "$username" 2>/dev/null || true
            return $USER_OP_SYSTEM_ERROR
        fi
        log_info "Password set for $username"
    fi
    
    # Add to groups
    if [[ -n "$groups" ]]; then
        IFS=',' read -ra group_array <<< "$groups"
        for group in "${group_array[@]}"; do
            if ! usermod -aG "$group" "$username" 2>/dev/null; then
                log_warning "Failed to add $username to group $group"
            else
                log_info "Added $username to group $group"
            fi
        done
    fi
    
    # Apply security hardening
    if ! harden_user_account "$username"; then
        log_warning "Security hardening failed for $username"
    fi
    
    # Log successful creation
    log_audit "USER_CREATE" "username=$username" "shell=$shell" "groups=$groups" "home=$home_dir"
    
    # Display user information
    echo "User created successfully:"
    echo "  Username: $username"
    echo "  Shell: $shell"
    echo "  Home: $home_dir"
    [[ -n "$groups" ]] && echo "  Groups: $groups"
    [[ -n "$comment" ]] && echo "  Comment: $comment"
    [[ -n "$password" ]] && echo "  Password: $password"
    
    return $USER_OP_SUCCESS
}

# Modify existing user with enterprise controls
modify_enterprise_user() {
    local username="$1"
    local options="$2"
    local errors=0
    
    log_info "Modifying enterprise user: $username"
    
    # Validate user exists
    if ! id "$username" &>/dev/null; then
        log_error "User $username does not exist"
        return $USER_OP_NOT_FOUND
    fi
    
    # Parse options
    local shell=""
    local groups=""
    local comment=""
    local home_dir=""
    local lock_account=false
    local unlock_account=false
    
    # Parse command line options
    while IFS='=' read -r key value; do
        case "$key" in
            shell) shell="$value" ;;
            groups) groups="$value" ;;
            comment) comment="$value" ;;
            home) home_dir="$value" ;;
            lock) lock_account=true ;;
            unlock) unlock_account=true ;;
        esac
    done <<< "$options"
    
    # Validate shell if provided
    if [[ -n "$shell" ]]; then
        if ! command -v "$shell" >/dev/null 2>&1; then
            log_error "Invalid shell: $shell"
            ((errors++))
        fi
    fi
    
    # Validate groups if provided
    if [[ -n "$groups" ]]; then
        IFS=',' read -ra group_array <<< "$groups"
        for group in "${group_array[@]}"; do
            if ! getent group "$group" &>/dev/null; then
                log_error "Group $group does not exist"
                ((errors++))
            fi
        done
    fi
    
    # Validate home directory if provided
    if [[ -n "$home_dir" && ! -d "$(dirname "$home_dir")" ]]; then
        log_error "Parent directory for home does not exist: $(dirname "$home_dir")"
        ((errors++))
    fi
    
    if [[ $errors -gt 0 ]]; then
        return $USER_OP_INVALID_INPUT
    fi
    
    # Apply modifications
    local modified=false
    
    # Change shell
    if [[ -n "$shell" ]]; then
        if usermod -s "$shell" "$username" 2>/dev/null; then
            log_info "Changed shell for $username to $shell"
            modified=true
        else
            log_error "Failed to change shell for $username"
            return $USER_OP_SYSTEM_ERROR
        fi
    fi
    
    # Change comment
    if [[ -n "$comment" ]]; then
        if usermod -c "$comment" "$username" 2>/dev/null; then
            log_info "Changed comment for $username to: $comment"
            modified=true
        else
            log_error "Failed to change comment for $username"
            return $USER_OP_SYSTEM_ERROR
        fi
    fi
    
    # Change home directory
    if [[ -n "$home_dir" ]]; then
        if usermod -d "$home_dir" "$username" 2>/dev/null; then
            log_info "Changed home directory for $username to $home_dir"
            modified=true
        else
            log_error "Failed to change home directory for $username"
            return $USER_OP_SYSTEM_ERROR
        fi
    fi
    
    # Manage groups (replace current groups)
    if [[ -n "$groups" ]]; then
        # Get current groups to preserve primary group
        local primary_group
        primary_group=$(id -gn "$username")
        
        # Build group list with primary group first
        local group_list="$primary_group"
        IFS=',' read -ra group_array <<< "$groups"
        for group in "${group_array[@]}"; do
            if [[ "$group" != "$primary_group" ]]; then
                group_list+=",$group"
            fi
        done
        
        if usermod -G "$group_list" "$username" 2>/dev/null; then
            log_info "Updated groups for $username to: $group_list"
            modified=true
        else
            log_error "Failed to update groups for $username"
            return $USER_OP_SYSTEM_ERROR
        fi
    fi
    
    # Lock account
    if [[ "$lock_account" == true ]]; then
        if usermod -L "$username" 2>/dev/null; then
            log_info "Locked account for $username"
            modified=true
        else
            log_error "Failed to lock account for $username"
            return $USER_OP_SYSTEM_ERROR
        fi
    fi
    
    # Unlock account
    if [[ "$unlock_account" == true ]]; then
        if usermod -U "$username" 2>/dev/null; then
            log_info "Unlocked account for $username"
            modified=true
        else
            log_error "Failed to unlock account for $username"
            return $USER_OP_SYSTEM_ERROR
        fi
    fi
    
    if [[ "$modified" == true ]]; then
        log_audit "USER_MODIFY" "username=$username" "options=$options"
        echo "User $username modified successfully"
    else
        log_info "No modifications applied to $username"
    fi
    
    return $USER_OP_SUCCESS
}

# Delete user with enterprise safeguards
delete_enterprise_user() {
    local username="$1"
    local remove_home="${2:-true}"
    local backup_home="${3:-false}"
    
    log_info "Deleting enterprise user: $username"
    
    # Validate user exists
    if ! id "$username" &>/dev/null; then
        log_error "User $username does not exist"
        return $USER_OP_NOT_FOUND
    fi
    
    # Prevent deletion of system users
    if is_reserved_username "$username"; then
        log_error "Cannot delete system user: $username"
        return $USER_OP_PERMISSION_DENIED
    fi
    
    # Backup home directory if requested
    if [[ "$backup_home" == true ]]; then
        local user_home
        user_home=$(getent passwd "$username" | cut -d: -f6)
        local backup_dir
        backup_dir="${CONFIG[backup_dir]}/$(date +%Y%m%d_%H%M%S)_${username}"
        
        if [[ -d "$user_home" ]]; then
            mkdir -p "$backup_dir"
            if cp -r "$user_home" "$backup_dir/"; then
                log_info "Backed up home directory to: $backup_dir"
            else
                log_warning "Failed to backup home directory"
            fi
        fi
    fi
    
    # Build userdel command
    local userdel_cmd=("userdel")
    if [[ "$remove_home" == true ]]; then
        userdel_cmd+=("-r")
    fi
    userdel_cmd+=("$username")
    
    # Execute user deletion
    if ! run_cmd "${userdel_cmd[@]}"; then
        log_error "Failed to delete user $username"
        return $USER_OP_SYSTEM_ERROR
    fi
    
    log_audit "USER_DELETE" "username=$username" "remove_home=$remove_home" "backup_home=$backup_home"
    echo "User $username deleted successfully"
    
    return $USER_OP_SUCCESS
}

# Create enterprise group with validation
create_enterprise_group() {
    local groupname="$1"
    local options="${2:-}"
    
    log_info "Creating enterprise group: $groupname"
    
    # Validate group name
    if ! validate_groupname "$groupname"; then
        log_error "Invalid group name: $groupname"
        return $GROUP_OP_INVALID_INPUT
    fi
    
    # Check if group already exists
    if getent group "$groupname" &>/dev/null; then
        log_error "Group $groupname already exists"
        return $GROUP_OP_EXISTS
    fi
    
    # Parse options
    local gid=""
    
    # Parse command line options
    while IFS='=' read -r key value; do
        case "$key" in
            gid) gid="$value" ;;
        esac
    done <<< "$options"
    
    # Validate GID if provided
    if [[ -n "$gid" ]]; then
        if ! validate_positive_int "$gid" "GID"; then
            log_error "Invalid GID: $gid"
            return $GROUP_OP_INVALID_INPUT
        fi
        
        if getent group "$gid" &>/dev/null; then
            log_error "GID $gid already in use"
            return $GROUP_OP_EXISTS
        fi
    fi
    
    # Build groupadd command
    local groupadd_cmd=("groupadd")
    if [[ -n "$gid" ]]; then
        groupadd_cmd+=("-g" "$gid")
    fi
    groupadd_cmd+=("$groupname")
    
    # Execute group creation
    if ! run_cmd "${groupadd_cmd[@]}"; then
        log_error "Failed to create group $groupname"
        return $GROUP_OP_SYSTEM_ERROR
    fi
    
    log_audit "GROUP_CREATE" "groupname=$groupname" "gid=$gid"
    echo "Group $groupname created successfully"
    
    return $GROUP_OP_SUCCESS
}

# Delete enterprise group with safeguards
delete_enterprise_group() {
    local groupname="$1"
    
    log_info "Deleting enterprise group: $groupname"
    
    # Validate group exists
    if ! getent group "$groupname" &>/dev/null; then
        log_error "Group $groupname does not exist"
        return $GROUP_OP_NOT_FOUND
    fi
    
    # Check if group has members
    local members
    members=$(getent group "$groupname" | cut -d: -f4)
    if [[ -n "$members" ]]; then
        log_error "Cannot delete group $groupname - has members: $members"
        return $GROUP_OP_PERMISSION_DENIED
    fi
    
    # Prevent deletion of system groups
    local system_groups=("root" "daemon" "bin" "sys" "adm" "wheel" "sudo" "users")
    for sys_group in "${system_groups[@]}"; do
        if [[ "$groupname" == "$sys_group" ]]; then
            log_error "Cannot delete system group: $groupname"
            return $GROUP_OP_PERMISSION_DENIED
        fi
    done
    
    # Execute group deletion
    if ! groupdel "$groupname" 2>/dev/null; then
        log_error "Failed to delete group $groupname"
        return $GROUP_OP_SYSTEM_ERROR
    fi
    
    log_audit "GROUP_DELETE" "groupname=$groupname"
    echo "Group $groupname deleted successfully"
    
    return $GROUP_OP_SUCCESS
}

# Add user to group with validation
add_user_to_group() {
    local username="$1"
    local groupname="$2"
    
    log_info "Adding user $username to group $groupname"
    
    # Validate user exists
    if ! id "$username" &>/dev/null; then
        log_error "User $username does not exist"
        return $USER_OP_NOT_FOUND
    fi
    
    # Validate group exists
    if ! getent group "$groupname" &>/dev/null; then
        log_error "Group $groupname does not exist"
        return $GROUP_OP_NOT_FOUND
    fi
    
    # Check if user is already in group
    if groups "$username" | grep -q "\b$groupname\b"; then
        log_info "User $username is already in group $groupname"
        return $USER_OP_SUCCESS
    fi
    
    # Add user to group
    if ! usermod -aG "$groupname" "$username" 2>/dev/null; then
        log_error "Failed to add $username to group $groupname"
        return $USER_OP_SYSTEM_ERROR
    fi
    
    log_audit "USER_GROUP_ADD" "username=$username" "groupname=$groupname"
    echo "Added $username to group $groupname"
    
    return $USER_OP_SUCCESS
}

# Remove user from group with validation
remove_user_from_group() {
    local username="$1"
    local groupname="$2"
    
    log_info "Removing user $username from group $groupname"
    
    # Validate user exists
    if ! id "$username" &>/dev/null; then
        log_error "User $username does not exist"
        return $USER_OP_NOT_FOUND
    fi
    
    # Validate group exists
    if ! getent group "$groupname" &>/dev/null; then
        log_error "Group $groupname does not exist"
        return $GROUP_OP_NOT_FOUND
    fi
    
    # Check if user is in group
    if ! groups "$username" | grep -q "\b$groupname\b"; then
        log_info "User $username is not in group $groupname"
        return $USER_OP_SUCCESS
    fi
    
    # Prevent removal from primary group
    local primary_group
    primary_group=$(id -gn "$username")
    if [[ "$groupname" == "$primary_group" ]]; then
        log_error "Cannot remove $username from primary group $groupname"
        return $USER_OP_PERMISSION_DENIED
    fi
    
    # Get current groups excluding the one to remove
    local current_groups
    current_groups=$(id -Gn "$username" | tr ' ' ',')
    local new_groups
    new_groups=$(echo "$current_groups" | sed "s/$groupname//" | sed 's/,,*/,/g' | sed 's/^,//' | sed 's/,$//')
    
    # Update user groups
    if ! usermod -G "$new_groups" "$username" 2>/dev/null; then
        log_error "Failed to remove $username from group $groupname"
        return $USER_OP_SYSTEM_ERROR
    fi
    
    log_audit "USER_GROUP_REMOVE" "username=$username" "groupname=$groupname"
    echo "Removed $username from group $groupname"
    
    return $USER_OP_SUCCESS
}

# List users with enterprise formatting
list_enterprise_users() {
    local filter="${1:-all}"
    # shellcheck disable=SC2034
    local format="${2:-table}"
    
    case "$filter" in
        all)
            getent passwd | grep -E '^[^:]+:[^:]*:[0-9]{4,}:' | cut -d: -f1
            ;;
        system)
            getent passwd | grep -E '^[^:]+:[^:]*:[0-9]{1,3}:' | cut -d: -f1
            ;;
        regular)
            getent passwd | grep -E '^[^:]+:[^:]*:[0-9]{4,}:' | cut -d: -f1
            ;;
        locked)
            getent passwd | cut -d: -f1 | while read -r user; do
                if [[ "$user" != "root" ]] && passwd -S "$user" 2>/dev/null | grep -q "^$user.*L"; then
                    echo "$user"
                fi
            done
            ;;
        *)
            log_error "Invalid filter: $filter"
            return 1
            ;;
    esac
}

# Get detailed user information
get_user_info() {
    local username="$1"
    
    # Validate user exists
    if ! id "$username" &>/dev/null; then
        log_error "User $username does not exist"
        return $USER_OP_NOT_FOUND
    fi
    
    echo "=== User Information: $username ==="
    echo "UID/GID: $(id -u "$username")/$(id -g "$username")"
    echo "Groups: $(groups "$username" | tr ' ' ',')"
    echo "Shell: $(getent passwd "$username" | cut -d: -f7)"
    echo "Home: $(getent passwd "$username" | cut -d: -f6)"
    echo "Comment: $(getent passwd "$username" | cut -d: -f5)"
    
    # Password information
    echo ""
    echo "=== Password Information ==="
    chage -l "$username" 2>/dev/null || echo "Password aging information not available"
    
    # Login information
    echo ""
    echo "=== Login Information ==="
    lastlog -u "$username" 2>/dev/null | tail -n +2 || echo "No login information available"
    
    # Process information
    echo ""
    echo "=== Process Information ==="
    local process_count
    process_count=$(pgrep -u "$username" | wc -l)
    echo "Running processes: $process_count"
    
    if [[ $process_count -gt 0 ]]; then
        ps -u "$username" -o pid,ppid,cmd,etime --no-headers 2>/dev/null | head -10
    fi
}

# Initialize user operations module
init_user_operations() {
    log_debug "Initializing user operations module"
    
    # Validate required system tools
    local required_tools=("useradd" "usermod" "userdel" "groupadd" "groupdel" "getent" "id" "groups")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            log_error "Required tool not found: $tool"
            return 1
        fi
    done
    
    # Ensure backup directory exists
    if [[ ! -d "${CONFIG[backup_dir]}" ]]; then
        mkdir -p "${CONFIG[backup_dir]}" 2>/dev/null || log_warning "Cannot create backup directory"
    fi
    
    log_info "User operations module initialized successfully"
    return 0
}

# Export functions for use in other modules
export -f create_enterprise_user
export -f modify_enterprise_user
export -f delete_enterprise_user
export -f create_enterprise_group
export -f delete_enterprise_group
export -f add_user_to_group
export -f remove_user_from_group
export -f list_enterprise_users
export -f get_user_info
export -f init_user_operations

# Auto-initialize when sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "User operations library must be sourced, not executed"
    exit 1
fi

init_user_operations
