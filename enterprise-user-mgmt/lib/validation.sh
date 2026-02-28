#!/usr/bin/env bash
# Enterprise Input validation utilities
# Compliance: CIS Benchmarks, NIST 800-53, Security standards

# Validate username format with enterprise rules
validate_username() {
	local username="$1"

	# Enhanced username rules:
	# - 1-32 characters
	# - Only lowercase letters, numbers, underscore, hyphen
	# - Must start with letter
	# - Not reserved names
	# - Security: No consecutive dots, no trailing dot

	# Reserved system usernames
	local reserved_names=(root daemon bin sys sync games man lp mail news uucp proxy www-data backup list irc gnats nobody systemd-network systemd-resolve syslog messagebus uuidd dnsmasq usbmux rtkit pulse speech-dispatcher avahi saned colord hplip geoclue gnome-initial-setup gdm)
	
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