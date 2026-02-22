#!/usr/bin/env bash
# Input validation utilities

# Validate username format
validate_username() {
	local username="$1"

	# Username rules:
	# - 1-32 characters
	# - Only lowercase letters, numbers, underscore, hyphen
	# -  Must start with letter

	if [[ ! "$username" =~ ^[a-z][a-z0-9_-]{0,31}$ ]]; then
		echo "Error: Invalid username '$username'."
		echo "Username must be 1-32 characters, start with a letter, and can contain lowercase letters, numbers, underscores, or hyphens."
		return 1
	fi
	return 0
}

# Validate group name
validate_groupname() {
	local groupname="$1"

	if [[ ! $groupname =~ ^[a-z][a-z0-9_-]{0,31}$ ]]; then
		echo "Error: Invalid group name '$groupname'."
		echo "Group name must be 1-32 characters, start with a letter, and can contain lowercase letters, numbers, underscores, or hyphens."
		return 1
	fi
	return 0
}

# Check if user exists
user_exists() {
	local username="$1"
	if id "$username" &>/dev/null; then
		return  0 
	fi
	return 1
}

# Check if group exists
group_exists() {
	local groupname="$1"
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