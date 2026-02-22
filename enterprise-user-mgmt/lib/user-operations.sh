#!/usr/bin/env bash
# Core user and group operations

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
# Usage: create_single_user USERNAME [OPTIONS]
# Options:
#   --shell SHELL         Set login shell (default: bash)
#   --home-dir DIR       Set home directory (default: /home/username)
#   --password PASS       Set initial password (default: ChangeMe123!)
#   --no-force-change    Don't force password change on first login
#   --groups "GROUP1,GROUP2"  Add user to specified groups
#   --comment "TEXT"     Set user comment field
#   --uid NUM            Set specific user ID
#   --gid NUM            Set specific group ID
create_single_user() {
	require_root

	local username="$1"
	shift

	# Validate username format
	if ! validate_username "$username"; then
		log_error "Invalid username: $username"
		return 2
	fi

	# Check if user already exists
	if user_exists "$username"; then
		log_warn "User $username already exists, skipping"
		return 0
	fi

	# Default values
	local user_shell="${CONFIG[default_shell]}"
	local user_home="${CONFIG[home_base]}/$username"
	local user_password="ChangeMe123!"
	local force_change=true
	local user_groups=""
	local user_comment="Custom User $username"
	local user_uid=""
	local user_gid=""

	# Parse options
	while [[ $# -gt 0 ]]; do
		case $1 in
			--shell)
				user_shell="$2"
				shift 2
				;;
			--home-dir)
				user_home="$2"
				shift 2
				;;
			--password)
				user_password="$2"
				shift 2
				;;
			--no-force-change)
				force_change=false
				shift
				;;
			--groups)
				user_groups="$2"
				shift 2
				;;
			--comment)
				user_comment="$2"
				shift 2
				;;
			--uid)
				user_uid="$2"
				shift 2
				;;
			--gid)
				user_gid="$2"
				shift 2
				;;
			*)
				log_error "Unknown option: $1"
				return 2
				;;
		esac
	done

	log_info "Creating user: $username with custom options"
	log_debug "Shell: $user_shell"
	log_debug "Home: $user_home"
	log_debug "Groups: $user_groups"
	log_debug "Force change: $force_change"

	# Build useradd command
	local useradd_cmd="useradd -m"
	[[ -n "$user_home" ]] && useradd_cmd="$useradd_cmd -d $user_home"
	[[ -n "$user_shell" ]] && useradd_cmd="$useradd_cmd -s $user_shell"
	[[ -n "$user_comment" ]] && useradd_cmd="$useradd_cmd -c '$user_comment'"
	[[ -n "$user_uid" ]] && useradd_cmd="$useradd_cmd -u $user_uid"
	[[ -n "$user_gid" ]] && useradd_cmd="$useradd_cmd -g $user_gid"
	useradd_cmd="$useradd_cmd $username"

	# Create user
	if ! run_cmd "$useradd_cmd" "Create user $username"; then
		log_error "Failed to create user $username"
		return 5
	fi

	# Set initial password
	if ! run_cmd "echo '$username:$user_password' | chpasswd" "Set initial password for $username"; then
		log_error "Failed to set password for $username"
		return 5
	fi

	# Force password change on first login if requested
	if [[ "$force_change" == "true" ]]; then
		if ! run_cmd "chage -d 0 $username" "Force password change for $username"; then
			log_error "Failed to set password expiration for $username"
			return 5
		fi
	fi

	# Add user to groups if specified
	if [[ -n "$user_groups" ]]; then
		IFS=',' read -ra groups_array <<< "$user_groups"
		for group in "${groups_array[@]}"; do
			group=$(echo "$group" | xargs) # Trim whitespace
			if group_exists "$group"; then
				log_info "Adding $username to group: $group"
				if ! run_cmd "usermod -aG $group $username" "Add $username to group $group"; then
					log_warn "Failed to add $username to group $group"
				fi
			else
				log_warn "Group $group does not exist, skipping"
			fi
		done
	fi

	log_info "Successfully created user: $username"
	[[ "$force_change" == "true" ]] && log_info "User will be prompted to change password on first login"
	[[ -n "$user_groups" ]] && log_info "User added to groups: $user_groups"
}

# Create required groups
create_required_groups() {
	require_root

	local groups=("developers" "admins")

	log_info "Creating required groups..."

	for group in "${groups[@]}"; do
		if group_exists "$group"; then
			log_warn "Group $group already exists, skipping"
			continue
		fi

		log_info "Creating group: $group"

		if ! run_cmd "groupadd $group" "Create group $group"; then
			log_error "Failed to create group $group"
			return 5
		fi

		log_info "Successfully created group: $group"
	done

	log_info "Group creation completed"
}

# Assign users to groups
assign_users_to_groups() {
	require_root

	# Group assignments
	declare -A assignments=(
		[dev1]="developers"
		[dev2]="developers"
		[dev3]="developers,admins" # dev3 is also admin
	)

	log_info "Assigning users to groups..."

	for user in "${!assignments[@]}"; do
		if ! user_exists "$user"; then
			log_error "User $user does not exist, skipping assignments"
			continue
		fi

		IFS=',' read -ra groups <<<"${assignments[$user]}"
		for group in "${groups[@]}"; do
			group=$(echo "$group" | xargs) # Trim whitespace

			if ! group_exists "$group"; then
				log_error "Group $group does not exist, skipping"
				continue
			fi

			log_info "Adding $user to group: $group"

			if ! run_cmd "usermod -aG $group $user" "Add $user to $group"; then
				log_error "Failed to add $user to group $group"
				return 5
			fi
		done
	done

	log_info "Group assignments completed"
}

# Configure sudo access
configure_sudo_access() {
	require_root

	local sudoers_file="${CONFIG[sudoers_dir]}/admins"

	log_info "Configuring sudo access for admins..."

	# Ensure sudoers.d directory exists with correct permissions
	if [[ ! -d "${CONFIG[sudoers_dir]}" ]]; then
		run_cmd "mkdir -p ${CONFIG[sudoers_dir]}" "Create sudoers.d directory"
		run_cmd "chmod 750 ${CONFIG[sudoers_dir]}" "Set sudoers.d permissions"
	fi

	# Create admin sudoers file
	local temp_file
	temp_file=$(mktemp)
	cat >"$temp_file" <<EOF
# Grant full sudo access to admins group
%admins ALL=(ALL:ALL) ALL

# Secure path for admins
Defaults:%admins secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Log all admin commands
Defaults:%admins log_output
Defaults:%admins syslog=auth
EOF

	# Validate and install sudoers file
	if visudo -cf "$temp_file"; then
		run_cmd "cp $temp_file $sudoers_file" "Copy sudoers file"
		run_cmd "chmod 440 $sudoers_file" "Set sudoers file permissions"
		run_cmd "chown root:root $sudoers_file" "Set sudoers file ownership"
		log_info "Sudo access configured successfully"
	else
		log_error "Invalid sudoers configuration"
		rm -f "$temp_file"
		return 5
	fi

	rm -f "$temp_file"
}

# Apply password policies
apply_password_policies() {
	require_root

	# Validate policy parameters
	if ! validate_password_policy \
		"${CONFIG[password_max_days]}" \
		"${CONFIG[password_min_days]}" \
		"${CONFIG[password_warn_days]}" \
		"${CONFIG[inactive_days]}"; then
		return 4
	fi

	log_info "Applying password policies to all users..."

	# Get all regular users (UID >= 1000)
	while IFS=: read -r username _ uid _; do
		if [[ $uid -ge 1000 ]]; then
			log_debug "Applying password policy to: $username"

			# Set password aging
			run_cmd "chage -M ${CONFIG[password_max_days]} $username" \
				"Set max days for $username"
			run_cmd "chage -m ${CONFIG[password_min_days]} $username" \
				"Set min days for $username"
			run_cmd "chage -W ${CONFIG[password_warn_days]} $username" \
				"Set warn days for $username"
			run_cmd "chage -I ${CONFIG[inactive_days]} $username" \
				"Set inactive days for $username"

			# Log current settings
			if $VERBOSE; then
				chage -l "$username" | while read -r line; do
					log_debug "  $line"
				done
			fi
		fi
	done </etc/passwd

	# Also set global policy in /etc/login.defs
	local login_defs="/etc/login.defs"
	if [[ -f "$login_defs" ]]; then
		log_info "Updating global password policies in $login_defs"

		# Backup original
		run_cmd "cp $login_defs ${login_defs}.backup" "Backup login.defs"

		# Update values
		run_cmd "sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   ${CONFIG[password_max_days]}/' $login_defs"
		run_cmd "sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   ${CONFIG[password_min_days]}/' $login_defs"
		run_cmd "sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   ${CONFIG[password_warn_days]}/' $login_defs"
	fi

	log_info "Password policies applied successfully"
}

# Lock user account
lock_user_account() {
	require_root

	local username="$1"

	if [[ -z "$username" ]]; then
		log_error "Username required for lock operation"
		return 2
	fi

	if ! user_exists "$username"; then
		log_error "User $username does not exist"
		return 5
	fi

	log_info "Locking account: $username"

	# Lock password and expire account
	run_cmd "passwd -l $username" "Lock password for $username"
	run_cmd "chage -E 0 $username" "Expire account for $username"

	# Kill all user processes (optional)
	if run_cmd "pkill -u $username" "Kill processes for $username"; then
		log_info "Terminated all processes for $username"
	fi

	log_info "Account $username locked successfully"
}

# Unlock user account
unlock_user_account() {
	require_root

	local username="$1"

	if [[ -z "$username" ]]; then
		log_error "Username required for unlock operation"
		return 2
	fi

	if ! user_exists "$username"; then
		log_error "User $username does not exist"
		return 5
	fi

	log_info "Unlocking account: $username"

	# Unlock password and remove account expiration
	run_cmd "passwd -u $username" "Unlock password for $username"
	run_cmd "chage -E -1 $username" "Remove account expiration for $username"

	log_info "Account $username unlocked successfully"
}

# Show system status
show_system_status() {
	log_info "=== System Status ==="

	echo -e "\nUsers:"
	printf "%-15s %-20s %-15s %s\n" "Username" "Home" "Shell" "Groups"
	printf "%s\n" "----------------------------------------"

	for user in dev1 dev2 dev3; do
		if user_exists "$user"; then
			home=$(getent passwd "$user" | cut -d: -f6)
			shell=$(getent passwd "$user" | cut -d: -f7)
			local groups
			groups=$(id -nG "$user" | tr ' ' ',')
			printf "%-15s %-20s %-15s %s\n" "$user" "$home" "$shell" "$groups"
		fi
	done

	echo -e "\nGroups:"
	for group in developers admins; do
		if group_exists "$group"; then
			members=$(getent group "$group" | cut -d: -f4)
			echo "$group: ${members:-<no members>}"
		fi
	done

	echo -e "\nSudo Access:"
	if [[ -f "${CONFIG[sudoers_dir]}/admins" ]]; then
		echo "Admin sudo configured: YES"
		grep -E "^%admins" "${CONFIG[sudoers_dir]}/admins" | sed 's/^/  /'
	else
		echo "Admin sudo configured: NO"
	fi

	echo -e "\nPassword Policies:"
	for user in dev1 dev2 dev3; do
		if user_exists "$user"; then
			echo -e "\n$user:"
			chage -l "$user" 2>/dev/null | sed 's/^/  /'
		fi
	done
}

# Validate configuration
validate_configuration() {
	log_info "Validating system configuration..."
	local errors=0

	# Check required users
	for user in dev1 dev2 dev3; do
		if ! user_exists "$user"; then
			log_error "Missing user: $user"
			((errors++))
		fi
	done

	# Check required groups
	for group in developers admins; do
		if ! group_exists "$group"; then
			log_error "Missing group: $group"
			((errors++))
		fi
	done

	# Check group memberships
	if user_exists "dev1" && ! id -nG "dev1" | grep -q "developers"; then
		log_error "dev1 not in developers group"
		((errors++))
	fi

	if user_exists "dev3" && ! id -nG "dev3" | grep -q "admins"; then
		log_error "dev3 not in admins group"
		((errors++))
	fi

	# Check sudo configuration
	local sudoers_file="${CONFIG[sudoers_dir]}/admins"
	if [[ ! -f "$sudoers_file" ]]; then
		log_error "Admin sudoers file not configured"
		((errors++))
	elif ! validate_sudoers "$sudoers_file"; then
		log_error "Invalid sudoers file syntax"
		((errors++))
	fi

	# Check password policies
	if user_exists "dev1"; then
		local max_days
		max_days=$(chage -l dev1 | grep "Maximum" | awk '{print $NF}')
		if [[ "$max_days" != "${CONFIG[password_max_days]}" ]]; then
			log_error "dev1 password max days is $max_days, expected ${CONFIG[password_max_days]}"
			((errors++))
		fi
	fi

	if [[ $errors -eq 0 ]]; then
		log_info "Validation PASSED - all requirements met"
		return 0
	else
		log_error "Validation FAILED - $errors errors found"
		return 1
	fi
}
