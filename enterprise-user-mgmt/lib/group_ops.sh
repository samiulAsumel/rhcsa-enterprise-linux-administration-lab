#!/usr/bin/env bash
# lib/group_ops.sh — Group management operations for ugm-tool
# Depends on: lib/logging.sh, lib/validation.sh

# ─── create_group <groupname> [--gid <gid>] ──────────────────────────────────
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
		validate_positive_int "$gid" "GID" || return 1
		groupadd_args+=(-g "$gid")
	fi

	log_info "Creating group '${groupname}'..."
	if groupadd "${groupadd_args[@]}" "$groupname"; then
		log_success "Group '${groupname}' created."
		log_audit "create_group" "$groupname" "ok"
	else
		log_error "Failed to create group '${groupname}'."
		log_audit "create_group" "$groupname" "fail"
		return 1
	fi
}

# ─── delete_group <groupname> ─────────────────────────────────────────────────
delete_group() {
	local groupname="$1"
	validate_groupname "$groupname" || return 1

	if ! group_exists "$groupname"; then
		log_warn "Group '${groupname}' does not exist — nothing to delete."
		return 0
	fi

	# Warn if group still has members
	local members
	members=$(getent group "$groupname" | cut -d: -f4)
	if [[ -n "$members" ]]; then
		log_warn "Group '${groupname}' still has members: ${members}"
		log_warn "Members will lose this group membership on deletion."
	fi

	log_info "Deleting group '${groupname}'..."
	if groupdel "$groupname"; then
		log_success "Group '${groupname}' deleted."
		log_audit "delete_group" "$groupname" "ok"
	else
		log_error "Failed to delete group '${groupname}'."
		log_audit "delete_group" "$groupname" "fail"
		return 1
	fi
}

# ─── add_user_to_group <username> <groupname> ─────────────────────────────────
# Appends the user to the group (preserves existing memberships).
add_user_to_group() {
	local username="$1"
	local groupname="$2"

	validate_username "$username" || return 1
	validate_groupname "$groupname" || return 1

	if ! user_exists "$username"; then
		log_error "User '${username}' does not exist."
		return 1
	fi
	if ! group_exists "$groupname"; then
		log_error "Group '${groupname}' does not exist."
		return 1
	fi

	if user_in_group "$username" "$groupname"; then
		log_warn "User '${username}' is already in group '${groupname}' — skipping."
		return 0
	fi

	log_info "Adding '${username}' to group '${groupname}'..."
	if usermod -aG "$groupname" "$username"; then
		log_success "User '${username}' added to group '${groupname}'."
		log_audit "add_user_to_group" "${username}:${groupname}" "ok"
	else
		log_error "Failed to add '${username}' to group '${groupname}'."
		log_audit "add_user_to_group" "${username}:${groupname}" "fail"
		return 1
	fi
}

# ─── remove_user_from_group <username> <groupname> ────────────────────────────
remove_user_from_group() {
	local username="$1"
	local groupname="$2"

	validate_username "$username" || return 1
	validate_groupname "$groupname" || return 1

	if ! user_exists "$username"; then
		log_error "User '${username}' does not exist."
		return 1
	fi
	if ! group_exists "$groupname"; then
		log_error "Group '${groupname}' does not exist."
		return 1
	fi

	if ! user_in_group "$username" "$groupname"; then
		log_warn "User '${username}' is not in group '${groupname}' — skipping."
		return 0
	fi

	log_info "Removing '${username}' from group '${groupname}'..."
	if gpasswd -d "$username" "$groupname"; then
		log_success "User '${username}' removed from group '${groupname}'."
		log_audit "remove_user_from_group" "${username}:${groupname}" "ok"
	else
		log_error "Failed to remove '${username}' from group '${groupname}'."
		log_audit "remove_user_from_group" "${username}:${groupname}" "fail"
		return 1
	fi
}

# ─── show_group_info <groupname> ──────────────────────────────────────────────
show_group_info() {
	local groupname="$1"
	validate_groupname "$groupname" || return 1

	if ! group_exists "$groupname"; then
		log_error "Group '${groupname}' does not exist."
		return 1
	fi

	local gid members
	gid=$(getent group "$groupname" | cut -d: -f3)
	members=$(getent group "$groupname" | cut -d: -f4)
	[[ -z "$members" ]] && members="(none)"

	echo ""
	echo "  Group   : ${groupname}"
	echo "  GID     : ${gid}"
	echo "  Members : ${members}"
	echo ""
}
