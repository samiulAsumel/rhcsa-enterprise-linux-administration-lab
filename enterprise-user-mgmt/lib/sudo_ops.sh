#!/usr/bin/env bash
# lib/sudo_ops.sh — sudoers management for ugm-tool
# Writes drop-in files to /etc/sudoers.d/ (the safe pattern).
# Never modifies /etc/sudoers directly.
# Depends on: lib/logging.sh, lib/validation.sh

readonly SUDOERS_DIR="/etc/sudoers.d"
readonly SUDOERS_FILE_PREFIX="ugm_"

# ─── _sudoers_filename <groupname> ───────────────────────────────────────────
# Returns the drop-in filename for a group's sudo rule.
_sudoers_filename() {
	echo "${SUDOERS_DIR}/${SUDOERS_FILE_PREFIX}${1}"
}

# ─── grant_sudo_group <groupname> ────────────────────────────────────────────
# Grants full sudo access to all members of a group.
# Uses the %group ALL=(ALL:ALL) ALL pattern.
grant_sudo_group() {
	local groupname="$1"
	validate_groupname "$groupname" || return 1

	if ! group_exists "$groupname"; then
		log_error "Group '${groupname}' does not exist."
		return 1
	fi

	local sudoers_file
	sudoers_file="$(_sudoers_filename "$groupname")"

	if [[ -f "$sudoers_file" ]]; then
		log_warn "sudo rule for group '${groupname}' already exists at ${sudoers_file}."
		log_warn "Remove it first with: ugm sudo revoke-group ${groupname}"
		return 0
	fi

	local rule="%${groupname} ALL=(ALL:ALL) ALL"
	local tmp_file
	tmp_file="$(mktemp /tmp/ugm_sudoers_XXXXXX)"

	# Write rule to temp file
	{
		echo "# ugm-tool managed — do not edit manually"
		echo "# Grant sudo to group: ${groupname}"
		echo "# Generated: $(date '+%Y-%m-%d %H:%M:%S') by $(id -un)"
		echo ""
		echo "$rule"
	} >"$tmp_file"

	# Validate syntax with visudo -c before installing
	log_info "Validating sudoers syntax for group '${groupname}'..."
	if command -v visudo &>/dev/null; then
		if ! visudo -c -f "$tmp_file" &>/dev/null; then
			log_error "Generated sudoers snippet failed visudo syntax check."
			rm -f "$tmp_file"
			log_audit "grant_sudo_group" "$groupname" "fail:visudo_check"
			return 1
		fi
		log_debug "visudo syntax check passed."
	else
		log_warn "visudo not found — skipping syntax validation. Install the 'sudo' package for safety checks."
	fi

	# Set strict permissions before moving into place
	chmod 0440 "$tmp_file"
	if mv "$tmp_file" "$sudoers_file"; then
		log_success "sudo access granted to group '${groupname}' via ${sudoers_file}"
		log_info "Rule: ${rule}"
		log_audit "grant_sudo_group" "$groupname" "ok"
	else
		log_error "Failed to install sudoers file for group '${groupname}'."
		rm -f "$tmp_file"
		log_audit "grant_sudo_group" "$groupname" "fail:install"
		return 1
	fi
}

# ─── revoke_sudo_group <groupname> ───────────────────────────────────────────
revoke_sudo_group() {
	local groupname="$1"
	validate_groupname "$groupname" || return 1

	local sudoers_file
	sudoers_file="$(_sudoers_filename "$groupname")"

	if [[ ! -f "$sudoers_file" ]]; then
		log_warn "No ugm-managed sudo rule found for group '${groupname}'."
		return 0
	fi

	log_info "Revoking sudo access from group '${groupname}'..."
	if rm -f "$sudoers_file"; then
		log_success "sudo access revoked from group '${groupname}'."
		log_audit "revoke_sudo_group" "$groupname" "ok"
	else
		log_error "Failed to remove sudoers file: ${sudoers_file}"
		log_audit "revoke_sudo_group" "$groupname" "fail"
		return 1
	fi
}

# ─── list_ugm_sudo_rules ─────────────────────────────────────────────────────
list_ugm_sudo_rules() {
	local found=0
	echo ""
	echo "  ugm-managed sudo rules in ${SUDOERS_DIR}:"
	echo ""
	for f in "${SUDOERS_DIR}/${SUDOERS_FILE_PREFIX}"*; do
		[[ -f "$f" ]] || continue
		echo "  File: ${f}"
		grep -v '^#' "$f" | grep -v '^$' | sed 's/^/    /'
		echo ""
		found=1
	done
	if [[ "$found" -eq 0 ]]; then
		echo "  (none found)"
		echo ""
	fi
}
