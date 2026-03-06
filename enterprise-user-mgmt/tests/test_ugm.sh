#!/usr/bin/env bash
# tests/test_ugm.sh — Manual integration test suite for ugm-tool
#
# These tests validate argument parsing, validation logic, and dry-run
# behavior without requiring root or making real system changes.
# Tests that need root are clearly marked and skipped when not root.
#
# Usage:
#   bash tests/test_ugm.sh              # Run all safe tests
#   sudo bash tests/test_ugm.sh --all   # Run all tests including root ops
#
# Exit code: 0 if all executed tests pass, non-zero otherwise.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UGM="${SCRIPT_DIR}/../bin/ugm.sh"
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

# ─── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RESET='\033[0m'
BOLD='\033[1m'

RUN_ROOT_TESTS=0
[[ "${1:-}" == "--all" ]] && RUN_ROOT_TESTS=1

# ─── Helpers ─────────────────────────────────────────────────────────────────
pass() {
	echo -e "${GREEN}  ✓ PASS${RESET} $1"
	((PASS_COUNT++))
}
fail() {
	echo -e "${RED}  ✗ FAIL${RESET} $1"
	((FAIL_COUNT++))
}
skip() {
	echo -e "${YELLOW}  ~ SKIP${RESET} $1"
	((SKIP_COUNT++))
}

section() {
	echo ""
	echo -e "${BOLD}══════════════════════════════════════════${RESET}"
	echo -e "${BOLD}  $1${RESET}"
	echo -e "${BOLD}══════════════════════════════════════════${RESET}"
}

# assert_exit_code <expected> <actual> <test_name>
assert_exit() {
	local expected="$1" actual="$2" name="$3"
	if [[ "$actual" -eq "$expected" ]]; then
		pass "$name (exit=${actual})"
	else
		fail "$name (expected exit=${expected}, got=${actual})"
	fi
}

# run_ugm <expected_exit> <test_name> -- <args...>
run_ugm() {
	local expected_exit="$1"
	local test_name="$2"
	shift 2
	# Skip "--" separator
	[[ "${1:-}" == "--" ]] && shift

	local actual_exit=0
	"$UGM" "$@" >/dev/null 2>&1 || actual_exit=$?
	assert_exit "$expected_exit" "$actual_exit" "$test_name"
}

# ─────────────────────────────────────────────────────────────────────────────
# TEST GROUPS
# ─────────────────────────────────────────────────────────────────────────────

test_help_and_usage() {
	section "Help / Usage"

	run_ugm 0 "ugm --help exits 0" -- --help
	run_ugm 0 "ugm help exits 0" -- help
	run_ugm 0 "ugm user help exits 0" -- user help
	run_ugm 0 "ugm group help exits 0" -- group help
	run_ugm 0 "ugm sudo help exits 0" -- sudo help
	run_ugm 0 "ugm policy help exits 0" -- policy help
	run_ugm 1 "ugm with no args exits 1" --
	run_ugm 1 "ugm unknown-command exits 1" -- foobar
	run_ugm 1 "ugm user with no subcommand exits 1" -- user
	run_ugm 1 "ugm group with no subcommand exits 1" -- group
}

test_input_validation() {
	section "Input Validation (no root required)"

	# These all fail at validation, before any system call
	# Expected: exit 1 (USAGE) because no root check happens first in dry-run
	# for non-root environments we expect exit 2 (NOTROOT) for real ops.

	# Username validation via dry-run
	run_ugm 1 "Invalid username with spaces rejected" -- -n user create "bad name"
	run_ugm 1 "Username starting with digit rejected" -- -n user create "1badname"
	run_ugm 1 "Empty username rejected" -- -n user create ""

	# Group name validation
	run_ugm 1 "Invalid group name rejected" -- -n group create "bad group"
	run_ugm 1 "Group name starting with digit rejected" -- -n group create "9group"

	# Policy validation
	run_ugm 5 "max-age smaller than min-age rejected" -- -n policy set-aging someuser --min 60 --max 30 --warn 7
	run_ugm 5 "warn-days >= max-age rejected" -- -n policy set-aging someuser --min 7 --max 30 --warn 30
	run_ugm 5 "min-age out of range rejected" -- -n policy set-aging someuser --min 200 --max 365 --warn 14
	run_ugm 5 "max-age out of range rejected" -- -n policy set-aging someuser --min 7 --max 999 --warn 14
	run_ugm 5 "warn-days out of range rejected" -- -n policy set-aging someuser --min 7 --max 90 --warn 60

	# Missing required arguments
	run_ugm 1 "user create requires at least one username" -- user create
	run_ugm 1 "group add-member requires user and group" -- group add-member onlyonearg
	run_ugm 1 "sudo grant-group requires group name" -- sudo grant-group
	run_ugm 1 "policy set-aging requires username" -- policy set-aging
}

test_dry_run_no_root() {
	section "Dry-Run: Valid Inputs (no root needed)"

	# In dry-run, root check is still enforced for operations that modify system
	# These will get EXIT_NOTROOT (2) unless running as root
	if [[ "$EUID" -ne 0 ]]; then
		run_ugm 2 "user create dry-run requires root" -- -n user create dev1
		run_ugm 2 "user delete dry-run requires root" -- -n user delete dev1
		run_ugm 2 "user lock dry-run requires root" -- -n user lock dev1
		run_ugm 2 "user unlock dry-run requires root" -- -n user unlock dev1
		run_ugm 2 "group create dry-run requires root" -- -n group create developers
		run_ugm 2 "group add-member dry-run requires root" -- -n group add-member dev1 developers
		run_ugm 2 "sudo grant-group dry-run requires root" -- -n sudo grant-group admins
		run_ugm 2 "policy set-aging dry-run requires root" -- -n policy set-aging dev1 --min 7 --max 90 --warn 14
	else
		run_ugm 0 "user create dry-run (root)" -- -n user create dev1 dev2 dev3
		run_ugm 0 "group create dry-run (root)" -- -n group create developers admins
		run_ugm 0 "policy set-aging dry-run (root)" -- -n policy set-aging dev1 --min 7 --max 90 --warn 14
		run_ugm 0 "sudo grant-group dry-run (root)" -- -n sudo grant-group admins
	fi
}

test_lib_validation_unit() {
	section "Library: Validation Logic Unit Tests"

	# Source libs and test validation functions directly
	local lib_dir="${SCRIPT_DIR}/../lib"
	# shellcheck source=../lib/logging.sh
	source "${lib_dir}/logging.sh"
	# shellcheck source=../lib/validation.sh
	source "${lib_dir}/validation.sh"

	# shellcheck disable=SC2034
	export LOG_NO_COLOR=1
	# shellcheck disable=SC2034
	export LOG_LEVEL=3 # Only errors

	# validate_username
	if validate_username "validuser"; then
		pass "validate_username: valid lowercase"
	else
		fail "validate_username: valid lowercase"
	fi
	if validate_username "valid_user-1"; then
		pass "validate_username: underscores and hyphens"
	else
		fail "validate_username: underscores and hyphens"
	fi
	if validate_username "_systemuser"; then
		pass "validate_username: leading underscore"
	else
		fail "validate_username: leading underscore"
	fi
	if ! validate_username "1startdigit" 2>/dev/null; then
		pass "validate_username: rejects leading digit"
	else
		fail "validate_username: rejects leading digit"
	fi
	if ! validate_username "has space" 2>/dev/null; then
		pass "validate_username: rejects spaces"
	else
		fail "validate_username: rejects spaces"
	fi
	if ! validate_username "" 2>/dev/null; then
		pass "validate_username: rejects empty"
	else
		fail "validate_username: rejects empty"
	fi
	if ! validate_username "UPPER" 2>/dev/null; then
		pass "validate_username: rejects uppercase"
	else
		fail "validate_username: rejects uppercase"
	fi
	if ! validate_username "$(printf '%0.sa' {1..33})" 2>/dev/null; then
		pass "validate_username: rejects >32 chars"
	else
		fail "validate_username: rejects >32 chars"
	fi

	# validate_groupname
	if validate_groupname "developers"; then
		pass "validate_groupname: valid"
	else
		fail "validate_groupname: valid"
	fi
	if ! validate_groupname "9bad" 2>/dev/null; then
		pass "validate_groupname: rejects leading digit"
	else
		fail "validate_groupname: rejects leading digit"
	fi

	# validate_password_aging
	if validate_password_aging 7 90 14; then
		pass "validate_password_aging: valid defaults"
	else
		fail "validate_password_aging: valid defaults"
	fi
	if ! validate_password_aging 60 30 7 2>/dev/null; then
		pass "validate_password_aging: min >= max rejected"
	else
		fail "validate_password_aging: min >= max rejected"
	fi
	if ! validate_password_aging 7 30 30 2>/dev/null; then
		pass "validate_password_aging: warn >= max rejected"
	else
		fail "validate_password_aging: warn >= max rejected"
	fi

	# validate_positive_int
	if validate_positive_int "0" "zero"; then
		pass "validate_positive_int: 0 is valid"
	else
		fail "validate_positive_int: 0 is valid"
	fi
	if validate_positive_int "999" "big"; then
		pass "validate_positive_int: 999 is valid"
	else
		fail "validate_positive_int: 999 is valid"
	fi
	if ! validate_positive_int "-1" "neg" 2>/dev/null; then
		pass "validate_positive_int: negative rejected"
	else
		fail "validate_positive_int: negative rejected"
	fi
	if ! validate_positive_int "abc" "str" 2>/dev/null; then
		pass "validate_positive_int: string rejected"
	else
		fail "validate_positive_int: string rejected"
	fi

	LOG_LEVEL=1 # Restore
}

test_root_ops() {
	section "Root Operations (requires sudo --all)"

	if [[ "$EUID" -ne 0 ]]; then
		skip "Skipping root tests (run with: sudo bash tests/test_ugm.sh --all)"
		return
	fi

	# Source libs for helper functions
	local lib_dir="${SCRIPT_DIR}/../lib"
	source "${lib_dir}/logging.sh"
	source "${lib_dir}/validation.sh"
	LOG_NO_COLOR=1
	LOG_LEVEL=3

	# ── User lifecycle ────────────────────────────────────────────────────────
	local test_users=("ugm_test_u1" "ugm_test_u2")

	for u in "${test_users[@]}"; do
		# Clean up from any previous failed run
		userdel -r "$u" 2>/dev/null || true
	done

	run_ugm 0 "Create test users" -- user create "${test_users[@]}"

	for u in "${test_users[@]}"; do
		if id "$u" &>/dev/null; then
			pass "User '${u}' exists after creation"
		else
			fail "User '${u}' missing after creation"
		fi
	done

	run_ugm 0 "Create users again is idempotent (warn, no fail)" -- user create "${test_users[@]}"

	run_ugm 0 "Lock user" -- user lock "${test_users[0]}"
	if passwd -S "${test_users[0]}" 2>/dev/null | awk '{print $2}' | grep -qx 'L'; then
		pass "Account '${test_users[0]}' is locked"
	else
		fail "Account '${test_users[0]}' lock not confirmed"
	fi

	run_ugm 0 "Lock already-locked user is idempotent" -- user lock "${test_users[0]}"
	run_ugm 0 "Unlock user" -- user unlock "${test_users[0]}"
	if ! passwd -S "${test_users[0]}" 2>/dev/null | awk '{print $2}' | grep -qx 'L'; then
		pass "Account '${test_users[0]}' is unlocked"
	else
		fail "Account '${test_users[0]}' unlock not confirmed"
	fi

	# ── Group lifecycle ───────────────────────────────────────────────────────
	local test_group="ugm_test_grp"
	groupdel "$test_group" 2>/dev/null || true

	run_ugm 0 "Create group" -- group create "$test_group"
	if getent group "$test_group" &>/dev/null; then
		pass "Group '${test_group}' exists after creation"
	else
		fail "Group '${test_group}' missing after creation"
	fi

	run_ugm 0 "Create group again is idempotent" -- group create "$test_group"

	run_ugm 0 "Add user to group" -- group add-member "${test_users[0]}" "$test_group"
	if id -nG "${test_users[0]}" | tr ' ' '\n' | grep -qx "$test_group"; then
		pass "User '${test_users[0]}' is in group '${test_group}'"
	else
		fail "User '${test_users[0]}' not in group '${test_group}'"
	fi

	run_ugm 0 "Add user to group again is idempotent" -- group add-member "${test_users[0]}" "$test_group"
	run_ugm 0 "Remove user from group" -- group remove-member "${test_users[0]}" "$test_group"
	if ! id -nG "${test_users[0]}" | tr ' ' '\n' | grep -qx "$test_group"; then
		pass "User '${test_users[0]}' removed from group '${test_group}'"
	else
		fail "User '${test_users[0]}' still in group '${test_group}'"
	fi

	# ── Password policy ───────────────────────────────────────────────────────
	run_ugm 0 "Apply password aging policy" -- policy set-aging "${test_users[0]}" --min 7 --max 60 --warn 10
	local max_days
	max_days=$(chage -l "${test_users[0]}" 2>/dev/null | grep "Maximum" | awk -F: '{print $2}' | tr -d ' ')
	if [[ "$max_days" -eq 60 ]]; then
		pass "Password max-age set to 60 days"
	else
		fail "Password max-age expected 60, got: ${max_days}"
	fi

	# ── Sudo configuration ────────────────────────────────────────────────────
	run_ugm 0 "Grant sudo to group" -- sudo grant-group "$test_group"
	if [[ -f "/etc/sudoers.d/ugm_${test_group}" ]]; then
		pass "Sudoers file created for '${test_group}'"
	else
		fail "Sudoers file missing for '${test_group}'"
	fi
	if visudo -c -f "/etc/sudoers.d/ugm_${test_group}" &>/dev/null; then
		pass "Sudoers file passes visudo syntax check"
	else
		fail "Sudoers file fails visudo syntax check"
	fi

	run_ugm 0 "Grant sudo again is idempotent" -- sudo grant-group "$test_group"
	run_ugm 0 "Revoke sudo from group" -- sudo revoke-group "$test_group"
	if [[ ! -f "/etc/sudoers.d/ugm_${test_group}" ]]; then
		pass "Sudoers file removed after revoke"
	else
		fail "Sudoers file still present after revoke"
	fi

	# ── User deletion ─────────────────────────────────────────────────────────
	run_ugm 0 "Delete test users" -- user delete "${test_users[@]}" --remove-home
	for u in "${test_users[@]}"; do
		if ! id "$u" &>/dev/null; then
			pass "User '${u}' removed"
		else
			fail "User '${u}' still exists after deletion"
		fi
	done

	run_ugm 0 "Delete group" -- group delete "$test_group"
	if ! getent group "$test_group" &>/dev/null; then
		pass "Group '${test_group}' removed"
	else
		fail "Group '${test_group}' still exists"
	fi
}

# ─────────────────────────────────────────────────────────────────────────────
# RUN ALL TESTS
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}ugm-tool Test Suite${RESET}"
echo "  Script: ${UGM}"
echo "  EUID  : ${EUID}"
echo "  Mode  : $([[ "$RUN_ROOT_TESTS" -eq 1 ]] && echo 'full (root)' || echo 'safe (no root)')"

test_help_and_usage
test_input_validation
test_dry_run_no_root
test_lib_validation_unit
if [[ "$RUN_ROOT_TESTS" -eq 1 ]]; then
	test_root_ops
else
	echo ""
	echo -e "${YELLOW}  Root tests skipped. Run with: sudo bash tests/test_ugm.sh --all${RESET}"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}══════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Test Summary${RESET}"
echo -e "${BOLD}══════════════════════════════════════════${RESET}"
echo -e "  ${GREEN}Passed : ${PASS_COUNT}${RESET}"
echo -e "  ${RED}Failed : ${FAIL_COUNT}${RESET}"
echo -e "  ${YELLOW}Skipped: ${SKIP_COUNT}${RESET}"
echo ""

if [[ "$FAIL_COUNT" -gt 0 ]]; then
	echo -e "${RED}${BOLD}  RESULT: FAILED${RESET}"
	exit 1
else
	echo -e "${GREEN}${BOLD}  RESULT: ALL TESTS PASSED${RESET}"
	exit 0
fi
