#!/usr/bin/env bash
# Manual test script for user-mgmt system

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"
USER_MGMT="${BASE_DIR}/bin/user-mgmt"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

test_count=0
pass_count=0

print_test() {
	echo -e "${YELLOW}[TEST]${NC} $1"
}

print_pass() {
	echo -e "${GREEN}[PASS]${NC} $1"
	((pass_count++))
}

print_fail() {
	echo -e "${RED}[FAIL]${NC} $1"
}

run_test() {
	local name="$1"
	local cmd="$2"
	local expected_exit="${3:-0}"

	((test_count++))
	print_test "$name"

	if eval "$cmd" >/dev/null 2>&1; then
		actual_exit=0
	else
		actual_exit=$?
	fi

	if [[ $actual_exit -eq $expected_exit ]]; then
		print_pass "$name (exit $actual_exit)"
	else
		print_fail "$name (expected $expected_exit, got $actual_exit)"
	fi
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
	echo "This test script should be run as root for full testing"
	echo "Some tests may fail due to permissions"
fi

echo "=== Testing User Management System ==="
echo

# Help and version tests
run_test "Help menu" "$USER_MGMT --help" 0
run_test "Version info" "$USER_MGMT --version" 0
run_test "Invalid command" "$USER_MGMT invalid-command" 2
run_test "Missing command" "$USER_MGMT" 2

# Dry run tests
run_test "Dry run create users" "$USER_MGMT --dry-run create-users" 0
run_test "Dry run create groups" "$USER_MGMT --dry-run create-groups" 0
run_test "Dry run configure sudo" "$USER_MGMT --dry-run configure-sudo" 0

# Actual operations (only if root)
if [[ $EUID -eq 0 ]]; then
	echo -e "\n${YELLOW}Running actual operations (requires cleanup)${NC}"

	# Clean up any previous test runs
	for user in dev1 dev2 dev3; do
		userdel -r "$user" 2>/dev/null || true
	done
	for group in developers admins; do
		groupdel "$group" 2>/dev/null || true
	done
	rm -f /etc/sudoers.d/admins

	# Run actual commands
	run_test "Create groups" "$USER_MGMT create-groups" 0
	run_test "Create users" "$USER_MGMT create-users" 0
	run_test "Assign groups" "$USER_MGMT assign-groups" 0
	run_test "Configure sudo" "$USER_MGMT configure-sudo" 0
	run_test "Set password policy" "$USER_MGMT set-password-policy" 0

	# Test validation
	run_test "Validate configuration" "$USER_MGMT validate" 0

	# Test locking/unlocking
	run_test "Lock user dev2" "$USER_MGMT lock-user dev2" 0
	run_test "Unlock user dev2" "$USER_MGMT unlock-user dev2" 0

	# Test status
	run_test "Show status" "$USER_MGMT status" 0

	# Test with config file
	run_test "Custom config" "$USER_MGMT -c ${BASE_DIR}/etc/user-mgmt.conf status" 0

	echo -e "\n${YELLOW}Cleaning up...${NC}"
	for user in dev1 dev2 dev3; do
		userdel -r "$user" 2>/dev/null || true
	done
	for group in developers admins; do
		groupdel "$group" 2>/dev/null || true
	done
	rm -f /etc/sudoers.d/admins
else
	echo -e "\n${YELLOW}Skipping actual operations (not root)${NC}"
fi

# Summary
echo
echo "=== Test Summary ==="
echo "Total tests: $test_count"
echo "Passed: $pass_count"
echo "Failed: $((test_count - pass_count))"

if [[ $pass_count -eq $test_count ]]; then
	echo -e "${GREEN}All tests passed!${NC}"
	exit 0
else
	echo -e "${RED}Some tests failed${NC}"
	exit 1
fi
