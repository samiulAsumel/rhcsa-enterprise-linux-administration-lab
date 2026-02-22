# Test Scenarios for User Management System

## Prerequisites

- Root or sudo access
- Bash 4.0+
- Linux system with standard user management tools

## Test Scenarios

### Scenario 1: Initial Setup

**Goal:** Verify complete setup from scratch

Steps:

1. `./bin/user-mgmt create-groups`
2. `./bin/user-mgmt create-users`
3. `./bin/user-mgmt assign-groups`
4. `./bin/user-mgmt configure-sudo`
5. `./bin/user-mgmt set-password-policy`

Expected Results:

- Groups developers and admins exist
- Users dev1, dev2, dev3 exist with home directories
- Correct group memberships
- Password policies applied
- Sudo access for admins

### Scenario 2: Idempotency

**Goal:** Verify commands can be run multiple times safely

Steps:

1. Run all setup commands once
2. Run all setup commands again

Expected Results:

- No errors from duplicate operations
- Existing users/groups not modified negatively
- Idempotent behavior

### Scenario 3: Account Locking

**Goal:** Test security features

Steps:

1. `./bin/user-mgmt lock-user dev2`
2. Attempt to login as dev2
3. `./bin/user-mgmt unlock-user dev2`
4. Attempt to login as dev2

Expected Results:

- Locked user cannot login
- After unlock, user can login
- Password must be changed on first login after unlock

### Scenario 4: Sudo Access Validation

**Goal:** Verify sudo restrictions

Steps:

1. Login as dev1 (developer only)
2. Try `sudo whoami`
3. Login as dev3 (admin)
4. Try `sudo whoami`

Expected Results:

- dev1 cannot use sudo
- dev3 can use sudo
- Sudo commands are logged

### Scenario 5: Password Policy Enforcement

**Goal:** Test password aging

Steps:

1. Check password expiration for dev1: `chage -l dev1`
2. Try to change password before min days
3. Wait for password to expire (or manually set expiration)

Expected Results:

- Password cannot be changed before min days
- Warning appears before expiration
- Account locks after inactivity period

### Scenario 6: Error Handling

**Goal:** Test error cases

Commands to test:

1. `./bin/user-mgmt lock-user nonexistent`
2. `./bin/user-mgmt --invalid-flag`
3. `./bin/user-mgmt` (no command)
4. `./bin/user-mgmt status` (without root)

Expected Results:

- Appropriate error messages
- Correct exit codes
- No system changes on error

### Scenario 7: Dry Run Mode

**Goal:** Verify dry run doesn't make changes

Steps:

1. `./bin/user-mgmt --dry-run create-users`
2. Check if users were actually created

Expected Results:

- Commands show what would happen
- No actual system changes
- Exit code indicates success

### Scenario 8: Configuration Override

**Goal:** Test custom configuration

Steps:

1. Edit `etc/user-mgmt.conf` to change password_max_days to 60
2. `./bin/user-mgmt -c etc/user-mgmt.conf set-password-policy`
3. Check new policy: `chage -l dev1`

Expected Results:

- Password policy reflects custom values
- Existing settings are updated

### Scenario 9: Validation Check

**Goal:** Verify system meets requirements

Steps:

1. Break something (remove user, change group)
2. `./bin/user-mgmt validate`

Expected Results:

- Validation detects missing components
- Clear error messages
- Non-zero exit code

### Scenario 10: Concurrent Operations

**Goal:** Test script stability under load

Steps:

1. Run multiple operations in background:
