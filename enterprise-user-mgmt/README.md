# Enterprise User and Group Management System

A production-ready Bash CLI tool for managing Linux user accounts, groups, and security policies in enterprise environments.

## Problem Statement

In enterprise Linux environments, system administrators frequently need to:

- Onboard new developers with consistent configurations
- Manage group memberships and permissions
- Enforce password security policies
- Configure sudo access based on roles
- Handle account lockouts and unlocks
- Audit and validate user configurations

Manual management is error-prone, inconsistent, and doesn't scale. This tool provides a standardized, repeatable approach to user management that ensures security compliance and operational consistency.

## Features

- ✅ Create multiple users with consistent settings
- ✅ Manage groups and group memberships
- ✅ Configure role-based sudo access
- ✅ Enforce password aging policies
- ✅ Lock/unlock user accounts
- ✅ Validate configuration against requirements
- ✅ Dry-run mode for safe testing
- ✅ Comprehensive logging
- ✅ Idempotent operations
- ✅ Production-grade error handling

## Design Decisions

### Bash as the Implementation Language

- **Why**: User management commands (`useradd`, `groupmod`, etc.) are shell-native
- **Portability**: Available on all Linux systems without additional dependencies
- **Transparency**: Easy to audit and modify for security-conscious environments

### Modular Architecture

- **Separation of concerns**: Each library handles specific functionality
- **Testability**: Functions can be tested in isolation
- **Maintainability**: Clear code organization

### Security First

- **Root required**: All operations require proper privileges
- **Sudoers validation**: Uses `visudo` to prevent syntax errors
- **Input validation**: Strict checking of usernames, groups, and parameters
- **Idempotent operations**: Safe to run multiple times

### Error Handling Philosophy

- **Immediate failure** with `set -euo pipefail`
- **Graceful degradation**: Clear error messages without crashing
- **Exit codes**: Meaningful codes for scripting integration

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/enterprise-user-mgmt.git
cd enterprise-user-mgmt

# Make scripts executable
chmod +x bin/user-mgmt
chmod +x tests/test-user-mgmt.sh

# Optional: Install system-wide
sudo ln -s $(pwd)/bin/user-mgmt /usr/local/bin/
```
