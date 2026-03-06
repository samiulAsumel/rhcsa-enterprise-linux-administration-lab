#!/usr/bin/env bash
# Enterprise Logging utilities for user-mgmt system
# Compliance: Syslog standards, Audit requirements, Security logging

# Log levels following syslog convention
if ! declare -p LOG_LEVELS &>/dev/null; then
    declare -gA LOG_LEVELS=(
        [DEBUG]=0
        [INFO]=1
        [WARN]=2
        [ERROR]=3
        [CRITICAL]=4
    )
fi

# Initialize default log level
LOG_LEVEL="INFO"

# Enterprise color codes (if terminal supports)
# shellcheck disable=SC2034  # Variables are used dynamically via indirection
if [[ -t 2 ]] && [[ "$TERM" != "dumb" ]]; then
	[[ -z "${COLOR_RESET:-}" ]] && declare -g COLOR_RESET='\033[0m'
	[[ -z "${COLOR_DEBUG:-}" ]] && declare -g COLOR_DEBUG='\033[36m' # Cyan
	[[ -z "${COLOR_INFO:-}" ]] && declare -g COLOR_INFO='\033[32m'  # Green
	[[ -z "${COLOR_WARN:-}" ]] && declare -g COLOR_WARN='\033[33m'  # Yellow
	[[ -z "${COLOR_ERROR:-}" ]] && declare -g COLOR_ERROR='\033[31m' # Red
	[[ -z "${COLOR_CRITICAL:-}" ]] && declare -g COLOR_CRITICAL='\033[35m' # Magenta
else
	[[ -z "${COLOR_RESET:-}" ]] && declare -g COLOR_RESET=''
	[[ -z "${COLOR_DEBUG:-}" ]] && declare -g COLOR_DEBUG=''
	[[ -z "${COLOR_INFO:-}" ]] && declare -g COLOR_INFO=''
	[[ -z "${COLOR_WARN:-}" ]] && declare -g COLOR_WARN=''
	[[ -z "${COLOR_ERROR:-}" ]] && declare -g COLOR_ERROR=''
	[[ -z "${COLOR_CRITICAL:-}" ]] && declare -g COLOR_CRITICAL=''
fi

# Enterprise log function with audit capabilities
log() {
	local level="$1"
	local message="$2"
	local timestamp
	timestamp=$(date +"%Y-%m-%d %H:%M:%S")
	local hostname
	hostname=$(hostname)
	local pid=$$

	# Check if we should log this level
	if [[ ${LOG_LEVELS[$level]} -ge ${LOG_LEVELS[$LOG_LEVEL]:-1} ]]; then
		local color_var="COLOR_$level"
		local color="${!color_var}"

		# Console output (stderr) with structured format
		echo -e "${color}[$timestamp] [$hostname:$pid] [$level] $message${COLOR_RESET}" >&2

		# File output (if writable)
		if [[ -w "$LOG_FILE" ]] || touch "$LOG_FILE" 2>/dev/null; then
			echo "[$timestamp] [$hostname:$pid] [$level] $message" >>"$LOG_FILE"
		fi
		
		# Critical messages also go to audit log
		if [[ "$level" == "CRITICAL" ]] && [[ -n "${CONFIG[audit_log]:-}" ]]; then
			if [[ -w "${CONFIG[audit_log]}" ]] || touch "${CONFIG[audit_log]}" 2>/dev/null; then
				echo "[$timestamp] [$hostname:$pid] [AUDIT] [CRITICAL] $message" >>"${CONFIG[audit_log]}"
			fi
		fi
	fi
}

# Convenience functions with enterprise naming
log_debug() { log "DEBUG" "$*"; }
log_info() { log "INFO" "$*"; }
log_warn() { log "WARN" "$*"; }
log_error() { log "ERROR" "$*"; }
log_critical() { log "CRITICAL" "$*"; }

# Audit logging for security events
log_audit() {
	local event="$1"
	local user="$2"
	local action="$3"
	local timestamp
	timestamp=$(date +"%Y-%m-%d %H:%M:%S")
	local hostname
	hostname=$(hostname)
	local pid=$$
	
	if [[ -n "${CONFIG[audit_log]:-}" ]]; then
		if [[ -w "${CONFIG[audit_log]}" ]] || touch "${CONFIG[audit_log]}" 2>/dev/null; then
			echo "[$timestamp] [$hostname:$pid] [AUDIT] [EVENT:$event] [USER:$user] [ACTION:$action]" >>"${CONFIG[audit_log]}"
		fi
	fi
	
	# Also log to regular log
	log_info "AUDIT: $event - User: $user - Action: $action"
}

# Convenience logging functions
log_debug() { log "DEBUG" "$1"; }
log_info() { log "INFO" "$1"; }
log_warn() { log "WARN" "$1"; }
log_warning() { log "WARN" "$1"; }
log_error() { log "ERROR" "$1"; }
log_critical() { log "CRITICAL" "$1"; }

# Execute command with logging
run_cmd() {
	local cmd="$1"
	local desc="${2:-$cmd}"

	log_debug "Executing; $cmd"

	if $DRY_RUN; then
		log_info "[DRY_RUN] Would execute: $cmd"
		return 0
	fi

	if output=$(eval "$cmd" 2>&1); then
		log_debug "Command succeeded: $desc"
		[[ -n "$output" ]] && log_debug "Output: $output"
		return 0 
	else
		local exit_code=$?
		log_error "Command failed ($exit_code): $desc"
		log_error "Error output:  $output"
		return $exit_code
	fi
}

# Check if running as root
require_root() {
	if [[ $EUID -ne 0 ]]; then
		log_error "This command must be run as root (use sudo)"
		exit 3 
	fi
}
