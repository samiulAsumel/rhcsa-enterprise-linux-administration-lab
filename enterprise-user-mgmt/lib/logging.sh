#!/usr/bin/env bash
# Enterprise Logging utilities for user-mgmt system
# Compliance: Syslog standards, Audit requirements, Security logging

# Log levels following syslog convention
declare -grA LOG_LEVELS=(
	[DEBUG]=0
	[INFO]=1
	[WARN]=2
	[ERROR]=3
	[CRITICAL]=4
)

# Initialize default log level
LOG_LEVEL="INFO"

# Enterprise color codes (if terminal supports)
if [[ -t 2 ]] && [[ "$TERM" != "dumb" ]]; then
	readonly COLOR_RESET='\033[0m'
	readonly COLOR_DEBUG='\033[36m' # Cyan
	readonly COLOR_INFO='\033[32m'  # Green
	readonly COLOR_WARN='\033[33m'  # Yellow
	readonly COLOR_ERROR='\033[31m' # Red
	readonly COLOR_CRITICAL='\033[35m' # Magenta
else
	readonly COLOR_RESET=''
	readonly COLOR_DEBUG=''
	readonly COLOR_INFO=''
	readonly COLOR_WARN=''
	readonly COLOR_ERROR=''
	readonly COLOR_CRITICAL=''
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
