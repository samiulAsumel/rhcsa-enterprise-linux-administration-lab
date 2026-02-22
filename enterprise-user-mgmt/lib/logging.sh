#!/usr/bin/env bash
# Logging utilities for user-mgmt system

# Log levels
declare -A LOG_LEVELS=(
	[DEBUG]=0
	[INFO]=1
	[WARN]=2
	[ERROR]=3
)

# Initialize default log level
LOG_LEVEL="INFO"

# Color codes (if terminal supports)
if [[ -t 2 ]] && [[ "$TERM" != "dumb" ]]; then
	readonly COLOR_RESET='\003[0m'
	readonly COLOR_DEBUG='\003[36m' # Cyan
	readonly COLOR_INFO='\003[32m'  # Green
	readonly COLOR_WARN='\003[33m'  # Yellow
	readonly COLOR_ERROR='\003[31m' # Red
else
	readonly COLOR_RESET=''
	readonly COLOR_DEBUG=''
	readonly COLOR_INFO=''
	readonly COLOR_WARN=''
	readonly COLOR_ERROR=''
fi

# Log a message with timestamp and level
log() {
	local level="$1"
	local message="$2"
	local timestamp
	timestamp=$(date +"%Y-%m-%d %H:%M:%S")

	# Check if we should log this level
	if [[ ${LOG_LEVELS[$level]} -ge ${LOG_LEVELS[$LOG_LEVEL]:-1} ]]; then
		local color_var="COLOR_$level"
		local color="${!color_var}"

		# Console output (stderr)
		echo -e "${color}[$timestamp] [$level] $message${COLOR_RESET}" >&2

		# File output (if writable)
		if [[ -w "$LOG_FILE" ]] || touch "$LOG_FILE" 2>/dev/null; then
			echo "[$timestamp] [$level] $message" >>"$LOG_FILE"
		fi
	fi
}

# Convenience functions
log_debug() { log "DEBUG" "$*"; }
log_info() { log "INFO" "$*"; }
log_warn() { log "WARN" "$*"; }
log_error() { log "ERROR" "$*"; }

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
