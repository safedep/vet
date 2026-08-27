#!/bin/bash
# vet_endpoint_scan.sh — run `vet endpoint scan` for every local user and sync
# the discovered inventory to SafeDep Cloud. One file, Linux and macOS.
#
# MDM tools (Jamf, Mosyle, Kandji, Intune, JumpCloud, ...) run scripts either as
# root or already as the logged-in user. This script handles both:
#
#   - As root (typical MDM): it scans every local human account, each in its own
#     context via `sudo -u`, so HOME, credentials, and per-user config all
#     resolve as that user. vet, run as the user, reports the OS username and
#     uid on each event, so the cloud attributes the inventory to the right user
#     on a shared machine.
#   - As the logged-in user (a "run as current user" MDM payload, or a person
#     running it by hand): it scans just that user, with their full login
#     environment.
#
# Cloud sync turns on when SAFEDEP_API_KEY and SAFEDEP_TENANT_ID are set. The
# keys are streamed into each per-user scan through stdin, never through argv or
# a shared environment, so they do not leak through `ps` on a multi-user box.
# Without the keys the script prints a local inventory per user and exits 0.
#
# Extra arguments are forwarded verbatim to `vet endpoint scan`, for example:
#
#   sudo ./vet_endpoint_scan.sh --silent --kind ai-tool
#
# Environment variables:
#   SAFEDEP_API_KEY    — SafeDep Cloud API key (enables cloud sync; set with the tenant)
#   SAFEDEP_TENANT_ID  — SafeDep Cloud tenant ID
#
# Test-only overrides (do not set in production):
#   VET_MDM_PASSWD_FILE — Linux passwd source override (default: getent passwd)
#   VET_MDM_HOME_PREFIX — required home-directory prefix on Linux (default /home)

set -euo pipefail

# Directories to search for the vet binary when it is not on PATH. root's PATH
# under an MDM is often minimal, so fall back to the common install locations.
VET_INSTALL_DIRS=(/usr/local/bin /opt/homebrew/bin)

# Capture and scrub cloud credentials from our own environment up front, so a
# child process only ever sees them when we deliberately inject them over stdin.
CLOUD_API_KEY="${SAFEDEP_API_KEY:-}"
CLOUD_TENANT_ID="${SAFEDEP_TENANT_ID:-}"
unset SAFEDEP_API_KEY SAFEDEP_TENANT_ID

log() { echo "==> $*"; }
warn() { echo "==> warning: $*" >&2; }
die() { echo "Error: $*" >&2; exit 1; }

running_as_root() { [[ "$EUID" -eq 0 ]]; }

# Detect the host OS once. Sets OS to "linux" or "macos"; dies otherwise.
detect_os() {
  case "$(uname -s)" in
    Linux) OS="linux" ;;
    Darwin) OS="macos" ;;
    *) die "unsupported OS: $(uname -s) (Linux and macOS only)" ;;
  esac
}

# Absolute path to the vet binary, or non-zero if not found.
resolve_vet() {
  local p
  p=$(command -v vet 2>/dev/null) && { echo "$p"; return 0; }
  for p in ${VET_INSTALL_DIRS[@]+"${VET_INSTALL_DIRS[@]}"}; do
    [[ -x "$p/vet" ]] && { echo "$p/vet"; return 0; }
  done
  return 1
}

# Emit passwd-format lines for the local and directory user databases. Uses
# `getent passwd`, which reads NSS, so on an MDM-managed host it returns
# directory users (LDAP/SSSD/AD) as well as local accounts, matching what the
# macOS dscl path sees. Falls back to /etc/passwd when getent is absent. Tests
# point VET_MDM_PASSWD_FILE at a fixture to run this seam without root.
passwd_source() {
  if [[ -n "${VET_MDM_PASSWD_FILE:-}" ]]; then
    cat "$VET_MDM_PASSWD_FILE"
  elif command -v getent >/dev/null 2>&1; then
    getent passwd
  else
    cat /etc/passwd
  fi
}

# Emit "user<TAB>uid<TAB>home" for every local or directory human account on
# Linux. Keeps accounts with UID >= UID_MIN (default 1000), a real home under
# the required prefix, and a login shell. Accounts whose home is absent on this
# machine (directory users who never logged in) and nologin/false service
# accounts are skipped. Split out from each_target_user so it is testable
# without root.
enumerate_linux_users() {
  local home_prefix="${VET_MDM_HOME_PREFIX:-/home}"
  local uid_min
  uid_min=$(awk '/^UID_MIN/{print $2}' /etc/login.defs 2>/dev/null || true)
  [[ "$uid_min" =~ ^[0-9]+$ ]] || uid_min=1000
  local user uid home shell
  while IFS=: read -r user _ uid _ _ home shell; do
    [[ "$uid" =~ ^[0-9]+$ ]] || continue
    [[ "$uid" -ge "$uid_min" ]] || continue
    [[ -n "$home" && -d "$home" ]] || continue
    case "$home" in "$home_prefix"/*) ;; *) continue ;; esac
    case "$shell" in */nologin | */false) continue ;; esac
    printf '%s\t%s\t%s\n' "$user" "$uid" "$home"
  done < <(passwd_source)
}

# Emit "user<TAB>uid<TAB>home" for every local human account on macOS via
# Directory Services. Filters to UID >= 500 with a real home under /Users.
enumerate_macos_users() {
  local user uid home
  while IFS= read -r user; do
    uid=$(dscl . -read "/Users/$user" UniqueID 2>/dev/null | awk '{print $2}')
    [[ "$uid" =~ ^[0-9]+$ ]] || continue
    [[ "$uid" -ge 500 ]] || continue
    home=$(dscl . -read "/Users/$user" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
    [[ -n "$home" && -d "$home" ]] || continue
    case "$home" in /Users/*) ;; *) continue ;; esac
    printf '%s\t%s\t%s\n' "$user" "$uid" "$home"
  done < <(dscl . -list /Users)
}

# Emit "user<TAB>uid<TAB>home" per target user: every local human account when
# run as root, or just the current user otherwise.
each_target_user() {
  if ! running_as_root; then
    printf '%s\t%s\t%s\n' "$(id -un)" "$(id -u)" "$HOME"
    return
  fi
  case "$OS" in
    linux) enumerate_linux_users ;;
    macos) enumerate_macos_users ;;
  esac
}

# Run a command as the given user with HOME forced to their home. Elevates with
# sudo only when we are root; when already running as the user it runs directly.
# XDG_* are dropped so vet resolves per-user state under the right home even when
# sudo preserves the caller's environment.
run_as_user() {
  local user="$1" home="$2"; shift 2
  if running_as_root; then
    sudo -u "$user" -H -- \
      env -u XDG_CONFIG_HOME -u XDG_CACHE_HOME -u XDG_DATA_HOME "HOME=$home" "$@"
  else
    "$@"
  fi
}

# Scan one user's endpoint. When cloud credentials are present they are streamed
# over stdin into the child and re-exported there, so they never appear in argv
# (and so never in `ps`) on a shared machine.
scan_user() {
  local user="$1" home="$2"
  log "Scanning endpoint for $user"

  if [[ -n "$CLOUD_API_KEY" && -n "$CLOUD_TENANT_ID" ]]; then
    # The single-quoted body runs in the target user's shell; the credentials
    # arrive on its stdin, not in this script's argv.
    # shellcheck disable=SC2016
    printf '%s\0%s\0' "$CLOUD_API_KEY" "$CLOUD_TENANT_ID" |
      run_as_user "$user" "$home" /bin/bash -c '
        IFS= read -r -d "" SAFEDEP_API_KEY || exit 1
        IFS= read -r -d "" SAFEDEP_TENANT_ID || exit 1
        export SAFEDEP_API_KEY SAFEDEP_TENANT_ID
        exec "$@"
      ' _ "$VET_BIN" endpoint scan ${SCAN_ARGS[@]+"${SCAN_ARGS[@]}"}
  else
    run_as_user "$user" "$home" "$VET_BIN" endpoint scan ${SCAN_ARGS[@]+"${SCAN_ARGS[@]}"}
  fi
}

main() {
  SCAN_ARGS=("$@")

  # A half-set credential pair is a misconfiguration, not a local-only run.
  if { [[ -n "$CLOUD_API_KEY" ]] && [[ -z "$CLOUD_TENANT_ID" ]]; } ||
     { [[ -z "$CLOUD_API_KEY" ]] && [[ -n "$CLOUD_TENANT_ID" ]]; }; then
    die "SAFEDEP_API_KEY and SAFEDEP_TENANT_ID must be set together"
  fi

  detect_os

  VET_BIN=$(resolve_vet) ||
    die "vet binary not found on PATH or in ${VET_INSTALL_DIRS[*]}"
  local ver
  ver=$("$VET_BIN" version 2>/dev/null | head -n1) || ver=""
  log "Using vet: $VET_BIN${ver:+ ($ver)}"

  if [[ -n "$CLOUD_API_KEY" ]]; then
    log "Cloud sync enabled"
  else
    log "SAFEDEP_API_KEY/SAFEDEP_TENANT_ID not set; running local-only (no cloud sync)"
  fi

  if running_as_root; then
    log "Running as root; scanning every local user"
  else
    log "Running as $(id -un); scanning current user only"
  fi

  local user home total=0 failed=0
  while IFS=$'\t' read -r user _ home; do
    [[ -n "$user" ]] || continue
    total=$((total + 1))
    scan_user "$user" "$home" || { warn "scan failed for $user"; failed=$((failed + 1)); }
  done < <(each_target_user)

  # Scrub credentials from our environment before returning.
  unset CLOUD_API_KEY CLOUD_TENANT_ID

  if [[ "$total" -eq 0 ]]; then
    warn "no target users found"
  else
    log "Scanned $((total - failed))/$total user(s)"
  fi
}

# Run main only on direct execution, so tests can source this file and exercise
# individual functions.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
