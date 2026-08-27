#!/bin/bash
# vet_endpoint_scan_test.sh — behavior tests for vet_endpoint_scan.sh.
#
# These run as an ordinary (non-root) user, so they exercise the current-user
# scan path end to end with a mock vet, plus the OS guard, binary resolution,
# credential handling, and the Linux user enumeration filter. The root fan-out
# needs a real multi-user host and is out of scope here.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
SCRIPT="${SCRIPT_DIR}/vet_endpoint_scan.sh"
HOST="$(uname -s)"

fail() { echo "FAIL: $*" >&2; exit 1; }
log() { echo "==> $*"; }

assert_equals() {
  [[ "$2" == "$1" ]] || fail "$3: expected '$1', got '$2'"
}

assert_contains() {
  grep -qF -- "$2" <<<"$1" || fail "$3: '$2' not found in: $1"
}

refute_contains() {
  grep -qF -- "$2" <<<"$1" && fail "$3: '$2' unexpectedly found in: $1"
  return 0
}

# Create a mock vet at $1/vet. It answers `version`, and for any other call
# records its argv and the SAFEDEP_* it saw in the environment.
make_mock_vet() {
  local dir="$1" args_cap="$2" env_cap="$3"
  mkdir -p "$dir"
  cat > "${dir}/vet" <<EOF
#!/bin/bash
if [[ "\${1:-}" == "version" ]]; then echo "vet mock v0.0.0"; exit 0; fi
printf 'argv:%s\n' "\$*" >> "${args_cap}"
printf 'api=%s tenant=%s\n' "\${SAFEDEP_API_KEY:-}" "\${SAFEDEP_TENANT_ID:-}" >> "${env_cap}"
exit 0
EOF
  chmod 0755 "${dir}/vet"
}

# ---------------------------------------------------------------------------

test_os_guard() {
  local tmp; tmp=$(mktemp -d)
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" RETURN
  mkdir -p "${tmp}/bin"
  cat > "${tmp}/bin/uname" <<'EOF'
#!/bin/bash
[[ "${1:-}" == "-s" ]] && { echo "Plan9"; exit 0; }
echo "Plan9"
EOF
  chmod 0755 "${tmp}/bin/uname"

  local out rc=0
  out=$(PATH="${tmp}/bin:$PATH" bash "$SCRIPT" 2>&1) || rc=$?
  [[ "$rc" -ne 0 ]] || fail "os_guard: expected non-zero exit on unsupported OS"
  assert_contains "$out" "unsupported OS" "os_guard message"
}

test_resolve_vet_found_on_path() {
  local tmp; tmp=$(mktemp -d)
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" RETURN
  make_mock_vet "${tmp}/bin" "${tmp}/args" "${tmp}/env"

  local got
  got=$(PATH="${tmp}/bin:$PATH" bash -c 'source "$1"; resolve_vet' _ "$SCRIPT")
  assert_equals "${tmp}/bin/vet" "$got" "resolve_vet on PATH"
}

test_resolve_vet_missing() {
  local tmp; tmp=$(mktemp -d)
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" RETURN
  mkdir -p "${tmp}/emptybin"
  local rc=0
  # A PATH with no vet and no install dirs => not found. Use a real empty dir
  # (not PATH="") so `command -v` does not fall back to searching the CWD. PATH
  # is set inside the child, after bash itself has been located.
  bash -c 'PATH="$2"; source "$1"; VET_INSTALL_DIRS=(); resolve_vet' \
    _ "$SCRIPT" "${tmp}/emptybin" >/dev/null 2>&1 || rc=$?
  [[ "$rc" -ne 0 ]] || fail "resolve_vet: expected non-zero when vet is absent"
}

test_each_target_user_non_root() {
  local got want
  got=$(bash -c 'source "$1"; OS=linux; each_target_user' _ "$SCRIPT")
  want=$(printf '%s\t%s\t%s' "$(id -un)" "$(id -u)" "$HOME")
  assert_equals "$want" "$got" "each_target_user (non-root) => current user"
}

test_credentials_must_be_paired() {
  local out rc=0
  out=$(SAFEDEP_API_KEY=only-key bash "$SCRIPT" 2>&1) || rc=$?
  [[ "$rc" -ne 0 ]] || fail "cred pairing: expected non-zero when only one key is set"
  assert_contains "$out" "must be set together" "cred pairing message"
}

test_scan_current_user_with_cloud() {
  local tmp; tmp=$(mktemp -d)
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" RETURN
  make_mock_vet "${tmp}/bin" "${tmp}/args" "${tmp}/env"

  PATH="${tmp}/bin:$PATH" SAFEDEP_API_KEY="key-123" SAFEDEP_TENANT_ID="tenant-abc" \
    bash "$SCRIPT" --silent --kind ai-tool >/dev/null 2>&1

  local args env
  args=$(cat "${tmp}/args"); env=$(cat "${tmp}/env")
  assert_equals "argv:endpoint scan --silent --kind ai-tool" "$args" "scan argv"
  assert_contains "$env" "api=key-123 tenant=tenant-abc" "cloud creds reached vet via env"
  # Credentials must never ride in argv (ps-visible on a shared host).
  refute_contains "$args" "key-123" "api key absent from argv"
  refute_contains "$args" "tenant-abc" "tenant absent from argv"
}

test_scan_current_user_local_only() {
  local tmp; tmp=$(mktemp -d)
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" RETURN
  make_mock_vet "${tmp}/bin" "${tmp}/args" "${tmp}/env"

  # Scrub any inherited creds so this is a genuine local-only run.
  local out
  out=$(PATH="${tmp}/bin:$PATH" env -u SAFEDEP_API_KEY -u SAFEDEP_TENANT_ID \
    bash "$SCRIPT" --silent 2>&1)

  assert_equals "argv:endpoint scan --silent" "$(cat "${tmp}/args")" "local-only argv"
  assert_equals "api= tenant=" "$(cat "${tmp}/env")" "no creds in vet env"
  assert_contains "$out" "local-only" "local-only notice printed"
}

test_enumerate_linux_users() {
  if [[ "$HOST" != "Linux" ]]; then
    log "SKIP enumerate_linux_users (Linux only; host is $HOST)"
    return 0
  fi
  local tmp; tmp=$(mktemp -d)
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" RETURN
  mkdir -p "${tmp}/home/alice" "${tmp}/home/bob" "${tmp}/home/sys" "${tmp}/home/svc"
  # ghost has no home dir; wrong is outside the home prefix; svc is a nologin
  # service account. VET_MDM_PASSWD_FILE stands in for the `getent passwd`
  # source so the seam runs as a normal user.
  cat > "${tmp}/passwd" <<EOF
root:x:0:0::/root:/bin/bash
sys:x:1:1::${tmp}/home/sys:/bin/sh
alice:x:5000:5000::${tmp}/home/alice:/bin/bash
bob:x:5001:5001::${tmp}/home/bob:/bin/bash
ghost:x:5002:5002::${tmp}/home/ghost:/bin/bash
wrong:x:5003:5003::/opt/wrong:/bin/bash
svc:x:5004:5004::${tmp}/home/svc:/usr/sbin/nologin
EOF

  local got want
  got=$(VET_MDM_PASSWD_FILE="${tmp}/passwd" VET_MDM_HOME_PREFIX="${tmp}/home" \
    bash -c 'source "$1"; enumerate_linux_users' _ "$SCRIPT")
  want=$(printf 'alice\t5000\t%s\nbob\t5001\t%s' "${tmp}/home/alice" "${tmp}/home/bob")
  assert_equals "$want" "$got" "enumerate_linux_users filters system/missing/off-prefix/nologin"
}

# ---------------------------------------------------------------------------

for t in \
  test_os_guard \
  test_resolve_vet_found_on_path \
  test_resolve_vet_missing \
  test_each_target_user_non_root \
  test_credentials_must_be_paired \
  test_scan_current_user_with_cloud \
  test_scan_current_user_local_only \
  test_enumerate_linux_users; do
  "$t"
  log "ok: $t"
done

echo "PASS"
