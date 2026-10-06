#!/usr/bin/env bash
# scan.sh runs vet scan with the action inputs and sets the action outputs.
# vet owns the gate, the comment and the state. The script only builds the
# command line and maps the report to the outputs.
#
# Environment: ACTION_FAIL_ON, ACTION_POLICY, ACTION_COMMENT,
# ACTION_COMMENT_PROXY, ACTION_SARIF, ACTION_ARGS, GH_TOKEN and the
# variables of GitHub Actions.
set -euo pipefail

fail() {
  echo "::error::$*"
  exit 1
}

command -v vet >/dev/null || fail "vet is not on the PATH of the runner"
command -v jq >/dev/null || fail "The action needs jq on the runner"
# The jq of a Windows runner writes CRLF line ends, and bash keeps the CR.
if [ "${RUNNER_OS:-}" = Windows ]; then
  jq() { command jq -b "$@"; }
fi

tmp=$(mktemp -d "${RUNNER_TEMP:?}/vet-scan.XXXXXX")
report=$tmp/report.json
summary=$tmp/summary.md
sarif=""
args=(scan --report "markdown=$summary" -o json)

case ${ACTION_COMMENT:=auto} in
  auto) create=changes ;;
  findings) create=findings ;;
  never) create="" ;;
  *) fail "The comment input is not valid: '$ACTION_COMMENT'. Use auto, findings or never" ;;
esac
case ${ACTION_COMMENT_PROXY:=true} in
  true | false) ;;
  *) fail "The comment-proxy input is not valid: '$ACTION_COMMENT_PROXY'. Use true or false" ;;
esac
case ${ACTION_SARIF:=false} in
  true)
    sarif=$tmp/vet.sarif
    args+=(--report "sarif=$sarif")
    ;;
  false) ;;
  *) fail "The sarif input is not valid: '$ACTION_SARIF'. Use true or false" ;;
esac
case ${ACTION_FAIL_ON:=attacks} in
  none) ;;
  *) args+=(--fail-on "$ACTION_FAIL_ON") ;;
esac

base=""
if [[ ${GITHUB_EVENT_NAME:-} == pull_request* ]]; then
  base=$(jq -r '.pull_request.base.sha // empty' "${GITHUB_EVENT_PATH:?}")
fi

if [ -n "$base" ]; then
  if ! git cat-file -e "$base^{commit}" 2>/dev/null; then
    # The docs set persist-credentials: false, so the fetch sends the token
    # for this one command, to the server of the run only. A checkout that
    # keeps its token has a header already.
    if git config --get-regexp '^http\..*extraheader$' >/dev/null; then
      git fetch --no-tags --depth=1 origin "$base"
    else
      auth=$(printf 'x-access-token:%s' "${GH_TOKEN:?}" | base64 | tr -d '\n')
      echo "::add-mask::$auth"
      GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0="http.${GITHUB_SERVER_URL:-https://github.com}/.extraheader" \
        GIT_CONFIG_VALUE_0="AUTHORIZATION: basic $auth" git fetch --no-tags --depth=1 origin "$base"
    fi
  fi
  args+=(--base-ref "$base")
  if [ -n "$create" ]; then
    args+=(--report pr-comment)
    export VET_PLUGINS_PR_COMMENT_OPTIONS_CREATE=$create
    export VET_PLUGINS_PR_COMMENT_OPTIONS_PROXY=$ACTION_COMMENT_PROXY
  fi
fi

# In a pull request, vet reads the policy at the base commit. vet prints a
# notice when the base has no policy.
policy=${ACTION_POLICY:-}
if [ -n "$policy" ]; then
  if [ -n "$base" ] || [ -e "$policy" ]; then
    args+=(--policy "$policy")
  else
    echo "vet applies no policy file, because the checkout has no $policy"
  fi
fi

# The args input splits on white space. The script never evaluates it.
extra=()
if [ -n "${ACTION_ARGS:-}" ]; then
  read -r -d '' -a extra <<<"$ACTION_ARGS" || true
fi

code=0
vet "${args[@]}" ${extra[@]+"${extra[@]}"} >"$report" || code=$?

# A step summary holds at most 1 MiB.
if [ -s "$summary" ] && [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  limit=$((1024 * 1024 - 1024))
  if [ $(($(wc -c <"$summary"))) -gt "$limit" ]; then
    head -c "$limit" "$summary" >>"$GITHUB_STEP_SUMMARY"
    printf '\n\n%s\n' "The report is too long for the step summary. The report output of the action has each finding." >>"$GITHUB_STEP_SUMMARY"
  else
    cat "$summary" >>"$GITHUB_STEP_SUMMARY"
  fi
fi

# When vet stops before it writes a report, the outputs stay empty and the
# exit code of vet fails the step.
{
  jq -r --arg report "$report" '"gate=\(.trailer.gate.outcome // "NONE" | ascii_downcase)",
    "findings=\(.trailer.summary.findings // 0)", "report=\($report)"' "$report" 2>/dev/null || true
  if [ -n "$sarif" ] && [ -s "$sarif" ]; then
    echo "sarif=$sarif"
  fi
} >>"${GITHUB_OUTPUT:?}"

exit "$code"
