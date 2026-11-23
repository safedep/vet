#!/usr/bin/env bash
# scan.sh runs vet scan with the action inputs and sets the action outputs.
# vet owns the gate, the comment and the state. The script only builds the
# command line and maps the report to the outputs.
#
# Environment: ACTION_FAIL_ON, ACTION_POLICY, ACTION_COMMENT,
# ACTION_COMMENT_PROXY, ACTION_SARIF, ACTION_ARGS, ACTION_CACHE_DIR,
# ACTION_REPORT_ARTIFACT, ACTION_TENANT_ID, ACTION_API_KEY, GH_TOKEN and the
# variables of GitHub Actions.
set -euo pipefail

# GitHub hides the key in each later line of the log.
if [ -n "${ACTION_API_KEY:-}" ]; then
  echo "::add-mask::$ACTION_API_KEY"
fi

# The action restores this directory before the scan and saves it after.
# An empty value keeps the cache directory of the user.
if [ -n "${ACTION_CACHE_DIR:-}" ]; then
  export VET_CACHE_DIR=$ACTION_CACHE_DIR
fi

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
if [ -n "${ACTION_REPORT_ARTIFACT:-}" ] && ! [[ $ACTION_REPORT_ARTIFACT =~ ^[A-Za-z0-9._-]+$ ]]; then
  fail "The report-artifact input is not valid: '$ACTION_REPORT_ARTIFACT'. Use only A-Z, a-z, 0-9, ., _ and -"
fi
case ${ACTION_FAIL_ON:=attacks} in
  none) ;;
  *) args+=(--fail-on "$ACTION_FAIL_ON") ;;
esac

base=""
if [[ ${GITHUB_EVENT_NAME:-} == pull_request* ]]; then
  base=$(jq -r '.pull_request.base.sha // empty' "${GITHUB_EVENT_PATH:?}")
  head=$(jq -r '.pull_request.head.sha // empty' "$GITHUB_EVENT_PATH")
  # The checkout of a pull_request event merges the head into the newest
  # base. The event keeps an older base when the base branch moved after
  # the last push. A diff against that base then counts the new commits of
  # the base branch as part of the change. The first parent of the merge is
  # the base that the merge holds. A shallow checkout keeps the parent ids
  # in the commit, so cat-file reads them with no fetch.
  read -r first second extra <<<"$(git cat-file -p HEAD 2>/dev/null | sed -n 's/^parent //p' | tr '\n' ' ')" || true
  if [ -n "$head" ] && [ "${second:-}" = "$head" ] && [ -z "${extra:-}" ]; then
    base=$first
  fi
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
    # The next step of the action uploads the report as this artifact.
    if [ -n "${ACTION_REPORT_ARTIFACT:-}" ]; then
      export VET_PLUGINS_PR_COMMENT_OPTIONS_ARTIFACT=$ACTION_REPORT_ARTIFACT
    fi
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

if [ -n "${ACTION_PACKAGE_COOLDOWN:-}" ]; then
  [[ $ACTION_PACKAGE_COOLDOWN =~ ^[1-9][0-9]{0,4}$ ]] ||
    fail "The package-cooldown input is not a count of days: '$ACTION_PACKAGE_COOLDOWN'"
  args+=(--cooldown-days "$ACTION_PACKAGE_COOLDOWN")
fi

# In a pull request, vet reads the config at the base commit, as it reads
# the policy. A change cannot turn off a control for its own scan.
config=${ACTION_CONFIG:-}
global=()
if [ -n "$config" ]; then
  case /$config/ in
    //* | */../* | */./* | *//*) fail "The config input is not a plain path in the repository: '$config'. Write it as .github/vet/config.yml" ;;
  esac
  if [ -n "$base" ]; then
    if [ -n "$(git ls-tree --name-only "$base" -- "$config")" ]; then
      git show "$base:$config" >"$tmp/config.yml" || fail "vet cannot read $config at the base commit ${base:0:7}"
      global=(--config "$tmp/config.yml")
      echo "vet reads the config $config at the base commit ${base:0:7}"
    elif [ -e "$config" ]; then
      echo "::warning::The base commit has no $config, so vet reads no config file. The config of this change applies after it merges."
    else
      fail "The config input names a file that does not exist: '$config'"
    fi
  elif [ -e "$config" ]; then
    global=(--config "$config")
  else
    fail "The config input names a file that does not exist: '$config'"
  fi
fi

# The args input splits on white space. The script never evaluates it.
extra=()
if [ -n "${ACTION_ARGS:-}" ]; then
  read -r -d '' -a extra <<<"$ACTION_ARGS" || true
fi

# The SafeDep Cloud inputs set the credentials of vet as the pmg action
# does. The script sets them for the vet process only, not in GITHUB_ENV, so
# later steps do not get them. With neither input, vet reads the
# environment of the job as before.
cloud=keep
tenant=${ACTION_TENANT_ID:-}
if [ -n "${ACTION_API_KEY:-}" ]; then
  [ -n "$tenant" ] || fail "The api-key input needs the tenant-id input. Set tenant-id to the domain of your SafeDep Cloud tenant, such as acme.safedep.io"
  cloud=key
elif [ -n "$tenant" ]; then
  cloud=workload
  if [ -z "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ]; then
    head_repo=""
    if [[ ${GITHUB_EVENT_NAME:-} == pull_request* ]]; then
      head_repo=$(jq -r '.pull_request.head.repo.full_name // empty' "${GITHUB_EVENT_PATH:?}")
    fi
    if [ -n "$head_repo" ] && [ "$head_repo" != "${GITHUB_REPOSITORY:-}" ]; then
      # GitHub gives no ID token to the job of a pull request from a fork,
      # and the fork must not get the API key of the repository.
      echo "::warning::GitHub gives no ID token to a pull request from a fork, so vet runs with no SafeDep Cloud credentials and uses the community endpoints."
      cloud=none
    else
      fail "The tenant-id input with no api-key input needs an ID token of GitHub. Give the job the permission id-token: write, or set the api-key input"
    fi
  fi
fi

code=0
(
  case $cloud in
    key) export SAFEDEP_TENANT_ID=$tenant SAFEDEP_API_KEY=$ACTION_API_KEY ;;
    # An empty SAFEDEP_API_KEY is a half credential to vet, so the script
    # unsets it, and vet exchanges the ID token of the job.
    workload)
      unset SAFEDEP_API_KEY
      export SAFEDEP_TENANT_ID=$tenant
      ;;
    # The fork run reads no credential at all. cloud.keychain_file points
    # vet at a keychain file that does not exist, so vet does not read a
    # login of the job user.
    none)
      unset SAFEDEP_API_KEY SAFEDEP_TENANT_ID
      export VET_CLOUD_KEYCHAIN_FILE=$tmp/no-credentials.json
      ;;
  esac
  exec vet ${global[@]+"${global[@]}"} "${args[@]}" ${extra[@]+"${extra[@]}"}
) >"$report" || code=$?

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
