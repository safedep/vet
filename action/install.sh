#!/usr/bin/env bash
# install.sh picks a vet v2 release, verifies it and puts vet on PATH.
# docs/github-action.md gives the rules. The script never reads the latest
# release of safedep/vet, because that release belongs to vet v1.
#
# Environment: ACTION_VERSION, ACTION_COOLDOWN, GH_TOKEN, RUNNER_OS,
# RUNNER_ARCH, RUNNER_TEMP, GITHUB_PATH.
set -euo pipefail

readonly repo=safedep/vet
readonly signer='^https://github\.com/safedep/vet/\.github/workflows/(release-edge\.yml@refs/heads/(v2|main)|release\.yml@refs/tags/v2\.[0-9]+\.[0-9]+)$'
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

fail() {
  echo "::error::$*"
  exit 1
}

hours() {
  if [ "$1" -eq 1 ]; then echo "1 hour"; else echo "$1 hours"; fi
}

for tool in gh jq; do
  command -v "$tool" >/dev/null || fail "The action needs $tool on the runner"
done
# The jq of a Windows runner writes CRLF line ends, and bash keeps the CR.
if [ "${RUNNER_OS:-}" = Windows ]; then
  jq() { command jq -b "$@"; }
fi
if command -v sha256sum >/dev/null; then
  sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null; then
  sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
  fail "The action needs sha256sum or shasum on the runner"
fi

case "${RUNNER_OS:-}/${RUNNER_ARCH:-}" in
  Linux/X64) archive=vet_Linux_x86_64.tar.gz ;;
  Linux/ARM64) archive=vet_Linux_arm64.tar.gz ;;
  macOS/*) archive=vet_Darwin_all.tar.gz ;;
  Windows/X64) archive=vet_Windows_x86_64.zip ;;
  *) fail "vet has no release for ${RUNNER_OS:-this OS} on ${RUNNER_ARCH:-this CPU}" ;;
esac
case $archive in
  *.zip) command -v unzip >/dev/null || fail "The action needs unzip on the runner" ;;
  *) command -v tar >/dev/null || fail "The action needs tar on the runner" ;;
esac

# valid_channel prints the channel of a channel file, or fails.
valid_channel() {
  jq -er '.v2.channel | select(. == "stable" or . == "prerelease")' 2>/dev/null
}

# The channel file on the default branch lets SafeDep move users from the
# pre-releases to the stable releases. Both sets pass the same cooldown and
# the same checks.
read_channel() {
  local remote
  if remote=$(gh api "repos/$repo/contents/action/channel.json" -H 'Accept: application/vnd.github.raw+json' 2>/dev/null) &&
    channel=$(valid_channel <<<"$remote"); then
    return
  fi
  echo "::warning::The action cannot read the channel file on the default branch of $repo. The action uses its own copy."
  channel=$(valid_channel <"$here/channel.json") || fail "The channel file of the action is not valid"
}

version=${ACTION_VERSION:-auto}
cooldown=${ACTION_COOLDOWN:-24}
[[ $cooldown =~ ^(0|[1-9][0-9]{0,5})$ ]] || fail "The cooldown input is not a count of hours: '$cooldown'"
min=$(tr -d '[:space:]' <"$here/min-version")
exact=""
case $version in
  auto)
    read_channel
    reason="the $channel channel and a cooldown of $(hours "$cooldown")"
    ;;
  latest)
    channel=stable
    reason="the newest stable release and a cooldown of $(hours "$cooldown")"
    ;;
  latest-prerelease)
    channel=prerelease
    reason="the newest release and a cooldown of $(hours "$cooldown")"
    ;;
  *)
    [[ $version =~ ^v?2\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] ||
      fail "The version input is not valid: '$version'. Use auto, latest, latest-prerelease or a v2 version such as 2.1.0"
    exact=v${version#v}
    channel=prerelease
    cooldown=0
    reason="the version input"
    ;;
esac

tmp=$(mktemp -d "${RUNNER_TEMP:?}/vet-install.XXXXXX")
releases=$tmp/releases.json
gh api --paginate "repos/$repo/releases?per_page=100" | jq -s 'add // []' >"$releases" ||
  fail "The action cannot list the releases of $repo"
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# resolve lists the candidates, newest first, as the tag and its youngest
# time. Arguments: the channel and the cooldown in hours.
resolve() {
  jq -r -f "$here/resolve.jq" --arg major v2 --arg channel "$1" --arg cooldown_hours "$2" \
    --arg min_version "$min" --arg now "$now" "$releases"
}

candidates=$tmp/candidates
resolve "$channel" "$cooldown" >"$candidates"
if [ -n "$exact" ]; then
  awk -F '\t' -v tag="$exact" '$1 == tag' "$candidates" >"$candidates.exact"
  mv "$candidates.exact" "$candidates"
  [ -s "$candidates" ] || fail "The action takes only an immutable v2 release at or above $min. The version input names $exact"
fi
if [ ! -s "$candidates" ]; then
  resolve "$channel" 0 >"$tmp/any"
  newest=$(head -n 1 "$tmp/any")
  [ -n "$newest" ] || fail "safedep/vet has no immutable $channel v2 release at or above $min"
  tag=${newest%%$'\t'*}
  age=$(jq -rn --arg t "${newest#*$'\t'}" '(now - ($t | fromdateiso8601)) / 3600 | floor')
  fail "No vet release passes the cooldown of $(hours "$cooldown"). The newest release $tag is $(hours "$age") old. To use it now, set the version input to ${tag#v}"
fi

# The attestation time is the latest time that sigstore verified: the
# transparency log time or a timestamp authority time.
attested_at='[.[].verificationResult.verifiedTimestamps[]? | select(.type == "Tlog" or .type == "TimestampAuthority")
  | .timestamp | sub("\\.[0-9]+"; "") | sub("\\+00:00$"; "Z") | fromdateiso8601] | max // empty | floor'

bin=$tmp/bin
# The loop reads fd 3, so no command in it can take a candidate from stdin.
while IFS=$'\t' read -r tag _ <&3; do
  # gh release download takes the latest release when the tag is empty.
  [ -n "$tag" ] || fail "The resolver gave an empty tag"
  dir=$tmp/$tag
  mkdir -p "$dir"
  gh release download "$tag" --repo "$repo" --dir "$dir" --pattern "$archive" --pattern checksums.txt
  [ -f "$dir/$archive" ] && [ -f "$dir/checksums.txt" ] || fail "The release $tag has no $archive or no checksums.txt"

  want=$(awk -v f="$archive" '$2 == f || $2 == "*" f { print $1 }' "$dir/checksums.txt")
  got=$(sha256 "$dir/$archive")
  [ -n "$want" ] && [ "$want" = "$got" ] || fail "The SHA-256 sum of $archive does not match checksums.txt in the release $tag"

  attestation=$dir/attestation.json
  gh attestation verify "$dir/$archive" --repo "$repo" --cert-identity-regex "$signer" \
    --deny-self-hosted-runners --format json >"$attestation" ||
    fail "The build attestation of $archive does not verify. Do not use the release $tag"

  # An attestation that is newer than the release makes the release young.
  signed=$(jq -r "$attested_at" "$attestation")
  [ -n "$signed" ] || fail "The build attestation of $tag has no verified time"
  age=$(($(date -u +%s) - signed))
  if [ "$age" -lt $((cooldown * 3600)) ]; then
    echo "::notice::The action skips $tag, because its attestation is $(hours $((age / 3600))) old."
    continue
  fi

  mkdir -p "$bin"
  case $archive in
    *.zip) unzip -q "$dir/$archive" -d "$bin" ;;
    *) tar -xzf "$dir/$archive" -C "$bin" ;;
  esac
  path=$bin
  if command -v cygpath >/dev/null; then
    path=$(cygpath -w "$bin")
  fi
  echo "$path" >>"${GITHUB_PATH:?}"
  echo "::notice::The action installs vet $tag. The choice comes from $reason."
  exit 0
done 3<"$candidates"

fail "No vet release passes the cooldown of $(hours "$cooldown"). The attestation of each candidate is too new."
