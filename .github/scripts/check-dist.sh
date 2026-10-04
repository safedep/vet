#!/usr/bin/env bash
# Checks the goreleaser output in dist: one binary for each platform, each
# built with CGO, and the vet@edge cask.
set -euo pipefail

artifacts=dist/artifacts.json

jq -r '.[] | select(.type == "Binary") | "\(.goos)/\(.goarch)"' "$artifacts" | sort > platforms.txt
printf '%s\n' darwin/all linux/amd64 linux/arm64 windows/amd64 | diff - platforms.txt

jq -r '.[] | select(.type == "Binary") | .path' "$artifacts" | while read -r bin; do
  if ! go version -m "$bin" | grep -qE '^\s+build\s+CGO_ENABLED=1$'; then
    echo "::error::$bin has no CGO, so it has no code usage analysis"
    exit 1
  fi
done

cask="dist/homebrew/Casks/vet@edge.rb"
grep -q 'binary "vet"' "$cask"
grep -qzE 'conflicts_with cask: \[\s*"vet",' "$cask"

bin=$(jq -r '.[] | select(.type == "Binary" and .goos == "linux" and .goarch == "amd64") | .path' "$artifacts")
"$bin" version
