#!/usr/bin/env bash
# Runs goreleaser in the goreleaser-cross image. The image has the C cross
# compilers for the CGO builds, so no job builds a toolchain. The Go version
# of the image must be the Go version of go.mod. test/release checks it.
set -euo pipefail

image="ghcr.io/goreleaser/goreleaser-cross:v1.27.1-3-v2.18.3@sha256:6683f7a137adeed2a7ac1aea80c52e486604e5f02ffaf4ca860e6413bbbaf665"

docker run --rm \
  -e GITHUB_TOKEN -e HOMEBREW_TAP_GITHUB_TOKEN -e GORELEASER_CURRENT_TAG \
  -v "$PWD:/src" -w /src \
  --entrypoint bash "$image" \
  -c 'git config --global --add safe.directory /src && goreleaser "$@"' goreleaser "$@"
