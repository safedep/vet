#!/usr/bin/env bash
# Runs goreleaser in the goreleaser-cross image. The image has the C cross
# compilers for the CGO builds, so no job builds a toolchain. The Go version
# of the image must be the Go version of go.mod. test/release checks it.
set -euo pipefail

image="ghcr.io/goreleaser/goreleaser-cross:v1.26.3-v2.16.0@sha256:7fa2f6adefc63b9d51daa5678c1f37349583e55bfa0ebead1665443014d346d0"

docker run --rm \
  -e GITHUB_TOKEN -e HOMEBREW_TAP_GITHUB_TOKEN -e GORELEASER_CURRENT_TAG \
  -v "$PWD:/src" -w /src \
  --entrypoint bash "$image" \
  -c 'git config --global --add safe.directory /src && goreleaser "$@"' goreleaser "$@"
