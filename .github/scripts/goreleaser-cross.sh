#!/usr/bin/env bash
# Runs goreleaser in the goreleaser-cross image. The image has the C cross
# compilers for the CGO builds, so no job builds a toolchain. The Go version
# of the image must be the Go version of go.mod. test/release checks it.
set -euo pipefail

image="ghcr.io/goreleaser/goreleaser-cross:v1.27.3-v2.18.3@sha256:1820cee53c4c06cfb43c2203caca73f9497042f5b6061c8916a251228a321975"

docker run --rm \
  -e GITHUB_TOKEN -e HOMEBREW_TAP_GITHUB_TOKEN -e GORELEASER_CURRENT_TAG \
  -v "$PWD:/src" -w /src \
  --entrypoint bash "$image" \
  -c 'git config --global --add safe.directory /src && goreleaser "$@"' goreleaser "$@"
