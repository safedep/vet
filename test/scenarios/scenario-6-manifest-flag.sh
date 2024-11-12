#!/bin/bash

set -ex

echo $( \
  $E2E_VET_SCAN_CMD \
  -M "$E2E_ROOT/go.mod" \
  --report-summary=false \
  --filter 'pkg.name == "github.com/safedep/dry"' \
) | grep "github.com/safedep/dry"

$E2E_VET_SCAN_CMD \
  -M $E2E_FIXTURES/lockfiles/nestjs-lfp-package-lock.json \
  --type package-lock.json \
  --report-summary=false \
  --fail-fast || exit 0

exit 1
