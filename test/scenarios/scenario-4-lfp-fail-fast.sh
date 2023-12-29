#!/bin/bash

set -x

$E2E_VET_BINARY scan -s --no-banner \
  --lockfiles $E2E_FIXTURES/lockfiles/nestjs-lfp-package-lock.json \
  --lockfile-as package-lock.json \
  --report-summary=false \
  --fail-fast || exit 0

exit 1
