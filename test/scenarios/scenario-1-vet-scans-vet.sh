#!/bin/bash

set -ex

echo $( \
  $E2E_VET_BINARY scan -s --no-banner --lockfiles "$E2E_ROOT/go.mod" --report-summary=false --filter 'pkg.name == "github.com/safedep/dry"' \
) | grep "github.com/safedep/dry"
