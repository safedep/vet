#!/bin/bash

set -x

export E2E_VET_CODE_DB="/tmp/vet-code.db"

rm -f $E2E_VET_CODE_DB

$E2E_VET_CODE_SCAN_CMD \
  --app $E2E_FIXTURES/code \
  --db $E2E_VET_CODE_DB \
  --lang python || exit 1

ls $E2E_VET_CODE_DB || exit 1

rm -f $E2E_VET_CODE_DB

exit 0
