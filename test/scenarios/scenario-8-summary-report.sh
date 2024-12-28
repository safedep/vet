#!/bin/bash

set -ex

if [ "$E2E_VET_INSIGHTS_V2" != "true" ]; then
  echo "Skipping scenario-8-summary-report.sh as E2E_INSIGHTS_V2 is not set to true"
  exit 0
fi

$(echo \
$E2E_VET_SCAN_CMD \
  scan --purl pkg:/npm/@clerk/nextjs@6.9.6
) | grep "slsa: verified"

