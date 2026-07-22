#!/bin/bash

set -x

# Active (on-demand) malware analysis has been deprecated. --malware is now a
# backward compatible alias for --malware-query, for all plans. This scenario
# verifies that a free plan user running with --malware gets the known
# malicious packages query enrichment, without the old entitlement
# auto-switch warning.

# We need API key to run this test
# hence we are checking if E2E_VET_INSIGHTS_V2 is set to true
# because API key is available for Insights v2
if [ "$E2E_VET_INSIGHTS_V2" != "true" ]; then
  echo "Skipping scenario-15-enricher-auto-switch.sh as E2E_INSIGHTS_V2 is not set to true"
  exit 0
fi

if [ -z "$VET_API_KEY_FREE" ] || [ -z "$VET_CONTROL_TOWER_TENANT_ID_FREE" ]; then
  echo "Error: scenario-15-enricher-auto-switch.sh requires VET_API_KEY_FREE and VET_CONTROL_TOWER_TENANT_ID_FREE to be set"
  exit 1
fi

# Run the command and capture output
# use free user api keys and tenant id to verify --malware works as a query alias
env VET_API_KEY=$VET_API_KEY_FREE \
  VET_CONTROL_TOWER_TENANT_ID=$VET_CONTROL_TOWER_TENANT_ID_FREE \
  $E2E_VET_SCAN_CMD --purl pkg:/npm/@clerk/nextjs@6.9.6 \
  --malware \
  --report-markdown-summary=sum.md 2>&1 | tee scenario-output.log

if [ "${PIPESTATUS[0]}" -ne 0 ]; then
    echo "✗ vet scan with --malware failed for free plan user"
    exit 1
fi

# The entitlement auto-switch warning must be gone
echo "Checking that the free plan auto-switch message is no longer emitted..."
if grep -q "On-demand malicious package scanning is not available on the Free plan" scenario-output.log; then
    echo "✗ Deprecated free plan auto-switch message found in stdout"
    exit 1
else
    echo "✓ No deprecated free plan auto-switch message in stdout"
fi

# The package must be enriched via the known malicious packages query
echo "Checking for malware query enrichment in stdout..."
if grep -q "1/1 libraries were scanned for malware" scenario-output.log; then
    echo "✓ Malware query enrichment found in stdout"
else
    echo "✗ Malware query enrichment NOT found in stdout"
    exit 1
fi

# The markdown summary must report the known malicious packages database check
echo "Checking for malicious package analysis section in sum.md..."
if grep -q -i "known malicious packages database" sum.md; then
    echo "✓ Malicious package analysis section found in sum.md"
else
    echo "✗ Malicious package analysis section NOT found in sum.md"
    exit 1
fi

echo "All checks passed!"
