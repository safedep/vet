#!/bin/bash

set -x

# Run the command and capture output
$E2E_VET_SCAN_CMD \
  --malware \
  --report-markdown-summary=sum.md 2>&1 | tee scenario-output.log

# Check if the free plan message appears in stdout
echo "Checking for free plan message in stdout..."
if grep -q "On-demand malicious package scanning is not available on the Free plan" scenario-output.log; then
    echo "✓ Free plan message found in stdout"
else
    echo "✗ Free plan message NOT found in stdout"
    exit 1
fi

# Check if similar message exists in sum.md
echo "Checking for upgrade message in sum.md..."
if grep -q -i "upgrade\|free plan\|on-demand" sum.md; then
    echo "✓ Upgrade/free plan message found in sum.md"
else
    echo "✗ Upgrade/free plan message NOT found in sum.md"
    exit 1
fi

echo "All checks passed!"
