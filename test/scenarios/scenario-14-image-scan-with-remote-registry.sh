#!/bin/bash

set -x

# Scenario for Container Scanning from remote registry

IMAGE="alpine/sqlite:3.48.0"
REPORT_JSON="/tmp/vet-image-scan-remote.json"

rm -f "$REPORT_JSON"

$E2E_VET_BINARY \
  scan --image "${IMAGE}" \
  --report-json "$REPORT_JSON" || exit 1

# Manifest source_type should be container_image, not purl
jq -e ".manifests[] | select(.source_type == \"container_image\" and .namespace == \"${IMAGE}\") | .source_type == \"container_image\"" "$REPORT_JSON" || exit 1

# Manifest namespace should be the image ref
jq -e ".manifests[] | select(.source_type == \"container_image\" and .namespace == \"${IMAGE}\") | .namespace == \"${IMAGE}\"" "$REPORT_JSON" || exit 1

# Manifest path should not contain '@' (it should be a DB location, not a package purl)
jq -e ".manifests[] | select(.source_type == \"container_image\" and .namespace == \"${IMAGE}\") | .path | contains(\"@\") | not" "$REPORT_JSON" || exit 1

# Display path should contain the image ref
jq -e ".manifests[] | select(.source_type == \"container_image\" and .namespace == \"${IMAGE}\") | .display_path | contains(\"${IMAGE}\")" "$REPORT_JSON" || exit 1

rm -f "$REPORT_JSON"
