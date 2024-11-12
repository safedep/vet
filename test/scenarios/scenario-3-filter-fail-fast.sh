#!/bin/bash

set -x

$E2E_VET_SCAN_CMD \
  --github https://github.com/safedep/demo-client-java.git \
  --report-summary=false \
  --skip-github-dependency-graph-api \
  --filter 'vulns.critical.exists(p, p.id == "GHSA-4wrc-f8pq-fpqp")' \
  --filter-fail || exit 0

exit 1
