#!/bin/bash

set -ex

echo $( \
  $E2E_VET_SCAN_CMD \
  --github https://github.com/safedep/demo-client-java.git \
  --report-summary=false \
  --filter 'vulns.critical.exists(p, p.id == "GHSA-4wrc-f8pq-fpqp")' \
  --skip-github-dependency-graph-api \
) | grep "https://github.com/spring-projects/spring-framework"
