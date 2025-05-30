#!/bin/bash

set -ex

export E2E_THIS_DIR=$(dirname $0)
export E2E_ROOT="$E2E_THIS_DIR/../../"
export E2E_FIXTURES="$E2E_THIS_DIR/fixtures"
export E2E_VET_BINARY="$E2E_ROOT/vet"
export E2E_VET_INSIGHTS_V2="${E2E_INSIGHTS_V2:-false}"
export E2E_VET_SCAN_CMD="$E2E_VET_BINARY scan -s --no-banner --insights-v2=$E2E_VET_INSIGHTS_V2"
export E2E_INSPECT_MALWARE_CMD="$E2E_VET_BINARY inspect malware"
export E2E_VET_CODE_SCAN_CMD="$E2E_VET_BINARY code scan"

bash $E2E_THIS_DIR/scenario-1-vet-scans-vet.sh
bash $E2E_THIS_DIR/scenario-2-vet-scan-demo-client-java.sh
bash $E2E_THIS_DIR/scenario-3-filter-fail-fast.sh
bash $E2E_THIS_DIR/scenario-4-lfp-fail-fast.sh
bash $E2E_THIS_DIR/scenario-5-gradle-depgraph-build.sh
bash $E2E_THIS_DIR/scenario-6-manifest-flag.sh
bash $E2E_THIS_DIR/scenario-7-rubygems-project-url.sh
bash $E2E_THIS_DIR/scenario-8-summary-report.sh
bash $E2E_THIS_DIR/scenario-9-malware-analysis.sh
bash $E2E_THIS_DIR/scenario-10-code-scan.sh
bash $E2E_THIS_DIR/scenario-11-code-csvreport.sh
bash $E2E_THIS_DIR/scenario-12-image-scan-local-docker-image.sh
bash $E2E_THIS_DIR/scenario-13-image-scan-with-local-tar.sh
bash $E2E_THIS_DIR/scenario-14-image-scan-with-remote-registry.sh
