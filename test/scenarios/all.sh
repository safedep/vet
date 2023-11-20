#!/bin/bash

set -ex

export E2E_THIS_DIR=$(dirname $0)
export E2E_ROOT="$E2E_THIS_DIR/../../"
export E2E_VET_BINARY="$E2E_ROOT/vet"

bash $E2E_THIS_DIR/scenario-1-vet-scans-vet.sh
bash $E2E_THIS_DIR/scenario-2-vet-scan-demo-client-java.sh
