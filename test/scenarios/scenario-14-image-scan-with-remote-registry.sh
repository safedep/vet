#!/bin/bash

set -x

# Scenario for Container Scanning from remote registry

IMAGE="alpine/sqlite:3.48.0"

$E2E_VET_BINARY \
  scan --image ${IMAGE}
