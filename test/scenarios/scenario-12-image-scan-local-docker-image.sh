#!/bin/bash

set -x

# Scenario for Container Scanning from local docker images

# Pull nats:2.10 image
docker pull nats:2.10

$E2E_VET_BINARY \
  scan --image nats:2.10
