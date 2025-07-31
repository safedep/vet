#!/bin/bash

set -x

# Scenario for Container Scanning from local docker images

IMAGE="alpine/sqlite:3.48.0"

# Pull image
docker pull ${IMAGE}

$E2E_VET_BINARY \
  scan --image ${IMAGE} --image-no-remote
