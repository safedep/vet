#!/bin/bash

set -x

# Scenario for Container Scanning from tar folder

IMAGE="alpine/sqlite:3.48.0"
TAR_FILE="alpine-sqlite.tar"

# Pull image
docker pull ${IMAGE}

# save this image into tar file
docker save ${IMAGE} -o ${TAR_FILE}

$E2E_VET_BINARY \
  scan --image ./${TAR_FILE} --image-no-remote
