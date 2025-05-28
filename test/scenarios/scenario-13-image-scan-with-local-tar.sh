#!/bin/bash

set -x

# Scenario for Container Scanning from tar folder

# Pull nats:2.10 image
docker pull nats:2.10

# save this image into tar file
docker save nats:2.10 -o nats210.tar

$E2E_VET_BINARY \
  scan --image ./nats210.tar
