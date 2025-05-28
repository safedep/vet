#!/bin/bash

set -x

# Scenario for Container Scanning from remote registry

$E2E_VET_BINARY \
  scan --image nats:2.10
