#!/bin/bash

set -ex

$E2E_VET_SCAN_CMD \
  scan --github https://github.com/abhisek/swachalit \
  --report-json /tmp/swachalit.json \
  --filter-suite ./samples/filter-suites/fs-generic.yml

grep "https://github.com/rails/ruby-coffee-script" /tmp/swachalit.json
