#!/bin/bash

set -ex

$E2E_VET_SCAN_CMD \
  --lockfiles $E2E_FIXTURES/lockfiles/demo-client-java-gradle.lockfile \
  --lockfile-as gradle.lockfile \
  --report-graph /tmp/graph

graphFile=$(ls /tmp/graph/*demo-client-java-gradle*)

grep "org.springframework:spring-beans@5.3.23" $graphFile
grep '"org.springframework.boot:spring-boot-starter-data-rest@2.7.4" -> "org.springframework.data:spring-data-rest-webmvc@3.7.3";' $graphFile

set +e
grep '"org.springframework.boot:spring-boot-starter-json@2.7.4" -> "org.springframework:spring-beans@5.3.23";' $graphFile && exit 1
exit 0
