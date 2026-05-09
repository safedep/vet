#!/bin/bash
#
# scenario-16: OSS-user invariant for `vet endpoint scan`.
#
# When a user runs `vet endpoint scan` without any SafeDep cloud
# credentials configured, vet must NOT create the endpointsync WAL
# file (or its parent SafeDep directory). OSS users who have not
# opted into cloud sync should never see or feel the WAL on disk.
#
# This is the cloud-sink-gating contract: buildCloudSink runs only
# when the credential resolver succeeds; no SyncClient is constructed
# in the no-creds path; no SQLite WAL is ever opened.
#

set -ex

E2E_TMP_HOME=$(mktemp -d -t vet-oss-no-creds-XXXXXX)
trap "rm -rf $E2E_TMP_HOME" EXIT

# Strip every cloud-credential env var the resolver layers consult.
# `env -i` would also work but we want PATH and basic vars from the
# parent for the binary probes (cursor, gh, etc.) the scanner runs.
env \
    -u SAFEDEP_API_KEY \
    -u SAFEDEP_TENANT_ID \
    -u VET_API_KEY \
    -u VET_INSIGHTS_API_KEY \
    -u VET_CONTROL_TOWER_TENANT_ID \
    HOME="$E2E_TMP_HOME" \
    XDG_CONFIG_HOME="$E2E_TMP_HOME/.config" \
    XDG_DATA_HOME="$E2E_TMP_HOME/.local/share" \
    APPDATA="$E2E_TMP_HOME" \
    "$E2E_VET_BINARY" endpoint scan --silent --drain-timeout 2s

# Assert no SafeDep directory and no SQLite WAL artefact landed under
# the isolated HOME. Anything matching "safedep" anywhere in the tree
# (or any *.db file) fails the scenario.
LEAKED=$(find "$E2E_TMP_HOME" \( -iname "safedep" -o -name "sync.db" -o -name "*.db" \) 2>/dev/null || true)

if [ -n "$LEAKED" ]; then
    echo "FAIL: OSS no-creds run created SafeDep / WAL artefacts:"
    echo "$LEAKED"
    exit 1
fi

echo "PASS: scenario-16 no-creds run left HOME free of SafeDep artefacts"
