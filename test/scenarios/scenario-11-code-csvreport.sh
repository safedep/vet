#!/bin/bash

set -x

E2E_VET_CODE_DB="/tmp/vet-code.db"
E2E_VET_CSV_REPORT="/tmp/vet-code.csv"

rm -f $E2E_VET_CODE_DB
rm -f $E2E_VET_CSV_REPORT

$E2E_VET_CODE_SCAN_CMD \
  --app $E2E_FIXTURES/code \
  --db $E2E_VET_CODE_DB \
  --lang python || exit 1

ls $E2E_VET_CODE_DB || exit 1

$E2E_VET_BINARY scan \
  -D $E2E_FIXTURES/code \
  --code $E2E_VET_CODE_DB \
  --filter 'vulns.critical.exists(p, true) || vulns.high.exists(p, true)' \
  --report-csv $E2E_VET_CSV_REPORT || exit 1

ls $E2E_VET_CSV_REPORT || exit 1

E2E_REALPATH=$(realpath $E2E_THIS_DIR)
echo $E2E_THIS_DIR
echo $E2E_REALPATH

TEMP_EXPECTED_CSV="/tmp/expected-report.csv"

cat > $TEMP_EXPECTED_CSV << EOL
Ecosystem,Manifest Path,Package Name,Package Version,Violation,Introduced By,Path To Root,OSV ID,CVE ID,Vulnerability Severity,Vulnerability Summary,Usage Evidence count,Sample Usage Evidence
PyPI,$E2E_REALPATH/fixtures/code/requirements.txt,flask,1.0.4,cli-filter,flask,flask,GHSA-m2qf-hxjv-5gpq,CVE-2023-30861,HIGH,Flask vulnerable to possible disclosure of permanent session cookie due to missing Vary: Cookie header,1,test/scenarios/fixtures/code/usage.py:4
PyPI,$E2E_REALPATH/fixtures/code/requirements.txt,flask,1.0.4,cli-filter,flask,flask,PYSEC-2023-62,CVE-2023-30861,,,1,test/scenarios/fixtures/code/usage.py:4
PyPI,$E2E_REALPATH/fixtures/code/requirements.txt,langchain,0.2.1,cli-filter,langchain,langchain,GHSA-3hjh-jh2h-vrg6,CVE-2024-2965,MEDIUM,Denial of service in langchain-community,0,
PyPI,$E2E_REALPATH/fixtures/code/requirements.txt,langchain,0.2.1,cli-filter,langchain,langchain,PYSEC-2024-114,CVE-2024-7042,CRITICAL,,0,
PyPI,$E2E_REALPATH/fixtures/code/requirements.txt,langchain,0.2.1,cli-filter,langchain,langchain,PYSEC-2024-118,CVE-2024-2965,MEDIUM,,0,
EOL

echo "expected" $TEMP_EXPECTED_CSV
echo "actual" $E2E_VET_CSV_REPORT

diff $TEMP_EXPECTED_CSV $E2E_VET_CSV_REPORT || exit 1

rm -f $E2E_VET_CODE_DB
rm -f $E2E_VET_CSV_REPORT
rm -f $TEMP_EXPECTED_CSV

exit 0
