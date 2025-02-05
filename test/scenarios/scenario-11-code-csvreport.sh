#!/bin/bash

set -x

E2E_CODEPATH=$(realpath $E2E_FIXTURES/code)

E2E_VET_CODE_DB="/tmp/vet-code.db"
E2E_VET_CSV_REPORT="/tmp/vet-code.csv"
E2E_VET_EXPECTED_CSV="/tmp/expected-report.csv"

rm -f $E2E_VET_CODE_DB
rm -f $E2E_VET_CSV_REPORT
rm -f $E2E_VET_EXPECTED_CSV

$E2E_VET_CODE_SCAN_CMD \
  --app $E2E_CODEPATH \
  --db $E2E_VET_CODE_DB \
  --lang python || exit 1

ls $E2E_VET_CODE_DB || exit 1

$E2E_VET_BINARY scan \
  -D $E2E_CODEPATH \
  --code $E2E_VET_CODE_DB \
  --filter 'vulns.critical.exists(p, true) || vulns.high.exists(p, true)' \
  --report-csv $E2E_VET_CSV_REPORT || exit 1

ls $E2E_VET_CSV_REPORT || exit 1

cat > $E2E_VET_EXPECTED_CSV << EOL
Ecosystem,Manifest Path,Package Name,Package Version,Violation,Introduced By,Path To Root,OSV ID,CVE ID,Vulnerability Severity,Vulnerability Summary,Usage Evidence count,Sample Usage Evidence
PyPI,$E2E_CODEPATH/requirements.txt,flask,1.0.4,cli-filter,flask,flask,GHSA-m2qf-hxjv-5gpq,CVE-2023-30861,HIGH,Flask vulnerable to possible disclosure of permanent session cookie due to missing Vary: Cookie header,1,$E2E_CODEPATH/usage.py:4
PyPI,$E2E_CODEPATH/requirements.txt,flask,1.0.4,cli-filter,flask,flask,PYSEC-2023-62,CVE-2023-30861,,,1,$E2E_CODEPATH/usage.py:4
PyPI,$E2E_CODEPATH/requirements.txt,langchain,0.2.1,cli-filter,langchain,langchain,GHSA-3hjh-jh2h-vrg6,CVE-2024-2965,MEDIUM,Denial of service in langchain-community,0,
PyPI,$E2E_CODEPATH/requirements.txt,langchain,0.2.1,cli-filter,langchain,langchain,PYSEC-2024-114,CVE-2024-7042,CRITICAL,,0,
PyPI,$E2E_CODEPATH/requirements.txt,langchain,0.2.1,cli-filter,langchain,langchain,PYSEC-2024-118,CVE-2024-2965,MEDIUM,,0,
EOL

# Compare CSV heading
head -n 1 "$E2E_VET_EXPECTED_CSV" | diff - <(head -n 1 "$E2E_VET_CSV_REPORT") || exit 1

# Compare Sorted CSV body
diff <(tail -n +2 "$E2E_VET_EXPECTED_CSV" | sort) <(tail -n +2 "$E2E_VET_CSV_REPORT" | sort) || exit 1

rm -f $E2E_VET_CODE_DB
rm -f $E2E_VET_CSV_REPORT
rm -f $E2E_VET_EXPECTED_CSV

exit 0
