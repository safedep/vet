# False-positive run

The false-positive run scans clean projects at fixed commits with the built-in extractors and
controls, and with no enricher. It fails on each finding of an attack control. It writes a table of
the other hidden-code and agent-config findings, so a reviewer sees the noise of a control that
warns.

```bash
go test -tags falsepositive -count=1 -timeout 50m ./test/falsepositive/
VET_FP_CACHE=/tmp/vet-fp VET_FP_REPORT=/tmp/vet-fp.md go test -tags falsepositive -count=1 ./test/falsepositive/
```

`VET_FP_CACHE` keeps the checkouts between runs. `VET_FP_REPORT` names a file for the table. The run
needs the network, so `go test ./...` does not run it. The workflow `false-positive.yml` runs it on
dispatch and each week.

## Rules

- [repos.yaml](repos.yaml) lists each project with a fixed commit and the detection that it stresses.
  Move a commit only in a change that records the table before and after.
- A new detection with a risk of false positives starts as a control that warns. It becomes an attack
  control in a change that shows a clean run in its pull request.
- A pull request that changes a detection runs the workflow on dispatch and puts the table in its
  body.
- A finding on a clean project is a false positive until a reviewer shows that the file is malicious.
  Fix the detection, or add a near miss to the [evasion corpus](../evasion/README.md) and a narrower
  rule. Do not add a suppression to make the run pass.
