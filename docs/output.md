# Output and saved scans

The terminal view goes to stderr. Report data goes to stdout with `-o`, and to files with
`--report FORMAT=PATH`. One scan writes many formats. A format that publishes the report itself,
such as a pull request comment, also takes `--report FORMAT` with no path. A failure to publish is a
warning, and the gate alone sets the exit code.

```bash
vet scan -o json > vet.json
vet scan --report sarif=vet.sarif --report markdown=vet.md
```

| Format | Use |
| --- | --- |
| `table`, `plain` | People, and `grep` |
| `json`, `jsonl` | Programs. `vet report schema get` prints the JSON Schema |
| `sarif` | GitHub code scanning and other SARIF tools |
| `markdown` | A job summary, or a comment that you post with your own tools. It has one row and one card for each cause: the findings of one control, gate rule, fix and file to edit |
| `pr-comment` | One pull request comment that vet edits on each run, with the progress since the last run. `--report pr-comment` posts it in CI. `--report pr-comment=FILE` writes the body |
| `cyclonedx` | An SBOM with the findings as vulnerabilities, and the AI and crypto inventory (CycloneDX 1.7) |
| `gitlab` | A GitLab dependency scanning report, for `artifacts:reports:dependency_scanning` |
| `bitbucket` | A Bitbucket Code Insights report and its annotations |

Every format lists the findings in one order. The findings of the attack controls come first, then
the most severe. A long list of critical vulnerabilities does not push an attack out of the table.
A finding of an attack control has an `attack` field in JSON, with its technique and its MITRE
ATT&CK ids. SARIF tags it `attack` and `external/mitre-attack/<id>`.

A vulnerability finding of a scan that computed reach shows it in every format: a REACH column in
the table, the last column of `plain`, a Reach column in `markdown`, the `reach` property in SARIF
and the `reach` object in JSON. The value names its evidence, as `called · 3 hops`, `not called`,
`imported · no symbol data` or `unknown · budget`. The table shows the riskiest reach of a row, so a
called vulnerability never hides behind one that is not called. A target with no source code has no
REACH column, and the scan view says `Reach: not computed, the target has no source code`. The scan
view also names the symbol bundle and counts each reach and each cause. The call graph search
covers the whole target. In a target with two `go.mod` files that require one module, a call from
one project makes the finding of the module `called` in both.

For a Go module, the dependency graph comes from the code. vet reads the import blocks of the Go
files of the project and of each module of the build list. It finds a module in `vendor`, in the
directory of a local `replace` inside the target, or in the module cache. It runs no build and
downloads nothing, so run `go mod download` before a scan. A module with no source on the disk is
open: vet does not know what it imports. A package that only an open module can reach is `unknown ·
no dependency source`, and the scan warns with `module_graph`. vet builds no graph for a module of
a `go.work` workspace, or for a `go.mod` with a `go` directive below 1.17. Its findings keep
`unknown · no graph`.

Each package in a report has a `purl`. It follows the purl-spec type definition of its ecosystem,
and it keeps the version as the manifest writes it. `name` and `version` hold the canonical form
that vet compares.

## Debug log

`--debug` writes the debug log of vet and of its libraries on stderr, with the rich view off.
`--log FILE` appends the same log to a file as JSON lines, for a support case. Stdout keeps the
report in both cases, so `vet scan --debug -o json | jq` still works. `-v` shows more of the view
and no log line. `--debug` and `-q` cannot be used together.

## Saved scans

vet saves each scan in its state directory. These commands read the saved scans, with no new scan:

| Command | Does |
| --- | --- |
| `vet report show` | Renders the last scan, or writes it in another format |
| `vet report show last --policy FILE` | Applies a new gate to the last scan |
| `vet report list` | Lists the scans of the current directory |
| `vet report diff` | Compares the findings of two scans |
| `vet report finding show ID` | Shows one finding with its evidence |
| `vet report capability list` | Lists the AI and crypto capabilities |
| `vet report root list` | Lists the entry points of the call graph search |

A scan that stops, for example with Ctrl-C or a lost connection, continues on the next run.
`vet state show` prints the state directory and the retention rules. `vet state delete` deletes
scans or the enrichment cache.

## Configuration

vet reads `config.yml` from the user config directory, then the `VET_*` variables, then the flags.
`vet config show` prints the path and each value with its source. A config file inside the scanned
target changes nothing. `vet config schema get` prints the JSON Schema of the file.
