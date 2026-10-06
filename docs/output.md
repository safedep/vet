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
| `markdown` | A pull request comment or a job summary |
| `cyclonedx` | An SBOM with the findings as vulnerabilities, and the AI and crypto inventory (CycloneDX 1.7) |
| `gitlab` | A GitLab dependency scanning report, for `artifacts:reports:dependency_scanning` |
| `bitbucket` | A Bitbucket Code Insights report and its annotations |

Each package in a report has a `purl`. It follows the purl-spec type definition of its ecosystem,
and it keeps the version as the manifest writes it. `name` and `version` hold the canonical form
that vet compares.

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

A scan that stops, for example with Ctrl-C or a lost connection, continues on the next run.
`vet state show` prints the state directory and the retention rules. `vet state delete` deletes
scans or the enrichment cache.

## Configuration

vet reads `config.yml` from the user config directory, then the `VET_*` variables, then the flags.
`vet config show` prints the path and each value with its source. A config file inside the scanned
target changes nothing. `vet config schema get` prints the JSON Schema of the file.
