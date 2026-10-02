# vet scan

Scan a project, a repository, an image, an SBOM or a package.

## Synopsis

```text
vet scan [TARGET] [--base-ref REF] [--fail-on SEVERITY] [--policy FILE]
         [--report FORMAT=PATH]... [--strict] [--resume | --fresh] [--no-cache]
         [--exclude GLOB]... [--cooldown-days N]
         [--state-dir DIR] [--cache-dir DIR] [--ephemeral]
         [-o table|plain|json|jsonl|sarif|markdown|cyclonedx|gitlab|bitbucket]
```

## Description

`vet scan` finds supply chain risk in a target. The target is one of these:

| Target | Example |
| --- | --- |
| A directory. The default is the current directory. | `vet scan`, `vet scan ./app` |
| A git repository URL. vet makes a shallow clone. | `vet scan https://github.com/safedep/vet` |
| A container image, from a registry or a `.tar` file. | `vet scan oci://alpine:3.20`, `vet scan image.tar` |
| An SBOM file, CycloneDX or SPDX. | `vet scan bom.cdx.json` |
| A package URL. | `vet scan pkg:npm/left-pad@1.3.0` |

vet extracts the packages and the GitHub Actions workflows, checks the packages with SafeDep
Insights and Malysis, and runs the controls: malware, known vulnerabilities, the dependency
cooldown, lockfile poisoning, dangerous workflow triggers, template injection and unpinned actions.
vet works with no credentials. `vet auth login` uses the API of your tenant.

A plain scan reports and exits 0. `--fail-on` and `--policy` set a gate. The gate fails, and vet
exits 1, when an unsuppressed finding is at the severity or above, or matches a fail rule of the
policy. The `policy.fail_on` and `policy.file` config keys set the same gate for every run.

`--base-ref` compares the target with a git ref, for example `origin/main`. vet then checks only the
packages and the workflows that the change adds or modifies, and reports only their findings. vet
keeps the extraction of the base commit in the state directory. The next scan with the same base
commit reads it and does not extract the base again.

stdout gets the report in the `-o` format. With no `-o`, the format follows the mode: `table` in a
terminal, `plain` in CI and `json` under an agent. stderr gets the progress, the diagnostics and the
gate line. `--report FORMAT=PATH` also writes the report to a file. vet writes a temporary file and
renames it into place, so a failed write leaves no partial file.

A backend that does not answer does not fail the scan. The controls that need its data do not run,
and the report has a diagnostic. `--strict` turns a diagnostic into exit code 3.

vet saves each scan in the state directory. `vet report show` renders it again with no new scan. A
scan that a signal stops saves its progress, and the next `vet scan` of the target continues it.
`--fresh` starts a new scan. `--resume` continues a stopped scan of any age. `--ephemeral` keeps no
state and no cache after the scan.

## Examples

```text
vet scan
vet scan . --fail-on high
vet scan . --base-ref origin/main --report sarif=vet.sarif
vet scan . --policy vet-policy.yml -o json
vet scan oci://alpine:3.20 --ephemeral
vet scan pkg:npm/left-pad@1.3.0 -o jsonl
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The scan completed, and the gate passed or no gate is set. |
| 1 | The gate failed. The report is complete and written. |
| 2 | A flag, the target, the config, the credentials or the policy is not valid. No scan ran. |
| 3 | The scan or a report write failed, or `--strict` found a diagnostic. |
| 130 | A signal stopped the scan. vet saved the progress, and the next `vet scan` continues it. |
