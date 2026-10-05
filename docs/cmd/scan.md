# vet scan

Scan a project, a repository, an image, an SBOM or a package.

## Synopsis

```text
vet scan [TARGET] [--base-ref REF] [--fail-on SEVERITY] [--policy FILE|NAME]
         [--report FORMAT=PATH]... [--strict] [--resume | --fresh] [--no-cache]
         [--exclude GLOB]... [--packages declared|installed|all] [--cooldown-days N]
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
Insights and SafeDep Threat Intel, and runs the controls: malware, known vulnerabilities, the dependency
cooldown, lockfile poisoning, dangerous workflow triggers, template injection and unpinned actions.
vet works with no credentials. `vet auth login` uses the API of your tenant.

A plain scan reports and exits 0. `--fail-on` and `--policy` set a gate. The gate fails, and vet
exits 1, when an unsuppressed finding is at the severity or above, or matches a fail rule of the
policy. The `policy.fail_on` and `policy.file` config keys set the same gate for every run. A
policy NAME with no extension and no directory is `policies/NAME.yml` in the vet config directory,
as `vet policy init` writes it, unless the current directory has a file with that name.

`--base-ref` compares the target with a git ref, for example `origin/main`. vet then checks only the
packages and the workflows that the change adds or modifies, and reports only their findings. vet
keeps the extraction of the base commit in the state directory. The next scan with the same base
commit reads it and does not extract the base again. The table counts the changed packages. It
shows a CHANGE column only when the rows have different changes. A `--base-ref` that git does not
know exits with code 2 and leaves no scan in the index.

stdout gets the report in the `-o` format. With no `-o`, the format follows the mode: `table` in a
terminal, `plain` in CI and `json` under an agent. stderr gets the progress, the diagnostics and the
gate line. In a terminal, vet first prints its banner and shows the first five diagnostics, errors
first. `-v` and the agent mode show all of them, and `vet report show SCAN_ID -v` lists them again.
The log lines of the parser libraries print only with `-v`. `--report FORMAT=PATH` also writes the report to a file. vet writes a temporary file and
renames it into place, so a failed write leaves no partial file.

`--packages` selects where vet finds packages. The `scan.packages` config key sets it for every run.

| Value | vet reads |
| --- | --- |
| `declared` | The lockfiles and the manifests. The default for a directory and a git URL. |
| `installed` | The packages on disk: `node_modules`, Python `site-packages` and `dist-packages`, Go binaries, installed gems and Rust binaries built with cargo-auditable. |
| `all` | Both. The default for an image. |

Use `installed` for a deployed app, a build output, an unpacked archive or a mounted file system. A
declared scan does not walk `node_modules`. No declared extractor reads a file under `node_modules`,
`site-packages` or `dist-packages`, because those files belong to installed packages.
Each installed package is in a manifest of kind `installed`, with the path of its metadata file. vet
does not report the project itself as an installed package: the `package.json` of the project, an
editable install or a wheel in `dist/`, the main module of a local Go build and the root crate of a
Rust binary.
Each selection reads the GitHub Actions workflows and the agent config files.
`--base-ref` reads declared packages only, because git does not hold installed packages.
When a default scan of a directory skips `node_modules`, `site-packages` or `dist-packages`, vet
names the directory and the flag that reads it. With `all`, the `installed-not-locked` control
reports a package in `node_modules` that the npm lockfile of its project does not list.

A scan of a root file system does not enter `proc`, `sys`, `dev` and the macOS `System/Volumes`.
On Linux, vet also skips each pseudo file system, such as proc, sysfs and cgroup, wherever it is
mounted. A path that the user cannot read gives one diagnostic with a count.

With `plugins.codeusage.enabled: true`, vet also reads the source files of a directory target. It
records which packages the code imports, and the AI and crypto capabilities that the code calls.
The `cyclonedx` report writes them as an xBOM and a CBOM. The code analysis needs a vet build with
CGO. A static build records a diagnostic and scans with no code usage.

A backend that does not answer does not fail the scan. The controls that need its data do not run,
and the report has a diagnostic. `--strict` turns a diagnostic into exit code 3.

vet saves each scan in the state directory. `vet report show` renders it again with no new scan. A
scan that a signal stops saves its progress, and the next `vet scan` of the target continues it. A
newer scan of the target supersedes the stopped scan, and only `--resume` continues it.
`--fresh` starts a new scan. `--resume` continues a stopped scan of any age. `--ephemeral` keeps no
state and no cache after the scan.

## Examples

```text
vet scan
vet scan . --fail-on high
vet scan . --policy default
vet scan . --base-ref origin/main
vet scan . --base-ref origin/main --report sarif=vet.sarif
vet scan . --policy vet-policy.yml -o json
vet scan oci://alpine:3.20 --ephemeral
vet scan /srv/app --packages installed
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
