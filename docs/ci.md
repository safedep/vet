# CI and AI agents

A plain scan reports and exits 0. A gate makes the scan exit 1 when it fails. `--fail-on SEVERITY`
and `--policy FILE` set a gate. See [policy.md](policy.md).

| Exit code | Meaning |
| --- | --- |
| 0 | The scan completed, and the gate passed or no gate was set |
| 1 | The gate failed |
| 2 | A usage or config error. The message names the fix |
| 3 | A runtime error, for example a report file that vet cannot write |
| 130 | A signal stopped vet. The scan continues on the next run |

In a pull request, use `--base-ref` with the base branch. vet then reports only the packages and the
workflows that the change adds or modifies. The checkout needs the history of the base branch.

## GitHub Actions

This workflow installs a pinned alpha build, checks the archive, scans the change and uploads the
findings to GitHub code scanning. Set `VET_VERSION` to a release from
[install.md](install.md#release-binaries).

```yaml
name: vet

on:
  pull_request:

permissions:
  contents: read

jobs:
  vet:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with:
          fetch-depth: 0

      - name: Install vet
        env:
          GH_TOKEN: ${{ github.token }}
          VET_VERSION: v2.0.0-alpha.20261004163722
        run: |
          gh release download "$VET_VERSION" --repo safedep/vet \
            --pattern vet_Linux_x86_64.tar.gz --pattern checksums.txt --dir "$RUNNER_TEMP"
          cd "$RUNNER_TEMP"
          sha256sum --check --ignore-missing checksums.txt
          tar -xzf vet_Linux_x86_64.tar.gz vet
          echo "$RUNNER_TEMP" >> "$GITHUB_PATH"

      - name: Scan the change
        env:
          BASE_REF: ${{ github.base_ref }}
        run: vet scan --base-ref "origin/$BASE_REF" --fail-on high --report sarif=vet.sarif

      - uses: github/codeql-action/upload-sarif@2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2 # v4.38.2
        if: always()
        with:
          sarif_file: vet.sarif
```

The `vet-action` of vet v1 installs vet v1. A GitHub Action for vet v2 is planned.

## GitLab CI

GitLab reads the `gitlab` file as a dependency scanning report:

```yaml
vet:
  script:
    - vet scan . --fail-on critical --report gitlab=gl-dependency-scanning-report.json
  artifacts:
    when: always
    reports:
      dependency_scanning: gl-dependency-scanning-report.json
```

## Bitbucket Pipelines

The `bitbucket` file holds `report` and `annotations`. A pipeline step sends `report` with
`PUT /2.0/repositories/{workspace}/{repo}/commit/{commit}/reports/vet`. Then it sends the
annotations with `POST .../reports/vet/annotations`, at most 100 in each request. The gate sets the
result of the report. With no gate, the report has no result.

## AI agents

vet finds an AI agent from the `CLAUDECODE` or the `AI_AGENT` variable. In agent mode, vet writes
JSON on stdout and never prompts. It prints each error as one `ERR: code=… message=… help=…` line.
`--mode agent` turns on the same mode.

The [`vet-policy-authoring`](../.claude/skills/vet-policy-authoring/SKILL.md) Agent Skill lets an
agent write and test a policy.
