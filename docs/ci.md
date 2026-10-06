# CI and AI agents

A plain scan reports and exits 0. A gate makes the scan exit 1 when it fails. `--fail-on SEVERITY`,
`--fail-on attacks` and `--policy FILE` set a gate. See [policy.md](policy.md).

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

This workflow installs the newest alpha build, checks the archive, scans the change and uploads the
findings to GitHub code scanning.

The releases page keeps only the last 5 alpha builds, so the workflow finds the newest build when
it runs. Do not pin an alpha version in a workflow. Its download fails when the release goes.

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
        run: |
          VET_VERSION=$(gh api "repos/safedep/vet/releases?per_page=30" \
            --jq '[.[] | select(.tag_name | startswith("v2.0.0-alpha."))][0].tag_name')
          gh release download "$VET_VERSION" --repo safedep/vet \
            --pattern vet_Linux_x86_64.tar.gz --pattern checksums.txt --dir "$RUNNER_TEMP"
          cd "$RUNNER_TEMP"
          sha256sum --check --ignore-missing checksums.txt
          tar -xzf vet_Linux_x86_64.tar.gz vet
          echo "$RUNNER_TEMP" >> "$GITHUB_PATH"

      - name: Scan the change
        env:
          BASE_REF: ${{ github.base_ref }}
          GITHUB_TOKEN: ${{ github.token }}
        run: vet scan --base-ref "origin/$BASE_REF" --fail-on high --report sarif=vet.sarif

      - uses: github/codeql-action/upload-sarif@2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2 # v4.38.2
        if: always()
        with:
          sarif_file: vet.sarif
```

`GITHUB_TOKEN` lets vet check the pinned actions of the workflows for impostor commits with the
GitHub API. See [controls.md](controls.md#pinned-commits).

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

`--report bitbucket=vet-bitbucket.json` writes a Bitbucket Code Insights file. The file holds two
keys. `report` is the body of the report, and `annotations` is the list of findings. The gate sets
the result of the report. With no gate, the report has no result.

The Code Insights API takes the report and the annotations in two requests, and at most 100
annotations in each request. In Pipelines, the local proxy at `localhost:29418` adds the
credentials. This step needs `vet`, `curl` and `jq` in the image:

```yaml
pipelines:
  pull-requests:
    '**':
      - step:
          name: vet
          script:
            - vet scan --base-ref "origin/$BITBUCKET_PR_DESTINATION_BRANCH" --fail-on high --report bitbucket=vet-bitbucket.json || status=$?
            - export API="http://api.bitbucket.org/2.0/repositories/$BITBUCKET_REPO_FULL_NAME/commit/$BITBUCKET_COMMIT/reports/vet"
            - jq '.report' vet-bitbucket.json | curl -sSf --proxy http://localhost:29418 -X PUT -H 'Content-Type: application/json' --data @- "$API"
            - |
              jq -c '.annotations | range(0; length; 100) as $i | .[$i:$i+100]' vet-bitbucket.json |
              while read -r batch; do
                curl -sSf --proxy http://localhost:29418 -X POST -H 'Content-Type: application/json' --data "$batch" "$API/annotations"
              done
            - exit "${status:-0}"
```

## AI agents

vet finds an AI agent from the `CLAUDECODE` or the `AI_AGENT` variable. In agent mode, vet writes
JSON on stdout and never prompts. It prints each error as one `ERR: code=… message=… help=…` line.
`--mode agent` turns on the same mode.

The [`vet-policy-authoring`](../.claude/skills/vet-policy-authoring/SKILL.md) Agent Skill lets an
agent write and test a policy.
