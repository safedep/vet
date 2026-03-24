# GitHub Actions Pinning

## Why Pin GitHub Actions?

GitHub Actions referenced by mutable tags (e.g., `actions/checkout@v3`) are a supply chain attack vector. If a tag is moved, whether by a compromised maintainer, a hijacked repository, or a forced push, every workflow using that tag silently pulls different code on the next run.

Pinning actions to full commit SHAs ensures CI/CD pipelines execute exactly the code that was reviewed, not whatever a tag happens to point to today.

## Usage

```bash
# Pin all GitHub Actions in a repository's workflows
vet scan -D .github/workflows --enrich=false --github-actions-pin

# Pin actions in a specific workflow file
vet scan -L .github/workflows/ci.yml --lockfile-as github-actions-workflow --enrich=false --github-actions-pin
```

The `--enrich=false` flag skips vulnerability and metadata enrichment, making the pinning operation fast since it only needs the GitHub API to resolve tags.

## What It Does

1. Each GitHub Actions workflow YAML file is parsed using an AST-aware parser
2. All `uses:` references with mutable tags (e.g., `v3`, `main`) are identified
3. Each tag is resolved to its current commit SHA via the GitHub API
4. The tag is replaced with the SHA in-place, and an inline comment with the original tag is added

### Before

```yaml
steps:
  - uses: actions/checkout@v3
  - uses: actions/setup-go@v4
```

### After

```yaml
steps:
  - uses: actions/checkout@f43a0e5ff2bd294095638e18286ca9a3d1956744 # v3
  - uses: actions/setup-go@7b8cf10d4e4a01d4992d18a89f4d7dc5a3e6d6f4 # v4
```

## Behavior

- **Lossless YAML**: Comments, formatting, and structure are preserved
- **Already-pinned actions are skipped**: Actions referencing a 40-character hex SHA are left untouched
- **Non-GHA manifests are ignored**: When scanning a directory with mixed ecosystems, only GitHub Actions workflow files are modified
- **Best-effort**: If a tag cannot be resolved (e.g., private repo without credentials, deleted tag), the action is skipped with a warning and the rest of the file is still processed
- **Subpath actions supported**: Actions like `aws-actions/configure-aws-credentials/assume-role@v2` are handled correctly

## GitHub Authentication

Tag resolution uses the GitHub API. For public repositories, unauthenticated requests work but are rate-limited (60 requests/hour). A `GITHUB_TOKEN` should be set for higher limits:

```bash
export GITHUB_TOKEN=ghp_...
vet scan -D .github/workflows --enrich=false --github-actions-pin
```
