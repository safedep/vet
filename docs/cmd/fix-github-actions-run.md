# vet fix github-actions run

Pin third-party GitHub Actions to commit SHAs.

## Synopsis

```text
vet fix github-actions run [DIR] [--dry-run] [-o table|plain|json|jsonl]
```

## Description

`vet fix github-actions run` pins each third-party action that a workflow under
`.github/workflows/` or a composite action under `.github/actions/` uses by a tag or a branch. vet
resolves the ref to its commit SHA with the GitHub API, writes the SHA, and keeps the ref in a
comment:

```text
- uses: actions/checkout@v4
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4
```

These stay as they are: local actions (`./path`), Docker images, the actions of the same
repository (from the `origin` remote), expressions, and actions that a SHA already pins. vet edits
only the `uses:` value, so each file keeps its format, its comments and its line ends. It writes a
file through a temporary file and a rename.

vet calls the GitHub API with `GITHUB_TOKEN`, or with the token of the `gh` CLI when one exists, and
without a token otherwise. The `github.api_url` config key sets another API address.

`--dry-run` prints a diff and writes nothing. The `unpinned-action` control of `vet scan` finds the
same actions, and its fix names this command. A scan never writes the repository.

## Examples

```text
vet fix github-actions run --dry-run
vet fix github-actions run
vet fix github-actions run ./service -o json
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | vet pinned every action, or there was nothing to pin. |
| 2 | A flag is not valid. |
| 3 | vet could not resolve one or more actions, or could not write a file. vet pins and writes the others. |
