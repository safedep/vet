# vet ci update

Move the action pins of the vet workflow.

## Synopsis

```text
vet ci update [DIR] [--dry-run]
```

## Description

`vet ci update` moves the `safedep/vet` and `actions/checkout` pins in `.github/workflows/vet.yml`
to the newest release that is older than 24 hours. For vet, it takes the newest immutable stable v2
release, or a pre-release while v2 has no stable release.

vet edits only the `uses:` lines of the two actions. The new tag replaces the old tag in the comment.
Each other line stays as it is. The command does not change other actions or other workflow files.

Use it when Dependabot or Renovate does not move the pins. `vet ci init` sets up Dependabot to do it.
`--dry-run` prints the diff and writes nothing.

## Examples

```text
vet ci update --dry-run
vet ci update
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | vet moved the pins, or they are up to date. |
| 2 | The workflow file does not exist, or a flag is not valid. |
| 3 | vet could not reach the GitHub API or could not write the file. |
