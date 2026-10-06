# vet ci update

Move the action pins of the vet workflow.

## Synopsis

```text
vet ci update [DIR] [--dry-run]
```

## Description

`vet ci update` moves the `safedep/vet` and `actions/checkout` pins in `.github/workflows/vet.yml`
to the newest release that is older than 24 hours:

- For vet, it takes the newest immutable stable v2 release. While v2 has no stable release, it takes
  the newest pre-release.
- For `actions/checkout`, it stays in the major version of the pin.
- vet reads the current version from the tag comment of each pin. A pin never moves to an older
  release.

vet edits only the `uses:` lines of the two actions. The new tag becomes the comment of the line.
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
| 2 | The workflow file does not exist, is not valid YAML or has no `safedep/vet` pin with a tag comment, or a flag is not valid. |
| 3 | The GitHub API failed, or vet could not write the file. |
