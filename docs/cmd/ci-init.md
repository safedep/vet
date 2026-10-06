# vet ci init

Add the vet workflow to a repository.

## Synopsis

```text
vet ci init [DIR] [--policy] [--force] [--dry-run]
```

## Description

`vet ci init` writes `.github/workflows/vet.yml`. The workflow runs the vet GitHub Action on each
pull request. [The GitHub Action](../github-action.md) describes what the action does.

vet pins two actions to a full commit SHA, with the tag in a comment:

- `safedep/vet` at the release of the vet that runs the command. A development build of vet has no
  release, so the command fails.
- `actions/checkout` at its newest release that is older than 24 hours.

vet finds the commits with the GitHub API, with `GITHUB_TOKEN` or the token of the `gh` CLI when one
exists.

vet knows the CI platform of the repository. A repository with a `github.com` origin remote or a
`.github` directory gets the GitHub Actions workflow. On another platform the command fails, and
[CI](../ci.md) shows how to run vet there.

**Dependabot.** vet adds a `github-actions` entry with a one day `cooldown` to
`.github/dependabot.yml`, so Dependabot moves the pins one day after each release:

- When the file does not exist, vet writes it.
- When the file has a `github-actions` entry for `/`, vet leaves the file as it is.
- vet adds the entry only as new lines at the end of `updates:`. It never changes a line of the file.
  When it cannot, it prints the entry for you to add.
- A repository with a Renovate config gets no entry.

`--policy` also writes `.github/vet/policy.yml` with the starter rules of `vet policy init`. The
action applies this file. vet keeps a policy file that exists.

`--force` replaces the workflow file and the policy file when they exist. `--dry-run` prints the diff
and writes nothing. vet commits nothing. It prints the `git` commands, the required check advice and
a badge line.

## Examples

```text
vet ci init --dry-run
vet ci init
vet ci init --policy
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | vet wrote the files, or printed the diff. |
| 2 | The workflow file exists, the repository is not on GitHub, vet is a development build, or a flag is not valid. |
| 3 | vet could not reach the GitHub API or could not write a file. |
