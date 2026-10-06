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
[CI](../ci.md) shows how to run vet there. DIR must be the root of the git repository, because
GitHub reads `.github` only there. When the release tag names another commit than the commit of the
running vet, the command fails.

**Dependabot.** vet adds a `github-actions` entry with a one day `cooldown` to
`.github/dependabot.yml`, or to `.github/dependabot.yaml` when that file exists. Dependabot then
moves the pins one day after each release:

- When the file does not exist, vet writes it.
- When the file has a `github-actions` entry, vet leaves the file as it is.
- vet adds the entry only as new lines at the end of `updates:`, and checks that each setting of the
  file stays the same. When it cannot, it prints the entry for you to add.
- A repository with a Renovate config gets no entry.

`--policy` also writes `.github/vet/policy.yml` with the starter rules of `vet policy init`. The
action applies this file. vet keeps a policy file that exists.

`--force` replaces the workflow file and the policy file when they exist. vet writes each file
through a temporary file and a rename, and never through a symbolic link. `--dry-run` prints the
diff and writes nothing. vet commits nothing. It prints the `git` commands, the required check
advice and a badge line.

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
| 2 | The workflow file exists, the repository is not on GitHub, DIR is not the root of the repository, vet is a development build, or a flag is not valid. |
| 3 | The GitHub API failed, the release tag names another commit, actions/checkout has no release older than 24 hours, or vet could not write a file. |
