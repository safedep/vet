# The vet GitHub Action

The vet GitHub Action scans each pull request. When the change adds a package, a workflow or a
finding, the action posts one comment that says what the change adds. It fails the check when the
change adds an attack, such as a malicious package. The step summary holds the full report.

## Set up

Run `vet ci init` in the repository, or copy this file to `.github/workflows/vet.yml`:

```yaml
name: vet
on:
  pull_request:
permissions: {}
concurrency:
  group: vet-${{ github.event.pull_request.number || github.ref }}
  cancel-in-progress: true
jobs:
  vet:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with:
          persist-credentials: false
      - uses: safedep/vet@<commit SHA> # <release tag>
```

Pin the action to the full commit SHA of a release, with the tag in a comment. `vet ci init` writes
the pin of the vet that runs it. Do not use a tag or a branch such as `@v2` as the ref. vet's own
`unpinned-action` control reports such a ref.

`vet ci init` also adds a Dependabot entry with a one day cooldown, so Dependabot moves the pins. When
you use no Dependabot and no Renovate, run `vet ci update` and commit the diff.

Then, in the settings of the repository:

- Make the `vet` job a required check in the branch ruleset.
- Add `.github/workflows/` to CODEOWNERS. A pull request can edit its own workflow, so a maintainer
  must review each workflow change.

## Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `version` | `auto` | `auto`, `latest`, `latest-prerelease` or an exact v2 version such as `2.1.0` |
| `release-cooldown` | `24` | Hours that a vet release must age before `auto`, `latest` or `latest-prerelease` installs it. It applies to the vet binary |
| `package-cooldown` | empty | Days that a version of your packages must age before `dependency-cooldown` stops reporting it. Empty keeps the vet default of 2 days. It sets `plugins.dependency-cooldown.options.days` |
| `fail-on` | `attacks` | `attacks`, `none`, `critical`, `high`, `medium` or `low` |
| `policy` | `.github/vet/policy.yml` | The policy file. The action skips it when it does not exist |
| `comment` | `auto` | `auto`, `findings` or `never` |
| `comment-proxy` | `true` | Post the comment of a fork pull request through the SafeDep comment proxy |
| `sarif` | `false` | Write SARIF and upload it to code scanning. The job needs `security-events: write` |
| `config` | empty | The path of a vet config file in the repository, such as `.github/vet/config.yml` in the default setup. In a pull request, vet reads the file at the base commit |
| `args` | empty | More arguments for `vet scan`. The action splits them on white space |
| `github-token` | `${{ github.token }}` | The token for the releases, the comment and the GitHub checks of vet |

The action has two cooldowns for two different things:

- `release-cooldown` is the age of the **vet binary** that the action installs. It protects the
  job from a bad vet release.
- `package-cooldown` is the age of the **package versions** that your pull request adds. The
  `dependency-cooldown` control reports a version that is younger, as a `high` finding. The
  control only reports. A policy rule on `high` findings, or `fail-on: high`, blocks the change.

When the control and a cooldown rule in your policy disagree, each finding says what blocked it,
as "Blocked by policy rule critical-or-high".

To trust the packages of your own organization, skip them in the cooldown in the config file:

```yaml
# .github/vet/config.yml, with config: .github/vet/config.yml
plugins:
  dependency-cooldown:
    options:
      skip:
        - purl: pkg:golang/buf.build/gen/go/acme/*
          reason: Our own SDK, which we test on each release.
```

Or keep the finding in the report and hide it from the gate with a suppression in the policy:

```yaml
suppressions:
  - purl: pkg:golang/buf.build/gen/go/acme/*
    control: dependency-cooldown
    reason: Our own SDK, which we test on each release.
```

For a `pull_request` or `pull_request_target` event, the action reads the config file and the
policy at the base commit, so a pull request cannot turn off a control for its own scan. When the base
has no config file, the action warns and reads none. For a push or a merge queue, the action reads
both files from the checkout. The `config` path is a path in the repository, with no leading `/` and
no `..`.

A suppression with a name glob must name a `control`, so a glob never hides an attack such as
malware.

## Outputs

| Output | Meaning |
| --- | --- |
| `gate` | `pass`, `fail` or `none`. Empty when vet stops with an error |
| `findings` | The count of findings in the report |
| `report` | The path of the JSON report |
| `comment-url` | The URL of the comment, or empty |

## The gate

The default gate is the attacks gate. It fails on a finding of an attack control: `malware`,
`impostor-commit` or `suspicious-command`. Each other finding is in the comment, and does not fail
the check. Move to a stricter gate in steps:

| Step | Setting | What fails |
| --- | --- | --- |
| Observe | `fail-on: none` | Nothing. The comment and the summary show the findings |
| Attacks | the default | An attack |
| Policy | a policy file | An attack, and each finding that a `fail` rule of the policy matches |

`fail-on: none` adds no gate of its own. A gate that the workflow sets for vet, with `args` or the
`VET_POLICY_FAIL_ON` variable, still applies.

`vet policy init .github/vet/policy.yml` or `vet ci init --policy` writes a starter policy. See
[policy.md](policy.md).

In a pull request, vet reads the policy file at the base commit. So a pull request cannot loosen the
gate of its own check by an edit of the policy. vet prints a notice, and the comment says that the
gate used the base version. A developer tests a policy edit with `vet report show --policy FILE`.

A pull request that replaces a policy of vet v1 with a v2 policy at the same path gets no policy
gate, because the base version does not load. The attacks gate still applies. The comment says so,
and the v2 policy applies after the merge.

## The comment

vet keeps one comment on a pull request, and edits it on each push. The `comment` input sets when vet
posts it. The comment shows:

- a caution box for an attack, with what to do when a person or a CI run installed the package
- a warning box when a check did not complete, or when vet cannot read a file. The box leaves out a
  file that the change does not edit
- the blocking findings, with the fix and a link to the docs of the control
- the other findings in a collapsed section
- what the last push resolved, and what it added
- the policy snippet that accepts a finding
- a "Wrong result?" link to the [issue form](https://github.com/safedep/vet/issues/new?template=false-positive.yml)

`comment: auto` posts a comment when the change adds or upgrades a package or a workflow, or has a
finding. A change that only removes a package gets no new comment. `comment: findings` posts only when the change has a finding. `comment: never`
posts none. vet always edits a comment that exists, so a resolved finding shows.

Two vet steps on one pull request, such as one for each service of a monorepo, need a key each.
Set it in the env of the step:

```yaml
      - uses: safedep/vet@<commit SHA> # <release tag>
        with:
          args: services/api
        env:
          VET_PLUGINS_PR_COMMENT_OPTIONS_KEY: api
```

## Forks

The token of a pull request from a fork cannot write a comment. For a public repository, vet posts
the comment through the SafeDep comment proxy. The proxy posts it as the SafeDep app, and the footer
says so. vet sends the proxy the comment body, the repository, the pull request number, a tag and the
token of the run.

For a private repository, vet posts no comment from a fork run. The step summary and the job log have
the report. `comment-proxy: false` turns off the proxy for a public repository.

## How the action picks vet

The action code stays at the commit that you pin. The vet binary moves to the newest v2 release:

- `version: auto` follows the release channel of SafeDep vet: the pre-releases during the alpha, and
  the stable releases after it.
- `latest` takes the newest stable v2 release, and `latest-prerelease` the newest v2 release.
- An exact version, such as `2.1.0`, takes that release, with no release cooldown.

The action takes only an immutable v2 release that is older than the release cooldown. The age counts from
the latest of the publish time, the update time of each asset and the time of the build
attestation. A change to an old release makes it young again. Nothing in the vet repository can
shorten the release cooldown. Only your workflow file can, with `version` or `release-cooldown`.

The action checks the SHA-256 sum of the archive and its build attestation. The attestation must come
from the release workflow of vet v2 on a GitHub-hosted runner. A failed check fails the job, and the
action does not fall back to an older release.

When no release passes the release cooldown, the job fails and names the newest release and its
age. For an urgent fix, SafeDep publishes a security advisory that names the version to pin until
the fix passes the release cooldown.

The action needs `bash`, `gh`, `jq`, `tar` or `unzip`, and `sha256sum` or `shasum`. The GitHub-hosted
Linux, macOS and Windows runners have each of them.

## Push and schedule

On `push` and `schedule`, the action scans the full checkout and posts no comment. A weekly schedule
finds malware that SafeDep Threat Intel learns about after a merge:

```yaml
on:
  pull_request:
  schedule:
    - cron: "17 4 * * 1"
```

## SARIF

`sarif: true` uploads the findings to GitHub code scanning. The job needs `security-events: write`. A
private repository needs GitHub Advanced Security for code scanning. A failed upload prints a warning
and does not fail the job.

## Badge

```markdown
[![vet](https://github.com/OWNER/REPO/actions/workflows/vet.yml/badge.svg)](https://github.com/OWNER/REPO/actions/workflows/vet.yml)
```
