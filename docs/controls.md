# Controls

A control turns the data about a package, a workflow or an agent config into findings. Each
finding has the id of its control, a family and a severity. A policy rule reads them as
`finding.control_id`, `finding.family` and `finding.severity`. See [policy.md](policy.md).

`vet policy control list` prints the controls of your build:

```bash
vet policy control list
vet policy control list -o json
```

## All controls

| Control | Family | Default severity | Finds |
| --- | --- | --- | --- |
| `malware` | malware | critical | A malicious package |
| `suspicious-package` | malware | high | A package that the analysis marks suspicious |
| `vulnerability` | vulnerability | from the advisory | A known vulnerability |
| `dependency-cooldown` | cooldown | high | A version that the registry published in the cooldown window (5 days) |
| `untrusted-registry` | lockfile | high | A lockfile entry (npm, yarn, pnpm, bun, uv, Cargo) from an untrusted registry |
| `registry-path-mismatch` | lockfile | high | A lockfile entry with the URL of another package |
| `integrity-changed` | lockfile | high | In pull request mode, a lockfile entry whose hash changes with no version change |
| `lockfile-only-change` | lockfile | high | In pull request mode, a lockfile change with no change to the manifest file next to it |
| `install-scripts-added` | hygiene | high | In pull request mode, a new or upgraded npm package that runs install scripts |
| `provenance-lost` | hygiene | medium | An upgrade to a version with no SLSA provenance, when the previous version had one |
| `deprecated-package` | hygiene | medium | A version that the registry marks deprecated |
| `license-change` | license | medium | An upgrade that changes the license |
| `non-registry-dependency` | hygiene | medium | A dependency on git, a URL, a file or any version |
| `scorecard-low` | hygiene | info | A package whose repository has an OpenSSF Scorecard score under 3 |
| `typosquat` | reputation | high | A name one typo away from a popular package, with few downloads |
| `new-unpopular-package` | reputation | medium | A package whose first version is under 30 days old, with under 1000 downloads |
| `version-anomaly` | reputation | medium | An upgrade that jumps two major versions, or to a version older than the previous one |
| `starjacking` | reputation | medium | A package that claims a popular repository and has almost no downloads |
| `dependency-confusion` | reputation | medium | A package that matches `internal_names` and comes from a public registry |
| `ai-bom-delta` | ai-bom | medium | In pull request mode, a new LLM SDK, agent framework or MCP library |
| `dangerous-trigger` | workflow | high | A `pull_request_target` or `workflow_run` workflow that checks out untrusted code |
| `template-injection` | workflow | high | An untrusted expression inside a `run:` script |
| `unpinned-action` | workflow | medium | A third-party action that a tag or a branch selects |
| `excessive-permissions` | workflow | medium | A workflow with no permissions or with write-all |
| `secrets-exposure` | workflow | high | `secrets: inherit`, `toJSON(secrets)` or a secret in a script |
| `github-env-injection` | workflow | high | A write to `GITHUB_ENV` or `GITHUB_PATH` with input that an outside user controls |
| `cache-poisoning` | workflow | medium | A cache in a release or deploy job |
| `artifact-poisoning` | workflow | medium | An artifact download in a `workflow_run` workflow |
| `self-hosted-runner` | workflow | medium | A job on a self-hosted runner |
| `spoofable-bot-condition` | workflow | medium | A condition on the actor name of a bot |
| `editor-task-command` | agent-config | medium, high on folder open | A `.vscode/tasks.json` task that runs a shell command |
| `agent-hook-command` | agent-config | medium | A Claude Code hook, a devcontainer lifecycle command or a git hook |
| `mcp-server-added` | agent-config | medium | An MCP server in an agent or editor config |
| `agent-instruction-change` | agent-config | info | An agent instruction file such as `CLAUDE.md` or `.cursorrules` |
| `suspicious-command` | agent-config | critical | A command in those files that runs a downloaded script, decodes a payload or reads credentials |

## Pull request mode

`vet scan --base-ref REF` compares the target with a git ref. vet reports only the findings of the
packages and the workflows that the change adds or modifies. Some controls run only in this mode,
because they need the base: `integrity-changed`, `lockfile-only-change`, `install-scripts-added`
and `ai-bom-delta`.

## Options

Some controls take options from the config file, under `plugins.<name>.options`.
`vet config schema get` prints all of them.

| Config key | Default | Effect |
| --- | --- | --- |
| `plugins.dependency-cooldown.options.days` | `5` | The cooldown window. `--cooldown-days N` sets it for one scan |
| `plugins.lockfile.options.trusted_registries` | none | The registry URLs that `untrusted-registry` trusts, in addition to the public registries |
| `plugins.reputation.options.internal_names` | none | The names of your private packages, for `dependency-confusion`. Globs such as `acme-*` work |
| `plugins.reputation.options.new_package_days` | `30` | The age under which `new-unpopular-package` reports a package |
| `plugins.reputation.options.min_downloads` | `1000` | The download count under which a package is unpopular |
| `plugins.hygiene.options.min_scorecard` | `3` | The OpenSSF Scorecard score under which `scorecard-low` reports a package |
| `plugins.malware.options.trust_automated_analysis` | `false` | Report an unverified malicious verdict as `malware`, not `suspicious-package` |
| `plugins.malware.options.minimum_confidence` | `high` | The lowest confidence of an unverified verdict that vet reports as `malware` |
| `plugins.workflow.options.allow_unpinned` | none | The actions that `unpinned-action` accepts with a tag |

```bash
vet config set plugins.reputation.options.internal_names '["acme-*"]'
```

## Fix workflow findings

`vet fix github-actions run` pins each third-party action to its commit SHA, and keeps the tag in a
comment. See [fix-github-actions-run.md](cmd/fix-github-actions-run.md).
