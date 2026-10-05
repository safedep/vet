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
| `license-relicensed` | license | high | An upgrade from an OSI or FSF license to a known license that is neither, such as SSPL-1.0, BUSL-1.1 or `NONE` |
| `license-denied` | license | high | A license that `plugins.license.options.deny` names, in each choice of the license expression |
| `license-not-allowed` | license | medium | A license that `plugins.license.options.allow` does not satisfy |
| `license-unknown` | license | low | A package with no license data, a license that is not an SPDX expression, or `NONE` with only a deny list. Reported when a list is set, unless `unknown: ignore` |
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
| `plugins.license.options.allow` | none | The licenses that a package can have. See [License lists](#license-lists) |
| `plugins.license.options.deny` | none | The licenses that a package cannot have |
| `plugins.license.options.unknown` | `report` | `report` or `ignore` a package with no SPDX license |
| `plugins.license.options.scope` | `all` | The packages to check: `all`, `runtime` (no dev dependencies) or `direct` |

```bash
vet config set plugins.reputation.options.internal_names '["acme-*"]'
```

## License lists

The license control checks the license of each package against two lists. It reads the license from
SafeDep Insights as an SPDX license expression, and it follows the SPDX specification (SPDX 2.3
Annex D):

- **allow**: a package passes when the list satisfies its expression. `MIT OR GPL-3.0-only` passes
  `allow: [MIT]`. `MIT AND GPL-3.0-only` does not.
- **deny**: a package fails when each choice of its expression has a denied license. `MIT OR
  GPL-3.0-only` passes `deny: [GPL-3.0-only]`, because you can take MIT.
- The deny list goes first. A package with more than one license value gets the values joined with
  `AND`.
- An entry is an SPDX license id, an `id WITH exception` term or a `LicenseRef-` id. An entry
  matches one license exactly. Ids and operators match in any case. A deprecated id maps to the
  successor that SPDX names, so `GPL-3.0` means `GPL-3.0-only`.
- A `WITH` term is a license of its own. `GPL-2.0-only` does not match `GPL-2.0-only WITH
  Classpath-exception-2.0`, and the sets do not hold `WITH` terms.
- An or-later license, such as `GPL-2.0-or-later` or `EUPL-1.1+`, lets you take that version or a
  later one. An allow list passes it when the list has one of those versions. A deny list fails it
  when the list has each of those versions, or the or-later id itself.
- An entry can also name a set from the flags of the SPDX License List: `osi-approved`, `fsf-libre`
  or `osi-approved-or-fsf-libre`.
- vet rejects an entry that is not SPDX, so a typo cannot pass a package. There are no globs.
- `NOASSERTION`, free text and a package with no license data are unknown. vet reports them as
  `license-unknown` when a list is set. Set `unknown: ignore` to stop this. A known license value
  that fails a list fails the package, even with an unknown value beside it.
- `NONE` means no license, so the author keeps all rights. It fails an allow list. A deny list alone
  cannot decide it, so it is unknown.
- `scope: runtime` skips the dev dependencies. `scope: direct` checks only the direct dependencies.
  When a manifest does not mark its direct dependencies, vet checks all its packages.
- `license-relicensed` (from the hygiene control) reports an upgrade that moves from an OSI or FSF
  license to a known license that is neither, such as `SSPL-1.0`, `BUSL-1.1` or `NONE`.

```yaml
plugins:
  license:
    options:
      allow: [osi-approved]
      deny: [AGPL-3.0-only, AGPL-3.0-or-later, SSPL-1.0]
```

This deny list holds the common copyleft licenses, strong and weak. Copy the ids that your policy
needs:

```yaml
deny: [GPL-2.0-only, GPL-2.0-or-later, GPL-3.0-only, GPL-3.0-or-later,
       LGPL-2.1-only, LGPL-2.1-or-later, LGPL-3.0-only, LGPL-3.0-or-later,
       AGPL-3.0-only, AGPL-3.0-or-later, MPL-2.0, EUPL-1.2, SSPL-1.0]
```

The evidence of each finding names the SPDX License List version that decided it. A package that
SafeDep Insights does not know has no verdict.

## Fix workflow findings

`vet fix github-actions run` pins each third-party action to its commit SHA, and keeps the tag in a
comment. See [fix-github-actions-run.md](cmd/fix-github-actions-run.md).
