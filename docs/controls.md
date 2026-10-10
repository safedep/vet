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

The table and the [control reference](#control-reference) come from the code. Each control id links
to its section.

<!-- controls:table:start -->

| Control | Family | Default severity | Finds |
| --- | --- | --- | --- |
| [`editor-task-command`](#editor-task-command) | agent-config | medium | Editor task runs a command |
| [`agent-hook-command`](#agent-hook-command) | agent-config | medium | Agent or git hook runs a command |
| [`mcp-server-added`](#mcp-server-added) | agent-config | medium | MCP server in an agent config |
| [`agent-instruction-change`](#agent-instruction-change) | agent-config | info | Agent instruction file |
| [`suspicious-command`](#suspicious-command) | agent-config | critical | Suspicious command in an agent or editor config |
| [`editor-autorun-enabled`](#editor-autorun-enabled) | agent-config | high | Editor setting turns off a safety check |
| [`agent-config-unreadable`](#agent-config-unreadable) | agent-config | high | Agent or editor config that vet cannot read |
| [`dependency-cooldown`](#dependency-cooldown) | cooldown | high | Version inside the cooldown window |
| [`padded-code`](#padded-code) | hidden-code | critical | Script hidden after a run of spaces |
| [`disguised-script`](#disguised-script) | hidden-code | critical | Script in a font, image or dictionary file |
| [`unicode-payload`](#unicode-payload) | hidden-code | critical | Payload in invisible Unicode characters |
| [`invisible-unicode`](#invisible-unicode) | hidden-code | high | Invisible Unicode characters |
| [`history-rewrite-script`](#history-rewrite-script) | hidden-code | critical | Script that rewrites the git history |
| [`install-scripts-added`](#install-scripts-added) | hygiene | high | New dependency with install scripts |
| [`provenance-lost`](#provenance-lost) | hygiene | medium | Provenance lost on an upgrade |
| [`deprecated-package`](#deprecated-package) | hygiene | medium | Deprecated package |
| [`license-change`](#license-change) | license | medium | License change on an upgrade |
| [`license-relicensed`](#license-relicensed) | license | high | Relicensed to a license that limits use |
| [`non-registry-dependency`](#non-registry-dependency) | hygiene | medium | Dependency that is not on a registry |
| [`scorecard-low`](#scorecard-low) | hygiene | info | Low OpenSSF Scorecard |
| [`license-denied`](#license-denied) | license | high | Denied license |
| [`license-not-allowed`](#license-not-allowed) | license | medium | License not in the allow list |
| [`license-unknown`](#license-unknown) | license | low | Unknown license |
| [`untrusted-registry`](#untrusted-registry) | lockfile | high | Lockfile entry from an untrusted registry |
| [`registry-path-mismatch`](#registry-path-mismatch) | lockfile | high | Lockfile entry with a URL of another package |
| [`integrity-changed`](#integrity-changed) | lockfile | high | Lockfile integrity hash changed with no version change |
| [`lockfile-only-change`](#lockfile-only-change) | lockfile | high | Lockfile change with no manifest change |
| [`installed-not-locked`](#installed-not-locked) | lockfile | medium | Installed package that the lockfile does not list |
| [`malware`](#malware) | malware | critical | Malicious package |
| [`suspicious-package`](#suspicious-package) | malware | high | Suspicious package |
| [`typosquat`](#typosquat) | reputation | high | Typosquat of a popular package |
| [`new-unpopular-package`](#new-unpopular-package) | reputation | medium | New and unpopular package |
| [`version-anomaly`](#version-anomaly) | reputation | medium | Version anomaly on an upgrade |
| [`starjacking`](#starjacking) | reputation | medium | Package that claims a popular repository |
| [`dependency-confusion`](#dependency-confusion) | reputation | medium | Internal package name on a public registry |
| [`ai-bom-delta`](#ai-bom-delta) | ai-bom | medium | New AI capability |
| [`vulnerability`](#vulnerability) | vulnerability | high | Known vulnerability |
| [`dangerous-trigger`](#dangerous-trigger) | workflow | high | Dangerous workflow trigger |
| [`template-injection`](#template-injection) | workflow | high | Workflow template injection |
| [`unpinned-action`](#unpinned-action) | workflow | medium | Action not pinned to a commit SHA |
| [`impostor-commit`](#impostor-commit) | workflow | critical | Action pinned to a commit outside its repository |
| [`pin-comment-mismatch`](#pin-comment-mismatch) | workflow | medium | Pin comment names another tag |
| [`excessive-permissions`](#excessive-permissions) | workflow | medium | Workflow with excessive permissions |
| [`secrets-exposure`](#secrets-exposure) | workflow | high | Secrets exposed to more code than needs them |
| [`github-env-injection`](#github-env-injection) | workflow | high | Untrusted write to GITHUB_ENV or GITHUB_PATH |
| [`cache-poisoning`](#cache-poisoning) | workflow | medium | Cache in a release or deploy workflow |
| [`artifact-poisoning`](#artifact-poisoning) | workflow | medium | Artifact download in a workflow_run workflow |
| [`self-hosted-runner`](#self-hosted-runner) | workflow | medium | Job on a self-hosted runner |
| [`spoofable-bot-condition`](#spoofable-bot-condition) | workflow | medium | Condition on a bot actor name |

<!-- controls:table:end -->

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
| `plugins.dependency-cooldown.options.days` | `2` | The cooldown window, the same default as pmg. `--cooldown-days N` sets it for one scan |
| `plugins.dependency-cooldown.options.skip` | none | The packages that the cooldown does not check, each with a `purl` and a `reason`. A PURL with no version skips each version, and a name glob such as `pkg:golang/buf.build/gen/go/acme/*` works. Other controls still check the packages |
| `plugins.lockfile.options.trusted_registries` | none | The registry URLs that `untrusted-registry` trusts, in addition to the public registries |
| `plugins.reputation.options.internal_names` | none | The names of your private packages, for `dependency-confusion`. Globs such as `acme-*` work |
| `plugins.reputation.options.new_package_days` | `30` | The age under which `new-unpopular-package` reports a package |
| `plugins.reputation.options.min_downloads` | `1000` | The download count under which a package is unpopular |
| `plugins.hygiene.options.min_scorecard` | `3` | The OpenSSF Scorecard score under which `scorecard-low` reports a package |
| `plugins.malware.options.trust_automated_analysis` | `false` | Report an unverified malicious verdict as `malware`, not `suspicious-package` |
| `plugins.malware.options.minimum_confidence` | `high` | The lowest confidence of an unverified verdict that vet reports as `malware` |
| `plugins.workflow.options.allow_unpinned` | none | The actions that `unpinned-action` accepts with a tag |
| `plugins.actionrefs.options.max_calls` | `50`, `500` with a token | The GitHub API calls that `impostor-commit` makes for one repository in a scan |
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
  cannot decide it, so it is unknown. `NONE` beside a license id does not change the verdict of the
  id.
- `scope: runtime` skips the dev dependencies. `scope: direct` checks only the direct dependencies.
  The dependencies of an npm workspace member are direct. When a manifest does not mark its direct
  dependencies, vet checks all its packages.
- `license-relicensed` (from the hygiene control) reports an upgrade that moves to a license that
  limits the use of the code, or to `NONE`. These licenses are source available (`SSPL-1.0`,
  `BUSL-1.1`, `Elastic-2.0`), allow no commercial use (`CC-BY-NC-*`, `PolyForm-Noncommercial-1.0.0`,
  `PolyForm-Small-Business-1.0.0`) or allow no derived works (`CC-BY-ND-*`). Each choice of the
  expression must have one. Other license changes are `license-change`.

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

## Pinned commits

GitHub serves each commit of a fork network through each repository of the network. In
`uses: actions/checkout@<sha>`, the SHA can come from a fork that an attacker controls, and GitHub
runs it as `actions/checkout`. The `actionrefs` enricher checks each action pinned to a commit. It
finds a branch or a tag of the named repository that contains the commit, cheapest first: a tag
that points to the commit, the default branch, then each other branch and tag.

- vet sends the `owner/repo` and the SHA to the GitHub API at `github.api_url`, and nowhere else.
- vet reads the token from `GITHUB_TOKEN`, then `GH_TOKEN`, then `gh auth token`. With no token, vet
  calls GitHub anonymously, with 60 calls an hour. A repository with about 20 pinned actions needs a
  token. `vet doctor` shows the source of the token.
- In GitHub Actions, the runner does not set the `GITHUB_TOKEN` variable. Set it on the step that
  runs vet:

  ```yaml
  - run: vet scan .
    env:
      GITHUB_TOKEN: ${{ github.token }}
  ```

- `plugins.actionrefs.options.max_calls` bounds the calls for one repository. The default is 50
  with no token and 500 with a token. A legitimate pin needs a few calls. An impostor commit needs a
  compare with each distinct commit of the branches and the tags.
- A rate limit, an API error or a spent budget gives a warning and no finding. vet never reports an
  impostor commit from a partial check.
- `pin-comment-mismatch` checks only a full release tag, such as `v4.2.0`. The owner of an action
  moves a major or a minor tag, such as `v4`, to each new release.
- `plugins.actionrefs.enabled: false` turns off the check.

## Fix workflow findings

`vet fix github-actions run` pins each third-party action to its commit SHA, and keeps the tag in a
comment. See [fix-github-actions-run.md](cmd/fix-github-actions-run.md).

## Control reference

<!-- controls:reference:start -->

### editor-task-command

**Editor task runs a command.** Family `agent-config`. Default severity medium. Plugin `agent-config`.

An editor task runs a shell command on the machine of each developer who opens the folder. A task with runOn: folderOpen runs with no click, so its severity is high.

### agent-hook-command

**Agent or git hook runs a command.** Family `agent-config`. Default severity medium. Plugin `agent-config`.

A coding agent hook, a devcontainer lifecycle command or a git hook runs a command on the machine of each developer.

### mcp-server-added

**MCP server in an agent config.** Family `agent-config`. Default severity medium. Plugin `agent-config`.

An MCP config gives the coding agent a server to run or to call. The agent sends it the data of the project.

### agent-instruction-change

**Agent instruction file.** Family `agent-config`. Default severity info. Plugin `agent-config`.

An instruction file tells a coding agent what to do in the project. Review it like code: it can tell the agent to run commands.

### suspicious-command

**Suspicious command in an agent or editor config.** Family `agent-config`. Default severity critical. Plugin `agent-config`. The attacks gate fails on it.

A command that an editor, an agent or a git hook runs looks malicious: it runs a downloaded script, decodes a payload or reads credentials.

### editor-autorun-enabled

**Editor setting turns off a safety check.** Family `agent-config`. Default severity high. Plugin `agent-config`.

A setting lets tasks run with no prompt, hides the terminal of a task, or turns off workspace trust. An attacker sets it so that a folder-open task runs unseen.

### agent-config-unreadable

**Agent or editor config that vet cannot read.** Family `agent-config`. Default severity high. Plugin `agent-config`.

vet cannot parse the file, or the file is too large to read, so vet cannot check what it runs. An editor or an agent can still run it, and an attacker can break or pad a file to hide a command.

### dependency-cooldown

**Version inside the cooldown window.** Family `cooldown`. Default severity high. Plugin `dependency-cooldown`.

The registry published the version less than the cooldown window ago. Most malicious versions are found and removed in the first days.

### padded-code

**Script hidden after a run of spaces.** Family `hidden-code`. Default severity critical. Plugin `hidden-code`. The attacks gate fails on it.

A source file, a build config or an npm entry script holds a script after a long run of white space, so an editor shows a clean line. A config can also hide it after its export. A build config runs at each build, test or lint, and an npm entry script at each npm command. An npm entry script that is far larger than the published file is also a finding. PolinRider adds its loader in these ways.

### disguised-script

**Script in a font, image or dictionary file.** Family `hidden-code`. Default severity critical. Plugin `hidden-code`. The attacks gate fails on it.

A file with the name of a font, an image or a dictionary holds a script. A task or a loader runs it with node, so the folder looks like it holds only assets. Contagious Interview repositories ship such a fake font.

### unicode-payload

**Payload in invisible Unicode characters.** Family `hidden-code`. Default severity critical. Plugin `hidden-code`. The attacks gate fails on it.

A file holds 16 or more variation selectors with no base character, or tag characters outside a flag emoji. Each one carries one byte of a payload, and an editor and a code review show nothing. Real text holds none. GlassWorm spreads this way, with the decoder in the same file or in another one.

### invisible-unicode

**Invisible Unicode characters.** Family `hidden-code`. Default severity high. Plugin `hidden-code`.

A file holds a run of invisible characters, or code holds a bidirectional control. They can hide text from a reviewer, hide instructions from a person who reads an agent file, or show code in another order than the compiler reads it.

### history-rewrite-script

**Script that rewrites the git history.** Family `hidden-code`. Default severity critical. Plugin `hidden-code`. The attacks gate fails on it.

A script amends the last commit with no hooks, keeps its date, and force-pushes it, or .gitignore hides such a script. PolinRider uses it to fold its change into the last real commit of each repository on an infected machine, so the history shows no new commit.

### install-scripts-added

**New dependency with install scripts.** Family `hygiene`. Default severity high. Plugin `hygiene`.

The change adds or upgrades a package that runs a preinstall, install or postinstall script. The script runs on each machine that installs the package.

### provenance-lost

**Provenance lost on an upgrade.** Family `hygiene`. Default severity medium. Plugin `hygiene`.

The previous version has a SLSA provenance attestation and the new version has none. The new version may not come from the build system of the project.

### deprecated-package

**Deprecated package.** Family `hygiene`. Default severity medium. Plugin `hygiene`.

The registry marks the package version deprecated. It gets no fixes.

### license-change

**License change on an upgrade.** Family `license`. Default severity medium. Plugin `hygiene`.

The new version has a license other than the license of the previous version.

### license-relicensed

**Relicensed to a license that limits use.** Family `license`. Default severity high. Plugin `hygiene`.

The new version moves to a license that limits the use of the code (source available, no commercial use or no derived works, such as SSPL-1.0, BUSL-1.1 or CC-BY-NC-4.0), or to no license.

### non-registry-dependency

**Dependency that is not on a registry.** Family `hygiene`. Default severity medium. Plugin `hygiene`.

A dependency comes from git, a URL or a file path, or takes any version. No registry checks it, and it can change with no new version.

### scorecard-low

**Low OpenSSF Scorecard.** Family `hygiene`. Default severity info. Plugin `hygiene`.

The source repository of the package has a low OpenSSF Scorecard score. vet shows it for review.

### license-denied

**Denied license.** Family `license`. Default severity high. Plugin `license`.

Each choice of the license of the package has a license that plugins.license.options.deny names.

### license-not-allowed

**License not in the allow list.** Family `license`. Default severity medium. Plugin `license`.

The licenses that plugins.license.options.allow names do not satisfy the license of the package.

### license-unknown

**Unknown license.** Family `license`. Default severity low. Plugin `license`.

The package has no license data, a license that is not an SPDX license expression, or no license (NONE) with only a deny list. The lists cannot decide it.

### untrusted-registry

**Lockfile entry from an untrusted registry.** Family `lockfile`. Default severity high. Plugin `lockfile`.

A lockfile entry resolves from a host that is not a trusted registry. An attacker can edit a lockfile to install code from a host they control.

### registry-path-mismatch

**Lockfile entry with a URL of another package.** Family `lockfile`. Default severity high. Plugin `lockfile`.

The resolved URL of a lockfile entry does not match the package name. An attacker can edit a lockfile to install another package under a trusted name.

### integrity-changed

**Lockfile integrity hash changed with no version change.** Family `lockfile`. Default severity high. Plugin `lockfile`.

The change keeps the version of a lockfile entry and changes its integrity hash. The lockfile now installs other code under the same name and version.

### lockfile-only-change

**Lockfile change with no manifest change.** Family `lockfile`. Default severity high. Plugin `lockfile`.

The change edits a lockfile and leaves the manifest file next to it as it was. A tool such as npm update makes this change, and so does an attacker who edits the lockfile by hand.

### installed-not-locked

**Installed package that the lockfile does not list.** Family `lockfile`. Default severity medium. Plugin `lockfile`.

node_modules holds a package, or a version of a package, that the lockfile of the project does not list. A stale install gives this result, and so does a package that someone added to node_modules by hand.

### malware

**Malicious package.** Family `malware`. Default severity critical. Plugin `malware`. The attacks gate fails on it.

SafeDep Threat Intel found malicious behavior in the package version, and a verification confirms it.

### suspicious-package

**Suspicious package.** Family `malware`. Default severity high. Plugin `malware`.

The automated analysis of SafeDep Threat Intel marks the package version malicious. No verification confirms it.

### typosquat

**Typosquat of a popular package.** Family `reputation`. Default severity high. Plugin `reputation`.

The name is one typo away from a popular package, and few people install it. Attackers publish such names to catch a typo.

### new-unpopular-package

**New and unpopular package.** Family `reputation`. Default severity medium. Plugin `reputation`.

The first version of the package is recent, and few people install it. Nobody has had time to review it.

### version-anomaly

**Version anomaly on an upgrade.** Family `reputation`. Default severity medium. Plugin `reputation`.

The upgrade jumps two or more major versions, or the new version is older than the previous one. A takeover often publishes such a version.

### starjacking

**Package that claims a popular repository.** Family `reputation`. Default severity medium. Plugin `reputation`.

The package names a popular source repository, and few people install it. The repository may not belong to the publisher.

### dependency-confusion

**Internal package name on a public registry.** Family `reputation`. Default severity medium. Plugin `reputation`.

The name matches an internal package name, and the package comes from a public registry. An attacker can publish a public package with the name of an internal one.

### ai-bom-delta

**New AI capability.** Family `ai-bom`. Default severity medium. Plugin `reputation`.

The change adds an LLM provider SDK, an agent framework or an MCP library, or code that calls one.

### vulnerability

**Known vulnerability.** Family `vulnerability`. Default severity high. Plugin `vulnerability`.

An advisory affects the package version. The finding has the severity of the advisory.

### dangerous-trigger

**Dangerous workflow trigger.** Family `workflow`. Default severity high. Plugin `workflow`.

A pull_request_target or workflow_run workflow checks out the code of the pull request. That code runs with the secrets and the write token of the base repository.

### template-injection

**Workflow template injection.** Family `workflow`. Default severity high. Plugin `workflow`.

A script interpolates an event field that an outside user controls, such as the title of a pull request. The user can run commands in the workflow.

### unpinned-action

**Action not pinned to a commit SHA.** Family `workflow`. Default severity medium. Plugin `workflow`.

A step uses an action by a tag or a branch. The owner of the action, or an attacker who controls it, can move the tag to other code.

### impostor-commit

**Action pinned to a commit outside its repository.** Family `workflow`. Default severity critical. Plugin `workflow`. The attacks gate fails on it.

A step pins an action to a commit that no branch and no tag of the named repository contains. GitHub serves each commit of a fork through the repository, so the commit can come from a fork that an attacker controls.

### pin-comment-mismatch

**Pin comment names another tag.** Family `workflow`. Default severity medium. Plugin `workflow`.

A step pins an action to a commit, and the comment names a release tag that does not point to that commit. A reviewer who reads the comment expects other code than the code that runs.

### excessive-permissions

**Workflow with excessive permissions.** Family `workflow`. Default severity medium. Plugin `workflow`.

The workflow sets no permissions, so its token gets the default permissions of the repository, or it asks for write-all. A step that an attacker controls can then write to the repository.

### secrets-exposure

**Secrets exposed to more code than needs them.** Family `workflow`. Default severity high. Plugin `workflow`.

The workflow passes every secret to a reusable workflow with secrets: inherit, dumps them with toJSON(secrets), or puts a secret in a script. A step that prints or leaks the script leaks the secret.

### github-env-injection

**Untrusted write to GITHUB_ENV or GITHUB_PATH.** Family `workflow`. Default severity high. Plugin `workflow`.

A script writes to GITHUB_ENV or GITHUB_PATH in a workflow that handles the input of an outside user. The user can set an environment variable or a path, such as LD_PRELOAD, for the next steps.

### cache-poisoning

**Cache in a release or deploy workflow.** Family `workflow`. Default severity medium. Plugin `workflow`.

A release or deploy job restores a cache. A pull request workflow can write a poisoned cache, and the release then builds with it.

### artifact-poisoning

**Artifact download in a workflow_run workflow.** Family `workflow`. Default severity medium. Plugin `workflow`.

A workflow_run workflow downloads an artifact of the triggering run. A pull request controls that artifact, and the privileged workflow uses it.

### self-hosted-runner

**Job on a self-hosted runner.** Family `workflow`. Default severity medium. Plugin `workflow`.

A job runs on a self-hosted runner. In a public repository, a pull request from a fork can run code on the runner and keep a foothold on it.

### spoofable-bot-condition

**Condition on a bot actor name.** Family `workflow`. Default severity medium. Plugin `workflow`.

A condition trusts the actor name of a bot, such as dependabot[bot]. github.actor is the last actor of the run, and a user can make the bot the actor of a run that the user controls.

<!-- controls:reference:end -->
