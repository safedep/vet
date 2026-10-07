# Policy

A policy decides when a scan fails. It is a YAML file with rules and suppressions.

- A **rule** is a [CEL](https://cel.dev/) condition over a finding, its package and its manifest.
  Its action is `fail` or `warn`. A `fail` rule that matches fails the gate, and vet exits 1. A
  `warn` rule marks the finding and does not fail the gate.
- A rule that reads `finding` runs on each finding. A rule that reads `package` and not `finding`
  is a **package rule**. It runs on each package, so it can block a package that no control
  reports. See [Package rules](#package-rules).
- A **suppression** hides findings from the gate. It needs a reason, and it can expire. A
  suppressed finding stays in the report.

## Start in one minute

```bash
vet policy init vet-policy.yml                     # write a starter policy
vet policy validate vet-policy.yml                 # check it
vet scan                                           # scan once, and save the scan
vet report show last --policy vet-policy.yml       # test the policy on the saved scan
vet scan --policy vet-policy.yml                   # apply it
```

`vet report show --policy` applies a new gate to a saved scan, with no new scan. Use it to tune a
policy before you put it in CI.

## An example

This policy blocks malware, injection in GitHub Actions workflows and critical vulnerabilities. In
a pull request, it also blocks a new dependency on a version that is less than 14 days old. One
known issue has a suppression that expires.

```yaml
version: 2
rules:
  - id: no-malware
    description: A malicious or suspicious package fails the build.
    when: finding.family == "malware"
    action: fail
  - id: no-workflow-injection
    when: finding.control_id in ["dangerous-trigger", "template-injection"]
    action: fail
  - id: no-critical-vulnerability
    when: finding.control_id == "vulnerability" && finding.severity == "critical"
    action: fail
  - id: new-dependency-age
    description: A pull request cannot add a version that is less than 14 days old.
    when: package.change == "ADDED" && has(package.days_since_publish) && package.days_since_publish < 14
    action: fail
suppressions:
  - purl: pkg:npm/lodash@4.17.20
    reason: The upgrade to 4.18.1 is in pull request 42.
    expires: 2026-12-31
```

`new-dependency-age` reads only `package`, so it is a package rule. It runs on each package, also
on a package that no control reports. In a full scan, `package.change` is empty, so it does not
match. With `--base-ref`, vet compares the change with the base, and a new package has
`change == "ADDED"`:

```bash
vet scan --base-ref origin/main --policy vet-policy.yml
```

## The file

| Key | Required | Meaning |
| --- | --- | --- |
| `version` | yes | Always `2` |
| `rules[].id` | yes | A unique id. The report and the gate name the rule with it |
| `rules[].description` | no | What the rule is for |
| `rules[].when` | yes | A CEL condition that gives a bool |
| `rules[].action` | yes | `fail` or `warn` |
| `rules[].help` | no | What to do when the rule matches. The report shows it on each finding that the rule matches |
| `rules[].link` | no | An http or https URL with more guidance, such as a page of your security team |
| `rules[].severity` | no | The severity of the finding that a package rule makes. The default is `info` |
| `suppressions[].id` | one of `id`, `purl`, `control` | A finding id, such as `f-e8b1a3df1a3b5c13` |
| `suppressions[].purl` | one of `id`, `purl`, `control` | A package. With no version, it matches every version |
| `suppressions[].control` | one of `id`, `purl`, `control` | A control id, such as `dependency-cooldown` |
| `suppressions[].reason` | yes | Why the finding is acceptable. A reviewer reads it |
| `suppressions[].expires` | no | A date (`2026-12-31`) or an RFC 3339 time. A date means 00:00 UTC |

A suppression with two selectors, such as `purl` and `control`, hides only the findings that match
both. A suppression `purl` matches every spelling of the package name in its ecosystem. A name with `*`,
`?` or `[` is a glob, and `*` also matches a `/`. A glob suppression must name a `control`, so that it
never hides an attack such as malware. Write the `?` of a glob as `%3F`, because a `?` in a PURL
starts the qualifiers.

## Package rules

A rule that reads `package` and not `finding` runs once on each package. In pull request mode, it
runs on each package that the change adds or changes. It skips the packages that the change keeps
or removes. A rule that reads neither runs on each finding.

`vet policy validate` prints the scope of each rule: "each finding" or "each package".

A match makes a finding with the control id `policy`:

- The title is the `description` of the rule.
- The severity is the `severity` of the rule, or `info`.
- The action of the rule decides the gate. `--fail-on` does not apply to the finding, and no other
  rule evaluates it.
- A suppression with the finding id, the `purl` or `control: policy` hides it.

This rule blocks an internal package name that comes from a public registry:

```yaml
  - id: internal-from-public
    description: An internal package comes from a public registry.
    when: >-
      package.is("@acme/*") &&
      (!has(package.resolved) || !package.resolved.startsWith("https://npm.acme.example/"))
    action: fail
    severity: high
    help: Install @acme packages from the internal registry. Check .npmrc.
    link: https://wiki.acme.example/security/registries
```

A rule that denies must also fail when a field is absent. A lockfile entry with no `resolved` URL
does not say where npm gets the package, so the rule above fails on it.

The `dependency-cooldown` control also reports fresh versions, as `high` findings. A cooldown rule
in the policy makes a second finding on the same package. Each finding says what blocked or warned
it, so the PR comment shows both causes on the card of the package.

An earlier v2 alpha ran each rule on the findings only. A rule that reads only `package` now makes
its own finding, and the control findings of the package no longer carry its gate record. To keep
the old behaviour, add a `finding` condition, as `finding.subject_kind == "package" && ...`.

## The rule input

A rule reads three variables. `vet policy schema get` prints their JSON Schema.

**`finding`**

| Field | Example |
| --- | --- |
| `id` | `f-e8b1a3df1a3b5c13` |
| `control_id` | `malware`, `vulnerability`, `dangerous-trigger`. See [controls.md](controls.md) |
| `family` | `malware`, `vulnerability`, `workflow`, `agent-config` |
| `severity` | `critical`, `high`, `medium`, `low`, `info` |
| `confidence` | The confidence of the evidence |
| `title` | The text of the finding |
| `change` | In pull request mode, the change that caused the finding |
| `subject_kind` | `package`, `workflow` or another subject |
| `path` | The file of the finding |

**`package`** (absent for a finding with no package, such as a workflow finding)

| Field | Example |
| --- | --- |
| `purl`, `ecosystem` | `pkg:npm/lodash@4.17.20`, `npm` |
| `name`, `version` | The canonical name and version of the ecosystem |
| `raw_name`, `raw_version` | The name and version as the manifest writes them |
| `direct`, `dev` | `true` for a direct or a development dependency |
| `resolved` | The download URL that the lockfile records. Absent when the lockfile has none |
| `origin` | `declared` for a package of a lockfile or a manifest, `installed` for a package on disk |
| `change`, `previous_version` | In pull request mode: `ADDED`, `UPGRADED`, `DOWNGRADED`, `MODIFIED`, `REMOVED` or `UNCHANGED`. A package rule never sees `REMOVED` or `UNCHANGED` |
| `licenses` | A list of SPDX ids |
| `deprecated` | `true` when the registry marks the version deprecated |
| `days_since_publish` | The age of the version in days |
| `downloads` | The download count |
| `scorecard` | The OpenSSF Scorecard score of the repository |
| `latest_version` | The newest version in the registry |
| `vulnerabilities` | A list. Each item has `id`, `aliases`, `severity` and `cvss` |
| `malware` | `malicious`, `verified` and `confidence` of the analysis |
| `action` | For a GitHub Actions package pinned to a commit: `reachable` (a branch or a tag contains the commit), `tags` (the tags that point to it) and `ref` |

**`manifest`**: `path`, `ecosystem`, `kind` and `change` of the file that holds the package.

An optional field with no value is absent. A condition that reads an absent field does not match.
Test the field with `has()`, as in `has(package.days_since_publish)`.

## Compare names and versions

Names and versions follow the rules of each ecosystem. Use the two package functions, not `==`.

- `package.is("name")` is true when the name names the package. `package.is("python-dateutil")`
  matches the PyPI package `python.dateutil`. A name with `*`, `?` or `[` is a glob:
  `package.is("@acme/*")` matches each package of the `@acme` scope.
- `package.version_cmp("1.2.3")` gives -1, 0 or 1 when the version is below, equal to or above
  `1.2.3`. `package.version_cmp("2.0") < 0` is true for `1.0rc1` on PyPI.

An ecosystem with no version order, such as GitHub Actions, gives no answer to `version_cmp`. A
condition that needs the answer does not match. CEL still decides `a || b` when `b` is true.

## More rules

```yaml
  - id: old-lodash
    when: package.is("lodash") && package.version_cmp("4.17.21") < 0
    action: fail
  - id: any-critical-advisory
    when: package.vulnerabilities.exists(v, v.severity == "critical")
    action: warn
  - id: deprecated
    when: has(package.deprecated) && package.deprecated
    action: warn
  - id: workflow-high
    when: finding.family == "workflow" && finding.severity in ["high", "critical"]
    action: fail
  - id: new-mcp-server
    when: finding.control_id == "mcp-server-added"
    action: fail
```

## License gate

The license control reports a license that an allow list or a deny list rejects. See
[License lists](controls.md#license-lists). A policy rule then decides the gate:

```yaml
# config.yml
plugins:
  license:
    options:
      allow: [osi-approved]
      deny: [GPL-3.0-only, GPL-3.0-or-later, AGPL-3.0-only, AGPL-3.0-or-later]
```

```yaml
# vet-policy.yml
version: 2
rules:
  - id: no-denied-license
    when: finding.control_id == "license-denied"
    action: fail
  - id: license-review
    when: finding.control_id in ["license-not-allowed", "license-unknown", "license-relicensed"]
    action: warn
```

## Where vet reads the policy

- `--policy FILE` reads one file. `--policy DIR` reads each `.yml` and `.yaml` file of the
  directory. A rule id must be unique across the files.
- `--policy NAME`, with no extension and no directory, reads `policies/NAME.yml` in the vet config
  directory. `vet policy init NAME` writes that file.
- The `policy.file` config key sets the policy for every run. `policy.fail_on` sets a severity or
  `attacks`.

## Pull request mode

With `--base-ref REF`, vet reads a policy file of the git repository at `REF`, not from the
working tree. A pull request that edits the policy cannot loosen the gate of its own change. The
edit takes effect after it merges.

- vet prints an info line that names the policy file and the base ref.
- When the change edits the policy, vet says so, and the report sets `trailer.gate.policy_changed`.
- `trailer.gate.policy` names the source, such as `origin/main:.github/vet/policy.yml`.
- When the policy file does not exist at the base ref, vet applies no policy file to the change.
- When the policy at the base ref does not load, such as a filter suite of vet v1, and the change
  edits it, vet applies no policy file to the change. vet prints a warning, and the report has a
  diagnostic with the code `base_policy_invalid`. The policy of the change must load. When the
  change keeps a policy that does not load, the scan stops with `policy_invalid`.
- vet reads a policy file anywhere in the git repository at `REF`, also when you scan a
  subdirectory. A policy outside the repository, such as `--policy NAME`, comes from disk. A file
  that the change adds cannot take over a policy name.
- vet stops with an error when it cannot read the policy at `REF`, for example when the policy is
  a symbolic link in git, or when the policy path goes through a symbolic link in the working tree.
  It never falls back to the policy of the change.
- A config file that you pass with `--config` still comes from disk. Keep the gate in the policy
  file, or pass `--fail-on` in the workflow.
- To test a policy edit on your machine, apply it to a saved scan: `vet report show last --policy
  vet-policy.yml`.

## The gate

`--fail-on SEVERITY` and the policy work together. The gate fails when an unsuppressed finding is
at the severity or above, or when it matches a `fail` rule. A plain scan, with neither, has no gate
and exits 0.

`--fail-on attacks` fails only on the controls that find an attack: `malware`, `impostor-commit`
and `suspicious-command`. Each other finding warns. Use it to block attacks on the first day,
before you fix old findings. `vet policy control list -o json` marks the attack controls with
`attack: true`. The report holds the gate in `trailer.gate`: the outcome, the policy, the rules that
failed and the finding ids.

Each finding says what the gate did with it. The PR comment, the step summary, the terminal table
and the markdown report show "Blocked by" or "Warned by" with the rules and the `--fail-on` value.
The JSON report holds it in the `gate` object of the finding:

```json
"gate": {"action": "fail", "rules": ["critical-or-high"], "help": "Ask the security team.", "link": "https://wiki.example.com/security"}
```

When two settings disagree, the gate record shows which one decided. For example, a `warn` rule on
fresh packages and a `fail` rule on `high` findings both match a `dependency-cooldown` finding. A
`fail` rule wins, and the finding says "Blocked by policy rule critical-or-high".

| Exit code | Meaning |
| --- | --- |
| 0 | The gate passed, or no gate was set |
| 1 | The gate failed |
| 2 | The policy file is not valid, or a flag is not valid |

## Let an AI agent write it

The [`vet-policy-authoring`](../.claude/skills/vet-policy-authoring/SKILL.md) Agent Skill drafts a
policy, validates it and tests it on a saved scan. It never installs the policy. Copy the directory
to `~/.claude/skills/` to use it in other repositories.
