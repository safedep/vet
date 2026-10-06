# Policy

A policy decides when a scan fails. It is a YAML file with rules and suppressions.

- A **rule** is a [CEL](https://cel.dev/) condition over a finding, its package and its manifest.
  Its action is `fail` or `warn`. A `fail` rule that matches fails the gate, and vet exits 1. A
  `warn` rule marks the finding and does not fail the gate.
- vet applies each rule to each finding. A package with no finding does not reach a rule. For
  example, a rule on `package.licenses` sees only the packages that have a finding. To gate on a
  license, use the license control. See [License gate](#license-gate).
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

In a full scan, `package.change` is empty, so `new-dependency-age` does not match. With
`--base-ref`, vet compares the change with the base, and a new package has `change == "ADDED"`:

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
| `suppressions[].id` | one of `id`, `purl`, `control` | A finding id, such as `f-e8b1a3df1a3b5c13` |
| `suppressions[].purl` | one of `id`, `purl`, `control` | A package. With no version, it matches every version |
| `suppressions[].control` | one of `id`, `purl`, `control` | A control id, such as `dependency-cooldown` |
| `suppressions[].reason` | yes | Why the finding is acceptable. A reviewer reads it |
| `suppressions[].expires` | no | A date (`2026-12-31`) or an RFC 3339 time. A date means 00:00 UTC |

A suppression with two selectors, such as `purl` and `control`, hides only the findings that match
both. A suppression `purl` matches every spelling of the package name in its ecosystem.

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
| `origin` | `declared` for a package of a lockfile or a manifest, `installed` for a package on disk |
| `change`, `previous_version` | In pull request mode: `ADDED`, `UPGRADED`, `DOWNGRADED`, `MODIFIED`, `REMOVED` or `UNCHANGED` |
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
  matches the PyPI package `python.dateutil`.
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
- The `policy.file` config key sets the policy for every run. `policy.fail_on` sets a severity.

## The gate

`--fail-on SEVERITY` and the policy work together. The gate fails when an unsuppressed finding is
at the severity or above, or when it matches a `fail` rule. A plain scan, with neither, has no gate
and exits 0. The report holds the gate in `trailer.gate`: the outcome, the policy, the rules that
failed and the finding ids.

| Exit code | Meaning |
| --- | --- |
| 0 | The gate passed, or no gate was set |
| 1 | The gate failed |
| 2 | The policy file is not valid, or a flag is not valid |

## Let an AI agent write it

The [`vet-policy-authoring`](../.claude/skills/vet-policy-authoring/SKILL.md) Agent Skill drafts a
policy, validates it and tests it on a saved scan. It never installs the policy. Copy the directory
to `~/.claude/skills/` to use it in other repositories.
