---
name: vet-policy-authoring
description: Use when someone asks you to write, change or test a vet policy, to fail or to warn on
  a kind of finding, to suppress a finding, or to explain why a vet gate failed. The skill drafts
  a policy v2 file and tests it against a saved scan. It never installs the policy.
---

# Write and test a vet policy

A vet policy is a YAML file with `version: 2`, a list of `rules` and a list of `suppressions`. A
rule has an `id`, a CEL condition in `when` and an `action`, `fail` or `warn`. A suppression names
an `id`, a `purl` or a `control`, a `reason`, and an optional `expires` date. vet reads a policy
only with `--policy FILE` or the `policy.file` config key.

## Rules for you

- Draft the policy in a new file that the user names, for example `vet-policy.yml`. Do not
  change a policy file that exists unless the user asks.
- Never install the policy. Do not set `policy.file`, and do not edit a CI workflow, a git hook or
  the vet config. Tell the user the command that applies the policy, and let the user run it.
- Read the fields from the schema. Do not guess a field name or a control id.
- Every suppression has a reason that a reviewer can check. Give it an `expires` date when the
  user knows when the fix comes.

## Steps

1. Read the input of a rule: `vet policy schema get`. A rule reads `finding`, `package` and
   `manifest`. An optional field with no value is absent, so test it with `has()`, for example
   `has(package.days_since_publish) && package.days_since_publish < 5`.
   Compare a package name with `package.is("name")`, not with `==`, and a version with
   `package.version_cmp("1.2.3")`. Both apply the rule of the ecosystem: `package.is("python-dateutil")`
   matches `python.dateutil`, and `package.version_cmp("2.0") < 0` holds for `1.0rc1`.
2. Read the control ids and their default severities: `vet policy control list -o json`.
3. Start from the starter file when the user has no policy: `vet policy init vet-policy.yml`.
4. Write the rules. Keep one idea in each rule, and give it a `description`.
5. Check the file: `vet policy validate vet-policy.yml -o json`. Fix every problem that it lists.
6. Test the policy against a saved scan. `vet report list -o json` lists the scans. With no scan,
   run `vet scan . -o json` once. Then run `vet report show last --policy vet-policy.yml -o json`.
   The `trailer.gate` object holds the outcome, the rules that failed and the finding ids. Each
   finding that a rule matched has `policy_rule`. The saved scan does not change.
7. Show the user the policy, the gate outcome, and the findings that each rule matched or that a
   suppression hid. Then give the command that applies it: `vet scan . --policy vet-policy.yml`.

## Exit codes

`vet report show` exits 1 when the gate fails, and 0 when it passes. A failed gate is a result to
report, not an error. Exit code 2 is a problem with the policy file or a flag.
