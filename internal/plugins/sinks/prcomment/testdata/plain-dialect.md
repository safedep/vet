<!-- vet:pr-comment v1 -->
### ❌ vet: 1 cause blocks this pull request

> **Caution:** `npm/evil-colors@1.4.1`: Malicious package
>
> Do not merge this change. Treat each machine and each CI run that installed or ran it as exposed.

**Next step:** `npm/evil-colors@1.4.1` in [`package-lock.json:42`](https://github.com/acme/app/blob/2222222222222222222222222222222222222222/package-lock.json#L42): Remove evil-colors. Run `npm uninstall evil-colors`.

> **Warning:** Some checks did not complete, so a finding can be missing. Run the job again before you merge.
>
> `insights`: 2 packages have no data

**Gate failed** · 1 blocking · Checked 2 added or upgraded packages at `2222222`.

#### Blocking

`npm/evil-colors@1.4.1`: **Malicious package** · `critical` · added in [`package-lock.json:42`](https://github.com/acme/app/blob/2222222222222222222222222222222222222222/package-lock.json#L42)

The package runs a postinstall script that reads \~/.npmrc.

**Fix:** Remove evil-colors.

```sh
npm uninstall evil-colors
```

**Evidence:** Verified malicious

[About this control](https://github.com/safedep/vet/blob/v2.0.0-alpha.20261005063951/docs/controls.md#malware) · [Wrong result?](https://github.com/safedep/vet/issues/new?control=malware&finding=f-f7017b227d6ad796&subject=pkg%3Anpm%2Fevil-colors%401.4.1&template=false-positive.yml&version=2.0.0-alpha.20261005063951) · `f-f7017b227d6ad796`

**1 finding does not block: 1 medium**

**Action not pinned to a commit SHA** · `medium`

- `tj-actions/changed-files@v44`: is not pinned to a commit SHA

**Maintainers: accept this cause**

Add the entries to the policy file on the base branch, then run the job again. Each entry matches no other finding of this scan. An entry with no expires stays until you remove it.

```yaml
suppressions:
  # npm/evil-colors@1.4.1
  - id: f-f7017b227d6ad796
    reason: Why this is acceptable
```

**For AI agents**

````yaml
vet-agent: v1
gate: fail
head: "2222222222222222222222222222222222222222"
causes:
  - gate: none
    control: malware
    subject: pkg:npm/evil-colors@1.4.1
    place: package-lock.json:42
    fix: Remove evil-colors.
    fixed_version: 1.3.9
    command: npm uninstall evil-colors
    findings: [f-f7017b227d6ad796]
other: [f-e815bb3b5e0846f1]
````

[vet](https://github.com/safedep/vet) 2.0.0-alpha.20261005063951 · open source, by SafeDep · [Full report](https://github.com/acme/app/actions/runs/99) · [Wrong result?](https://github.com/safedep/vet/issues/new?template=false-positive.yml&version=2.0.0-alpha.20261005063951) · [Add vet to your repo](https://github.com/safedep/vet/blob/v2.0.0-alpha.20261005063951/docs/github-action.md)

<!-- vet:state eyJ2IjoxLCJoZWFkIjoiMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMiIsImlkcyI6WyJmLWU4MTViYjNiNWUwODQ2ZjEiLCJmLWY3MDE3YjIyN2Q2YWQ3OTYiXSwiZmlyc3QiOnRydWV9 -->
