<!-- vet:pr-comment v1 -->
### ⚠️ vet: 1 cause to review in this pull request

> [!CAUTION]
> `npm/evil-colors@1.4.1`: Malicious package
>
> Do not merge this change. Treat each machine and each CI run that installed or ran it as exposed.

**Next step:** `npm/evil-colors@1.4.1` in [`package-lock.json:42`](https://github.com/acme/app/blob/2222222222222222222222222222222222222222/package-lock.json#L42): Remove evil-colors. Run `npm uninstall evil-colors`.

> [!WARNING]
> Some checks did not complete, so a finding can be missing. Run the job again before you merge.
>
> `insights`: 2 packages have no data

**No gate** · 1 to review · Checked 2 added or upgraded packages at `2222222`.

#### Review

`npm/evil-colors@1.4.1`: **Malicious package** · `critical` · added in [`package-lock.json:42`](https://github.com/acme/app/blob/2222222222222222222222222222222222222222/package-lock.json#L42)

The package runs a postinstall script that reads \~/.npmrc.

**Fix:** Remove evil-colors.

```sh
npm uninstall evil-colors
```

**Evidence:** Verified malicious

[About this control](https://github.com/safedep/vet/blob/v2.0.0-alpha.20261005063951/docs/controls.md#malware) · [Wrong result?](https://github.com/safedep/vet/issues/new?control=malware&finding=f-f7017b227d6ad796&subject=pkg%3Anpm%2Fevil-colors%401.4.1&template=false-positive.yml&version=2.0.0-alpha.20261005063951) · `f-f7017b227d6ad796`

<details><summary>1 more finding: 1 medium</summary>

**Action not pinned to a commit SHA** · `medium`

- `tj-actions/changed-files@v44`: is not pinned to a commit SHA

</details>

<details><summary>Maintainers: accept this cause</summary>

Add the entries to the policy file on the base branch, then run the job again. Each entry accepts its cause and no other finding.

```yaml
suppressions:
  # npm/evil-colors@1.4.1
  - id: f-f7017b227d6ad796
    reason: Why this is acceptable
```

</details>

<sub>[vet](https://github.com/safedep/vet) 2.0.0-alpha.20261005063951 · open source, by SafeDep · [Full report](https://github.com/acme/app/actions/runs/99) · [Wrong result?](https://github.com/safedep/vet/issues/new?template=false-positive.yml&version=2.0.0-alpha.20261005063951) · [Add vet to your repo](https://github.com/safedep/vet/blob/v2.0.0-alpha.20261005063951/docs/github-action.md)</sub>

<!-- vet:state eyJ2IjoxLCJoZWFkIjoiMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMiIsImlkcyI6WyJmLWU4MTViYjNiNWUwODQ2ZjEiLCJmLWY3MDE3YjIyN2Q2YWQ3OTYiXSwiZmlyc3QiOnRydWV9 -->
