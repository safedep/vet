<!-- vet:pr-comment v1 -->
### ❌ vet: 1 cause blocks this pull request

**Next step:** `npm/pnpm@12.15.0` and 14 more in [`pnpm-lock.yaml:92`](https://github.com/acme/app/blob/2222222222222222222222222222222222222222/pnpm-lock.yaml#L92): Keep version 12.8.2, or wait until 2026-10-23. The wait ends at 2026-10-23 11:17 UTC.

**Gate failed** · 15 blocking · Checked 23 added or upgraded packages at `2222222`.

#### Blocking

`npm/pnpm@12.15.0` and 14 more: **Published 1 day ago** · `cooldown` · upgraded in [`pnpm-lock.yaml:92`](https://github.com/acme/app/blob/2222222222222222222222222222222222222222/pnpm-lock.yaml#L92)

The registry published this version on 2026-10-21 11:15:00 UTC. The cooldown is 2 days (flag --cooldown-days). The version can merge after 2026-10-23 11:15:00 UTC.

**Blocked by:** policy rule package-cooldown

**Policy help:** Wait until the version is older than the cooldown, or pin an older version.

**Fix:** Keep version 12.8.2, or wait until 2026-10-23. The wait ends at 2026-10-23 11:17 UTC.

**Evidence:** published at 2026-10-21T11:15:00Z

<details><summary>14 more with this cause</summary>

- `npm/@pnpm/exe.android-arm64@12.15.0`
- `npm/@pnpm/exe.android-x64@12.15.0`
- `npm/@pnpm/exe.darwin-arm64@12.15.0`
- `npm/@pnpm/exe.darwin-x64@12.15.0`
- `npm/@pnpm/exe.freebsd-x64@12.15.0`
- `npm/@pnpm/exe.linux-arm64-musl@12.15.0`
- `npm/@pnpm/exe.linux-arm64@12.15.0`
- `npm/@pnpm/exe.linux-ppc64@12.15.0`
- `npm/@pnpm/exe.linux-riscv64@12.15.0`
- `npm/@pnpm/exe.linux-s390x@12.15.0`
- `npm/@pnpm/exe.linux-x64-musl@12.15.0`
- `npm/@pnpm/exe.linux-x64@12.15.0`
- `npm/@pnpm/exe.win32-arm64@12.15.0`
- `npm/@pnpm/exe.win32-x64@12.15.0`

</details>

[About this control](https://github.com/safedep/vet/blob/v2.0.0-alpha.20261014124335/docs/controls.md#dependency-cooldown) · [Wrong result?](https://github.com/safedep/vet/issues/new?control=dependency-cooldown&finding=f-492e6ab63797f149&subject=pkg%3Anpm%2Fpnpm%4012.15.0&template=false-positive.yml&version=2.0.0-alpha.20261014124335) · `f-492e6ab63797f149`

<details><summary>9 findings do not block: 7 medium, 2 info</summary>

**New and unpopular package** · `medium`

- `npm/lefthook-android-arm64@2.2.2`: is new: its first version is 9 days old
- `npm/@codemirror/streamparser@6.0.0`: is new: its first version is 15 days old

**Provenance lost on an upgrade** · `medium`

- `npm/@oxc-parser/binding-linux-x64-musl@0.154.0`: has no provenance, and 0.150.0 had one
- `npm/@nosecone/next@1.14.1`: has no provenance, and 1.13.0 had one
- `npm/@typescript-eslint/scope-manager@8.71.2`: has no provenance, and 8.70.1 had one
- `npm/lefthook@2.2.2`: has no provenance, and 2.1.14 had one

**Version anomaly on an upgrade** · `medium`

- `npm/unbash@6.0.0`: the upgrade jumps from 4.0.11 to 6.0.0

**Agent instruction file** · `info`

- `CLAUDE.md`: Agent instruction file CLAUDE.md

**Low OpenSSF Scorecard** · `info`

- `npm/source-map-js@1.2.2`: has an OpenSSF Scorecard score of 2.8

</details>

<details><summary>Maintainers: accept this cause</summary>

Add the entries to `.github/vet/policy.yml` on the base branch, then run the job again. Each entry accepts its cause and no other finding.

```yaml
suppressions:
  # npm/pnpm@12.15.0 and 14 more
  - purl: pkg:npm/pnpm@12.15.0
    control: dependency-cooldown
    reason: Why this is acceptable
    expires: 2026-10-23T11:16:31Z
  - purl: pkg:npm/%40pnpm/exe.*@12.15.0
    control: dependency-cooldown
    reason: Why this is acceptable
    expires: 2026-10-23T11:16:31Z
```

</details>

<details><summary>For AI agents</summary>

```yaml
vet-agent: v1
gate: fail
head: "2222222222222222222222222222222222222222"
causes:
  - gate: fail
    control: dependency-cooldown
    rules: [package-cooldown]
    subject: pkg:npm/pnpm@12.15.0
    place: pnpm-lock.yaml:92
    fix: Keep version 12.8.2, or wait until 2026-10-23. The wait ends at 2026-10-23 11:17 UTC.
    wait_until: "2026-10-23T11:16:31Z"
    findings: [f-492e6ab63797f149, f-b0579d0afabfedb4, f-46785b90e9ebad16, f-a69b600775bf23f9, f-c2e9551e506c31e0, f-f19b1ce17d468eb4, f-9d02a3f59502f5a9, f-6a8763a80c9ecd27, f-32ac2a286ed795cb, f-6a841e98056181b4, f-836594314dfde5fd, f-0904cb2689c6085e, f-92fe51002f0610e6, f-8aa7abcb83588720, f-23bd63dd8af8ed23]
other: [f-4c153369825a13c7, f-5040d4c508043032, f-6af0f2aca8e112d7, f-822a48b188a3640a, f-8c4ab1869e91f60f, f-a49e47daf6246e48, f-4b90087f9be39568, f-2680d5d001a6098f, f-10063743abfd4c01]
```

</details>

<sub>[vet](https://github.com/safedep/vet) 2.0.0-alpha.20261014124335 · open source, by SafeDep · [Full report](https://github.com/acme/app/actions/runs/99) · [Policy](https://github.com/acme/app/blob/1c8a58d6e27559015e1621a830dc20e9dc6b4bd0/.github/vet/policy.yml) · [Wrong result?](https://github.com/safedep/vet/issues/new?template=false-positive.yml&version=2.0.0-alpha.20261014124335) · [Add vet to your repo](https://github.com/safedep/vet/blob/v2.0.0-alpha.20261014124335/docs/github-action.md)</sub>

<!-- vet:state eyJ2IjoxLCJoZWFkIjoiMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMiIsImlkcyI6WyJmLTA5MDRjYjI2ODljNjA4NWUiLCJmLTEwMDYzNzQzYWJmZDRjMDEiLCJmLTIzYmQ2M2RkOGFmOGVkMjMiLCJmLTI2ODBkNWQwMDFhNjA5OGYiLCJmLTMyYWMyYTI4NmVkNzk1Y2IiLCJmLTQ2Nzg1YjkwZTllYmFkMTYiLCJmLTQ5MmU2YWI2Mzc5N2YxNDkiLCJmLTRiOTAwODdmOWJlMzk1NjgiLCJmLTRjMTUzMzY5ODI1YTEzYzciLCJmLTUwNDBkNGM1MDgwNDMwMzIiLCJmLTZhODQxZTk4MDU2MTgxYjQiLCJmLTZhODc2M2E4MGM5ZWNkMjciLCJmLTZhZjBmMmFjYThlMTEyZDciLCJmLTgyMmE0OGIxODhhMzY0MGEiLCJmLTgzNjU5NDMxNGRmZGU1ZmQiLCJmLThhYTdhYmNiODM1ODg3MjAiLCJmLThjNGFiMTg2OWU5MWY2MGYiLCJmLTkyZmU1MTAwMmYwNjEwZTYiLCJmLTlkMDJhM2Y1OTUwMmY1YTkiLCJmLWE0OWU0N2RhZjYyNDZlNDgiLCJmLWE2OWI2MDA3NzViZjIzZjkiLCJmLWIwNTc5ZDBhZmFiZmVkYjQiLCJmLWMyZTk1NTFlNTA2YzMxZTAiLCJmLWYxOWIxY2UxN2Q0NjhlYjQiXSwiZmlyc3QiOnRydWV9 -->
