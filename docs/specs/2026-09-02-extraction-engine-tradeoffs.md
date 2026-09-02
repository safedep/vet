# Trade-offs: OSV-Scalibr as the extraction engine, manifest versus installed extraction, and a local malicious-package store

**Date:** 2026-09-02
**Status:** Draft, for brainstorm
**Companion to:** [Continuous endpoint filesystem scan design](2026-09-02-endpoint-filesystem-oss-package-scan-design.md)

This document answers three questions the design left open.

1. Should vet use OSV-Scalibr as the extraction engine for the endpoint
   scan, and in what form?
2. Should the endpoint scan extract from package manifests (lockfiles) or
   from the packages installed on the filesystem?
3. If vet and pmg keep a local copy of the malicious package set for
   offline and reliable matching, how big is it?

Short answers, with the evidence in the sections below.

1. Yes, as a library inside the new `oss-package` scanner. Not yet as a
   replacement for `pkg/parser` in `vet scan`.
2. Both. Installed artifacts are the source of the malware verdict.
   Manifests give the project association and a "declared but absent"
   signal. Neither alone is correct.
3. Small. The malicious set fits in 1 to 5 MB as a probabilistic filter, or
   about 16 MB as an exact hashed SQLite table, at one million entries. The
   full 20 million record set fits in 25 to 50 MB as a filter. Bandwidth and
   disk are not the constraint. Freshness and exclusions are.

## 1. Evidence

### 1.1 Benchmark tree

Built on this session's container (4 cores, page cache warm) with scalibr
v0.5.2 (`binary/scalibr`) and vet at `7a9ce13`.

| Tree | Content | Files | Package manifests |
|---|---|---|---|
| `webapp` | `npm install express react react-dom next webpack jest typescript eslint` | 19,625 in `node_modules`, 460 MB | 1 `package.json`, 1 `package-lock.json`, 771 `package.json` under `node_modules` |
| `pyapp` | venv with `requests flask pandas numpy boto3` | 9,202 in `.venv`, 220 MB | 1 `requirements.txt`, 38 `*.dist-info/METADATA` |
| `bin` | the vet and scalibr binaries | 2 | 0 |

### 1.2 Timings

| Run | Plugins | Inodes visited | Extract calls | Packages | Wall time |
|---|---|---|---|---|---|
| scalibr, lockfile mode | `javascript/packagelockjson`, `python/requirements` | 33,059 | 2 | 553 (533 npm, 20 pypi) | 0.12 s |
| scalibr, installed mode | `javascript/packagejson`, `python/wheelegg` | 33,060 | 812 | 519 (479 npm, 40 pypi) | 0.09 s |
| scalibr, installed + binaries | above + `go/binary`, `java/archive`, `ruby/gemspec` | 33,061 | 4,127 | 1,113 (+594 golang from the two Go binaries) | 0.21 s |
| scalibr, installed mode, `--skip-dir-regex node_modules` | `javascript/packagejson`, `python/wheelegg` | 10,998 | | | 0.03 s |
| scalibr, one project root (`--root webapp`) | `javascript/packagejson` | 22,068 | | | 0.06 s |
| `find -type f` | | 28,830 | | | 0.05 s |
| vet, `vet scan -D webapp --enrich=false --malware-query=false` | vet parsers | | 2 manifests | 536 | 4.2 s (process start, analytics, UI; the walk itself is milliseconds) |

Two conclusions.

- The walk is the cost, not the extraction. Reading 812 `package.json` files
  costs nothing measurable over visiting their directories. `node_modules`
  is two thirds of the inodes in a JavaScript project. A scan that skips
  `node_modules` is three times cheaper and blind to installed packages.
- At roughly 300,000 inodes per second warm, a 5 million inode home
  directory walks in about 20 seconds warm and a few minutes cold on a
  laptop SSD. That is the floor for a full scan. A delta scan that walks
  only changed project roots is proportional to the change.

The Go binary extractor deserves a note. It opened two executables and
reported 594 Go modules embedded in them. On a developer machine with
hundreds of Go binaries in `~/go/bin`, `node_modules/.bin`, and
`/usr/local/bin`, this extractor reads every executable. Enable it
deliberately, with `MaxFileSize`, not by default.

### 1.3 Declared versus installed, same project

From `webapp`. "Declared" is every entry in `package-lock.json`. "Installed"
is every `node_modules/<name>/package.json` whose directory name matches its
`name` field.

| Set | Count |
|---|---|
| Declared in `package-lock.json` | 536 |
| Marked `optional` in the lockfile | 98 |
| Installed under `node_modules` | 458 |
| Declared and not installed | 91 (`@img/sharp-darwin-arm64`, `@img/sharp-libvips-linux-arm64`, `@emnapi/*`, other platform-specific optional packages) |
| Installed and not declared | 13 (nested and bundled copies: `@babel/runtime@7.27.0`, `react-is@19.3.0-canary-...`, `@edge-runtime/*`, `server-only`) |
| `package.json` files under `node_modules` that are not a package | 4 (`bin@1.0.0`, `dist@1.0.0`, `benchmark@1.0.0`, and the project's own `webapp@1.0.0`) |

Python shows the same shape. `requirements.txt` from `pip freeze` lists 20
packages. The venv holds 40 distributions, because `pip freeze` hides `pip`,
`setuptools`, and their vendored distributions, which are on disk and
importable.

## 2. OSV-Scalibr as the extraction engine

### 2.1 What scalibr gives that vet does not have

| Capability | vet today | scalibr v0.5.2 |
|---|---|---|
| Walker controls | skip `.git` and `node_modules`, glob exclusions | `DirsToSkip`, `SkipDirRegex`, `SkipDirGlob`, `UseGitignore`, `MaxFileSize`, `MaxInodes`, `ReadSymlinks`, `PathsToExtract`, `IgnoreSubDirs`, `Stats` hook, `ErrorOnFSErrors` |
| Installed-package extractors | none | `javascript/packagejson`, `python/wheelegg`, `python/condameta`, `ruby/gemspec`, `go/binary`, `java/archive`, `os/homebrew`, `os/macapps`, `javascript/vsix`, plus every OS package manager |
| Lockfile ecosystems | 17 file names in `pkg/parser` | all of vet's plus `pylock`, `pdm.lock`, `deno`, `.NET` (5 formats), Haskell, Julia, Conan, `mix.lock`, Bazel, `go vendor/modules.txt` |
| Line numbers | no | yes for most lockfiles since v0.5.1 |
| Dependency groups | dev flag in npm graph parser | `DepGroups` metadata per package |
| Enrichers | vet's own | `vulnmatch`, `license`, `transitivedependency`, `packagedeprecation`, `secrets`, `reachability` |
| Container image layers | vet's own reader on top of scalibr | native |

### 2.2 What scalibr does not give

- No incremental or delta scanning. The walker is single-threaded
  (`internal.WalkDirUnsorted`) and keeps no index. Delta stays ours, built
  around scalibr by feeding changed project roots as `ScanRoots` or
  `PathsToExtract`. The one-project-root run above shows this works and
  costs what the root costs.
- No project association for installed packages. `javascript/packagejson`
  reports each `node_modules/x/package.json` as an independent package with
  a location. The owning project root is derived by us from the path.
- No guard against non-package `package.json` files. Any `package.json`
  with a `name` and `version` becomes a package (`dist@1.0.0` above). We
  filter on directory-name-equals-package-name under `node_modules`, or run
  the extractor through `ExtractorOverride`.
- A parse error on one file can fail the extractor status for the scan.
  The extractor carries a `TODO(b/281023532)` for this. We treat plugin
  status as advisory, not fatal.
- No malware verdicts, no SafeDep exclusions. Matching stays with us.
- vet's dependency graph shape, lockfile-poisoning analyzer inputs, GitHub
  Actions and Terraform parsers, and CycloneDX and SPDX readers have no
  one-to-one scalibr equivalent. A full core migration must re-validate all
  of them.

### 2.3 Cost of the upgrade

- v0.4.4 to v0.5.2 requires Go 1.26.3. vet is on 1.26.2. `go mod download`
  already switched toolchains during this session.
- v0.5.x centralised plugin configuration in `PluginConfig` and changed the
  plugin list API. `pkg/parser` uses scalibr through `osv-scanner`'s
  lockfile package and through direct extractors in `cargo.go`, `bun.go`,
  and `pomxml.go`. Expect a half day of compile fixes and a run of the
  parser fixtures.
- Binary size. The scalibr CLI is 69 MB. vet is 271 MB already, and links
  most of scalibr today, so the increment is small.

### 2.4 Two integration modes

| | C1. Library inside the `oss-package` scanner | C2. Scalibr as the single extraction core |
|---|---|---|
| Scope | new scanner only | `pkg/readers`, `pkg/parser`, container image reader, `vet scan` |
| Risk | low, isolated | high, every reporter and analyzer sees a new manifest shape |
| Duplication | two extraction stacks for a while | one stack |
| Ecosystem coverage | full for the endpoint scan | full everywhere |
| Migration effort | days | weeks, plus re-validation |
| Reversible | yes | hard |
| What we learn | real numbers on real trees before committing | nothing before committing |

Recommendation: C1 now. Build the `scalibr.Inventory` to `inventory.Item`
adapter for the endpoint scan. Decide C2 after the adapter has run on
customer trees, with the numbers.

## 3. Manifest extraction versus installed extraction

### 3.1 What each source says

| | Manifest (lockfile, `requirements.txt`, `go.mod`) | Installed (`node_modules`, `site-packages`, module caches, binaries) |
|---|---|---|
| Statement | "this project wants these versions" | "this code is on the disk" |
| Version precision | exact for lockfiles, a range for `package.json` and `requirements.txt` (vet floors ranges since #770; scalibr takes the minimum of the constraint) | exact, read from the artifact's own metadata |
| Project association | direct, the manifest is the project | derived from the path |
| Dependency graph | yes | no, flat |
| Dev versus prod | yes | no |
| Platform-conditional packages | lists all platforms (98 of 536 above) | only what this machine installed |
| Bundled and nested copies | not listed (13 of 458 above) | listed |
| Global installs, tool caches, venvs outside a project, pipx, uvx, `~/go/pkg/mod`, `~/.cargo/registry` | invisible | visible |
| Manual or scripted installs with no lockfile | invisible | visible |
| Malware execution risk | the package may never have been installed | the package can run: postinstall already ran, imports work |
| Retroactive detection | yes, from the baseline | yes, from the baseline |
| Walk cost | low, `node_modules` and `site-packages` can be skipped | high, every package directory is visited |
| Extraction cost | one large file per project | one small file per package, negligible over the walk |
| False inventory | none | non-package `package.json` files, vendored test fixtures, the project itself |
| Delta signal | hash of one file per project | mtime of the `node_modules` or `site-packages` root, plus per-package directory mtimes |

### 3.2 For the malware question specifically

A malicious package harms when it is installed and runs. The lockfile is
where the developer decided; the install is where the attacker won. The
benchmark shows the two sets differ by 17 percent in one direction and 3
percent in the other, in a clean project. In a real home directory the gap
grows: venvs with no requirements file, global npm packages, a `git clone`
that shipped a vendored `node_modules`, and package caches with unpacked
tarballs have no manifest at all.

So the verdict must come from installed artifacts. The manifest still
matters for three reasons.

1. It names the project and the owner, which is what Sec needs to act.
2. "Declared but not installed" and "installed but not declared" are
   signals. The second is how a compromised nested dependency or a manual
   drop-in shows up.
3. Some ecosystems have no installed artifact to read. `go.mod` plus
   `~/go/pkg/mod` and `Cargo.lock` plus `~/.cargo/registry` need the
   manifest to know which cached module a project uses.

### 3.3 Per-ecosystem source of truth

| Ecosystem | Installed source (verdict) | Manifest source (association) | Note |
|---|---|---|---|
| npm, pnpm, yarn, bun | `node_modules/<name>/package.json` (pnpm real dirs live under `.pnpm/`) | `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock` | filter on dir name equals package name |
| PyPI | `*.dist-info/METADATA`, `*.egg-info/PKG-INFO` in every venv, user site, conda env | `uv.lock`, `poetry.lock`, `Pipfile.lock`, `requirements*.txt` | venvs sit outside project trees often |
| Go | `~/go/pkg/mod/<module>@<ver>` directories, Go binaries | `go.mod`, `go.sum` | module cache is shared by all projects |
| Cargo | `~/.cargo/registry/src/*/<name>-<ver>` | `Cargo.lock` | same |
| Maven, Gradle | `~/.m2/repository/**/*.jar`, `~/.gradle/caches` | `pom.xml`, `gradle.lockfile` | `java/archive` opens each jar, cap the size |
| RubyGems | `gems/<name>-<ver>/*.gemspec` | `Gemfile.lock` | |
| VS Code, IDE extensions | `~/.vscode/extensions/*/package.json` | none | already an inventory kind |
| Homebrew, OS packages | `os/homebrew`, `os/dpkg`, `os/rpm` | none | already covered by `vet scan --brew` |

### 3.4 Recommendation

Extract both, and record the source kind on every item.

- Installed items carry the verdict. They go to the maldb match and to the
  endpoint page.
- Manifest items carry the project root, the dependency graph, and the
  dev flag. They enable the "declared but absent" and "installed but
  undeclared" diffs.
- The default extractor set for the endpoint scan is: all lockfile
  extractors, `javascript/packagejson`, `python/wheelegg`,
  `python/condameta`, `ruby/gemspec`, `javascript/vsix`, and the OS package
  extractors for the host. `go/binary` and `java/archive` are opt-in with a
  size cap. Go and Cargo module caches are indexed by directory name, which
  needs no file read.
- Both use one walk. Scalibr runs all enabled extractors in one pass, so
  installed extraction adds no walk cost over the manifest walk when
  `node_modules` is visited.

## 4. Local malicious-package store: size estimate

### 4.1 Assumptions

- SafeDep's malware analysis database holds 20 million package version
  records.
- At most 5 percent are malicious: 1 million purls. The likely number is
  lower, 200,000 to 500,000, because most records are benign analyses.
- A verdict can be for one version or for all versions (version `0` in
  the maldb convention). Treat "all versions" as a second key on the
  package name, so a lookup is two probes: `name@version` then `name@*`.
- The endpoint asks one question offline: "is this purl known malicious as
  of feed version V?" It does not ask "is this purl known benign?" That
  question needs the full 20 million set and is addressed separately in 4.4.

### 4.2 Sizes

Computed from the standard formulas. The SQLite rows are measured on this
container with one million synthetic purls of realistic shape (average 30.7
bytes per purl).

| Store | Semantics | 200k entries | 1M entries | 20M entries |
|---|---|---|---|---|
| Bloom filter, p = 1e-3 | no false negatives, 0.1% false positives, no delete | 0.4 MB | 1.8 MB | 36 MB |
| Bloom filter, p = 1e-4 | 0.01% false positives | 0.5 MB | 2.4 MB | 48 MB |
| Bloom filter, p = 1e-6 | | 0.7 MB | 3.6 MB | 72 MB |
| Binary fuse or xor filter, 8-bit fingerprint | p about 0.4%, immutable, rebuild on change | 0.2 MB | 1.1 MB | 22 MB |
| Binary fuse or xor filter, 16-bit fingerprint | p about 1.5e-5 | 0.5 MB | 2.2 MB | 45 MB |
| Sorted 64-bit hash list, delta coded | exact in practice (collision 1e-13), binary search, immutable | 1.2 MB | 5.8 MB | 104 MB |
| SQLite, 64-bit hashed key, `INTEGER PRIMARY KEY` | exact in practice, mutable, indexed | 3.3 MB | 16.5 MB | 330 MB |
| SQLite, purl text primary key + verdict + timestamp | exact, mutable, human readable | 9 MB | 45.5 MB | 910 MB |
| Plain text purl list, gzip | for transport only | 2.8 MB | 13.9 MB | 278 MB |

SQLite point lookup on the text table measured 8.6 microseconds. A filter
probe is under one microsecond. Either is invisible next to the walk.

### 4.3 What the numbers mean

- A one million entry malicious set costs 1 to 3 MB as a filter and about
  16 MB as an exact hashed table. A daily full snapshot download at this
  size is acceptable on every endpoint. Deltas are kilobytes.
- A filter with p = 1e-4 on an endpoint with 30,000 unique purls produces
  about 3 false positives per full match, each resolved by one
  `QueryPackageAnalysis` call. A clean endpoint therefore makes a handful
  of calls instead of 30,000, and makes zero calls when offline, at the
  cost of reporting "unconfirmed" for those few.
- A filter never misses a malicious purl that is in the feed. The failure
  mode is staleness, not false negatives. Bound it with a maximum feed age
  and a warning in `vet endpoint status` and `pmg setup doctor`.
- A bloom filter accepts additions in place (daily delta of new malicious
  purls), so the client rebuilds only on a full snapshot. It cannot delete.
  Retractions (a false positive verdict withdrawn) wait for the next
  snapshot. A cuckoo filter or the hashed SQLite table supports delete if
  we want same-day retractions.
- Tenant exclusions cannot live in a shared feed. Apply them after a hit,
  from a small per-tenant list fetched with the feed, as pmg already does
  through `MaliciousPackageExclusion`.
- Sign the feed. An attacker who can replace the file on disk can hide a
  package. The vet auto-update path already verifies signatures.

### 4.4 The "known benign" question, for pmg

pmg wants to skip the round trip for a package it has seen analysed before.
That needs the full 20 million set, not the malicious subset.

- A bloom filter over all analysed purls at p = 1e-3 is 36 MB; a binary
  fuse filter with 8-bit fingerprints is 22 MB. Both fit. A false positive
  here means "we think it was analysed, so skip the call", which is the
  unsafe direction: a new, unanalysed package that collides would pass
  without a verdict. Use p = 1e-6 (72 MB bloom, 90 MB fuse32) or an exact
  hashed list (104 MB delta coded, 330 MB SQLite) for this use.
- The analysed set churns daily by the thousands, so the client keeps
  pmg's existing TTL cache for recent verdicts and refreshes the big filter
  weekly.
- Recommendation: ship the malicious filter first for both tools. It is the
  reliability win. Decide the benign filter after measuring how many pmg
  calls the malicious filter plus the TTL cache already remove.

### 4.5 Proposed shape

- Feed: `malicious-purls-<version>.bf` (binary fuse, 16-bit) plus
  `malicious-names-<version>.bf` for all-version verdicts, a signed
  manifest with version, generation time, entry counts, and the hash of
  each file, and daily delta files that list added purls in plain text.
  Served from a CDN. Total per endpoint per day: under 3 MB full, under
  50 KB delta.
- Client: `dry/localdb` module `maldb_feed` with the filter blob, version,
  fetched-at, and the per-tenant exclusion list. Shared by vet and pmg.
  A probe API: `Lookup(purl) (Hit, Unconfirmed, Miss)`.
- Confirm: on a hit, if online, call `QueryPackageAnalysis` for the verdict
  detail and the exclusion check. If offline, report the hit with the feed
  version as evidence and reconcile on the next sync.
- API: a `MalwareFeedService` with `GetFeedManifest` and signed URLs, or a
  static bucket. This is the one piece that does not exist today.

## 5. Decisions to take in the brainstorm

1. C1 now and C2 later, or C2 directly.
2. The default extractor set, and whether `go/binary` and `java/archive`
   are on for developer endpoints.
3. Installed items as the verdict source, manifests as association. Agree
   or not.
4. Filter type for the feed: bloom (simple, appendable) or binary fuse
   (smaller, immutable). Exact hashed table if we want retractions and
   zero confirm calls.
5. Whether pmg gets the benign filter, and at what false positive rate.
6. Who owns the feed service and the signing key.
