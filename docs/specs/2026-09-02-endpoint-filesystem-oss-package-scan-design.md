# Design: Continuous endpoint filesystem scan for malicious OSS packages

**Date:** 2026-09-02
**Status:** Draft, for brainstorm
**Related:** [ADR 0001 `vet endpoint scan`](../adr/0001-endpoint-scan.md),
[safedep/vet#724](https://github.com/safedep/vet/issues/724)

## 1. Trigger

A user ran `vet scan -D /home/user1/code` on a 400 GB developer directory with
hundreds of projects. The goal was "find every malicious package on this
machine". The scan ran for more than four hours and then hung. A re-run
repeats the four hours. The same need now comes up from several customers.

This document does three things.

1. Defines the problem: what "scan the developer filesystem for malicious
   packages" means, why `vet scan -D` cannot do it, and what a solution must
   guarantee.
2. Defines the developer experience we want, from a technical product
   manager's view.
3. Lists the solution options we should brainstorm, with the trade-offs,
   before we fix the UX and the approach.

It does not pick a final design. Section 7 gives a recommendation to start
the discussion.

## 2. Why the current scan takes four hours and hangs

`vet scan -D` is a project scanner that got pointed at a filesystem. Every
part of its pipeline assumes one project of a few manifests. The code
references below explain each cost.

### 2.1 Discovery walks every byte, single threaded

`pkg/readers/dir_reader.go` walks the tree with `filepath.WalkDir` on one
goroutine. It skips only two directory names, `.git` and `node_modules`. It
has no `.gitignore` support, no size or inode budget, no symlink loop guard,
and no way to stop early. On 400 GB the walk alone is tens of minutes of
`stat` calls. The walk also skips `node_modules`, so the scan never sees
installed npm packages (see 3.2). The scan covers less than the user thinks.

### 2.2 Every manifest is parsed and enriched, one at a time

`pkg/scanner/scanner.go` processes manifests serially on one goroutine
(`startManifestScanner`). Inside one manifest it runs a work queue with
`--concurrency` workers (default 5). The queue buffer is 100,000 items and
the file carries a `FIXME` that names a deadlock when the buffer fills, since
workers both read and write the queue when transitive analysis is on.

### 2.3 Every package costs two network round trips, with no cache

Per package, in sequence:

- `pkg/scanner/enrich_insightsv2.go` calls `GetPackageVersionInsight` once
  per package. It is on by default (`--enrich`).
- `pkg/scanner/enrich_malware_query.go` calls `QueryPackageAnalysis` once
  per package.

There is no batch RPC and no cache. The same `lodash@4.17.21` that appears in
300 lockfiles is queried 600 times. A 400 GB tree with a few thousand
manifests and 200 to 2,000 packages each is 1 to 5 million package
lookups. At 5 workers and ~100 ms per call that is 3 to 30 hours. That is the
four hours.

Until #771 (2026-08-27) the Insights call used `context.Background()` with no
deadline. One stalled stream held a worker forever, five stalled streams held
the scan forever. That is the hang. #771 adds a 30 s per-call timeout with
retries on `UNAVAILABLE`, which turns the hang into slowness but does not
remove the cost model.

### 2.4 Everything stays in memory and nothing is resumable

Reporters keep every manifest until `Finish`. A scan that dies at hour four
writes nothing and restarts from zero. No checkpoint, no baseline, no delta.

### 2.5 The scan answers the wrong question

`vet scan` answers "is this project safe to ship". The user asked "is
anything malicious installed anywhere on this machine, and tell me when that
changes". That is an endpoint inventory question. ADR 0001 already names
"full filesystem OSS package inventory" as a medium-term scanner kind for
`vet endpoint scan`, and designates the endpointsync SQLite WAL as the
persistence layer for a client-side delta feature. Issue #724 tracks it. This
document is the design for that scanner kind.

## 3. Problem definition

### 3.1 Statement

Security teams need a continuous, machine-wide answer to: "which open source
package versions exist on each developer endpoint, which of them are known
malicious (and optionally vulnerable or policy-violating), where they are,
and which user and project they belong to". The answer must stay current as
developers clone, install, and delete code, and as SafeDep's threat
intelligence learns about new malicious packages after the package landed on
the disk.

`pmg` covers the install-time gate for package managers that run through it.
This design covers everything `pmg` does not see: what was already on the
disk before rollout, installs that bypass `pmg` (IDE-driven installs, scripts,
`git clone` of a repo with a vendored `node_modules`, global installs, tool
caches, container volumes), and retroactive detection when threat intel
changes.

### 3.2 What "on the filesystem" means

Two different sources, with different value.

| Source | Examples | Meaning | Malware relevance |
|---|---|---|---|
| Declared (manifests and lockfiles) | `package-lock.json`, `uv.lock`, `Cargo.lock`, `go.mod`, `pom.xml` | The project asks for this version | Medium. Says intent, not presence. A lockfile can name a package that was never installed. |
| Installed (artifacts on disk) | `node_modules/*/package.json`, `site-packages/*.dist-info/METADATA`, `~/.cargo/registry`, `~/go/pkg/mod`, `~/.npm/_cacache`, `~/.cache/pip`, global npm, `pipx`, `uvx`, Homebrew, Go binaries | The code is on the machine and can run | High. A malicious package must be installed to run a postinstall hook or be imported. |

`vet scan -D` today reads only the first row and skips `node_modules`. A
filesystem scan for malware must cover the second row, and it must cover the
per-user caches and global install locations outside the "code" directory.
OSV-Scalibr ships extractors for the installed row (`javascript/packagejson`,
`python/wheelegg`, `ruby/gemspec`, `go/binary`, `java/archive`, conda,
Homebrew, `vsix`). vet has none of them.

### 3.3 Scale facts that shape the design

- The tree is huge (400 GB, millions of inodes), but the set of unique
  package versions on one machine is small: tens of thousands.
- Between two runs a day apart, the changed set is tiny: a handful of
  projects, a few hundred package versions.
- The set of known malicious package versions is small (tens of thousands
  of purls) and changes daily. Vulnerability data is large (hundreds of
  thousands of advisories) and changes hourly.
- A machine can have several human users. Attribution must be per OS user
  (the MDM script already runs `vet` per user).
- Endpoints are offline part of the time. Laptops sleep mid-scan.

Consequence: the expensive resource is the filesystem walk, not the
network, once we stop paying the network per manifest occurrence. Walk
once, index, then work on deltas. Match against threat intel on the unique
purl set, not the occurrence set.

### 3.4 Requirements

Functional:

- R1. Inventory every OSS package version present on the endpoint, from
  lockfiles and from installed artifacts, across the user's home, code roots,
  package caches, and global install locations. Each item records path,
  ecosystem, name, version, source kind (lockfile or installed), owning
  project root, and OS user.
- R2. Report known malicious package versions with SafeDep verdicts, with
  the same confidence and exclusion rules as `vet scan --malware-query`.
- R3. Optionally report vulnerabilities and policy violations on the same
  inventory. Malware is the first and default use case.
- R4. Keep a local baseline. A repeat run detects added, removed, and
  changed items and does work proportional to the change, not the tree.
- R5. Sync inventory and findings to SafeDep Cloud per endpoint and per
  user, in the existing `vet endpoint scan` invocation model.
- R6. Detect retroactively: when threat intel flags a package version after
  it was inventoried, surface it without a full re-walk.
- R7. Offer the answer fleet-wide: "which endpoints have `pkg:npm/foo@1.2.3`"
  must be a cloud query, not a fleet re-scan.

Non-functional:

- N1. Bounded runtime. A first full scan of a 400 GB tree finishes in under
  30 minutes on a laptop. An incremental run finishes in under one minute.
- N2. Never hangs. Every network call and every walk step has a deadline.
  The scan checkpoints so a killed run resumes.
- N3. Bounded resources. Memory stays flat with tree size. CPU and IO run at
  low priority. A developer does not notice it.
- N4. Works offline. Inventory and the local baseline never need the
  network. Verdicts degrade to "unknown" and reconcile later.
- N5. Zero configuration under MDM. Sensible default roots, exclusions, and
  schedule. Configurable when needed.
- N6. Predictable exclusions. Users can exclude paths and see what was
  excluded. Secrets-bearing files are never read beyond what the extractor
  needs.

## 4. Developer experience

### 4.1 Personas and jobs

| Persona | Job | What they see |
|---|---|---|
| Developer (Dev) | Know I am clean, get told when I am not, lose no time | A command that returns in seconds, a clear finding with a path and a fix |
| Security engineer (Sec) | Prove no known-malicious package exists on any endpoint, respond within hours when one appears | Endpoint Hub: per-endpoint inventory, malicious findings with user and path, fleet query by purl, trend |
| IT / MDM admin | Roll out once, never touch again | One script, one schedule, runs as every user, reports health |

### 4.2 Principles

1. Inventory first, verdicts second. The scan never waits on the network to
   finish the inventory.
2. Delta by default. `full` is a flag, not the norm.
3. Quiet when clean. One line of output. Loud only on a finding.
4. Same pipeline as the other endpoint kinds. No new command tree, no new
   sink, no new wire envelope. The kind plugs into `pkg/inventory/scanners`.
5. The cloud remembers so the endpoint does not have to re-walk.

### 4.3 Command surface (proposal)

```text
vet endpoint scan --kind oss-package                 # walk default roots, delta against baseline, sync
vet endpoint scan --kind oss-package --full          # rebuild the baseline
vet endpoint scan --kind oss-package --root ~/code --root /opt/apps
vet endpoint scan --kind oss-package --exclude '**/build/**'
vet endpoint scan --kind oss-package --with vulns    # opt in to more than malware
vet endpoint status                                  # last run, baseline size, pending sync, findings
vet endpoint scan --kind oss-package --report-json inventory.json
```

`vet scan -D <dir>` stays the project scanner. When `-D` points at a very
large tree (a heuristic on inode count during the walk), vet prints a hint
that points to `vet endpoint scan --kind oss-package`. We do not silently
change what `vet scan` does.

Default roots, per OS user: home directory, plus known global locations
(global `node_modules`, `pipx`, `uv` tool dirs, Homebrew cellar, Go module
cache, Cargo registry). Default exclusions: `.git`, `.Trash`, browser
profiles, VM images, `.cache` subtrees that hold no package artifacts, files
over a size cap. The scan prints the roots and the exclusions it used.

### 4.4 First run

```text
$ vet endpoint scan --kind oss-package
Indexing /home/user1 (first run, this builds the baseline)
  walked 2.1M files in 1,842 dirs of interest, 6m12s
  found 1,317 manifests, 41,220 installed packages, 28,904 unique versions
Matching 28,904 versions against SafeDep threat intelligence
  2 malicious, 0 suspicious

MALICIOUS  pkg:npm/evil-colors@1.4.1
  installed  /home/user1/code/web-app/node_modules/evil-colors  (project: web-app, user: user1)
  declared   /home/user1/code/web-app/package-lock.json:1042
  verdict    SafeDep verified malware, analysis 01J...  https://platform.safedep.io/...
  fix        remove the package and rotate any secrets the postinstall could read

Baseline saved. Synced 28,906 events to SafeDep Cloud (invocation 7f3c...).
```

### 4.5 Every later run

```text
$ vet endpoint scan --kind oss-package
Delta against baseline of 2026-09-01 22:00: +214 -37 packages in 3 projects, 41s
  0 malicious, 0 suspicious in the delta
Synced 251 events.
```

And the retroactive case, which needs no walk at all:

```text
$ vet endpoint scan --kind oss-package
Delta: no filesystem change.
Threat intelligence flagged 1 package version that is in your baseline:
MALICIOUS  pkg:pypi/requests-helpers@0.3.2  installed /home/user1/.venvs/ml/lib/python3.12/site-packages/...
```

### 4.6 Fleet view (Endpoint Hub)

- Endpoint page: inventory snapshot (kind `OSS_PACKAGE`), count by ecosystem,
  malicious findings with path, project, user, first seen, last seen.
- Fleet query: "endpoints with purl X" and "endpoints with any malicious
  package", already the shape of `ListEndpointsByComponent`.
- Alert: when the maldb gains a verdict for a purl that any endpoint holds,
  open a finding on that endpoint (cloud-side retroactive match, R6 and R7).
- Health: last successful scan per endpoint and user, baseline age, scan
  duration trend, so IT sees a broken rollout.

### 4.7 Success metrics

| Metric | Target |
|---|---|
| First full scan, 400 GB tree, laptop | < 30 min |
| Incremental scan, no change | < 30 s |
| Incremental scan, one project changed | < 1 min |
| Peak RSS | < 500 MB independent of tree size |
| Time from maldb verdict to fleet finding | < 24 h with a daily schedule, < 1 h with cloud-side matching |
| Network calls per scan | proportional to changed unique versions, not to manifests |
| MDM rollout | one script, no per-machine config |

## 5. Solution options

Each option is a building block. The final design composes several. For
each: what it is, what it solves, what it costs, and where it fails.

### Option A. Fix `vet scan -D` in place

Parallel directory walk, a per-run purl cache so each unique version is
enriched once, batch or bounded concurrency across manifests, hard deadlines
everywhere, skip lists and size caps, a memory-bounded reporter path.

- Solves: the four hours and the hang for the current command. Days of work.
- Does not solve: installed packages, baseline, delta, retroactive
  detection, fleet view. It stays a one-shot project scanner.
- Verdict: do it regardless as a quick win for CI users with monorepos.
  It is not the endpoint answer.

### Option B. New `oss-package` scanner kind in `vet endpoint scan`

Implement `inventory.Scanner` for OSS packages. The scanner walks the
configured roots, extracts packages from lockfiles and installed artifacts,
keeps a local baseline in the existing endpointsync SQLite file (ADR 0001) or
in `dry/localdb`, computes the delta, and emits `ITEM_OBSERVED` (plus new
`ITEM_ADDED` / `ITEM_REMOVED` lifecycle events) through the existing sinks.

Baseline and delta mechanics to brainstorm:

- Index unit is the project root (the directory that holds the manifest or
  the `node_modules` / `site-packages` root), not the file. Store per root:
  path, content hash of the manifest files, mtime, and the purl set.
- Delta step 1: walk directories only, compare mtime and a cheap manifest
  hash against the index, and rebuild only roots that changed. A directory
  walk without file reads is 10 to 50 times cheaper than the current scan.
- Delta step 2: set-diff the purls per root to produce added and removed
  items. Unique-purl diff across the whole endpoint decides what to send to
  threat intel.
- Checkpoint after every root so a killed run resumes.
- Requires: a new `InventoryItemKind` (`OSS_PACKAGE`) and a typed
  `PackageDetail` (purl, source kind, project root, manifest path, line) in
  `VetInventoryEvent`, plus `ITEM_ADDED` / `ITEM_REMOVED` event types.
  Control-tower stores them in `vet_inventory_events` with the existing
  filter columns and adds a purl column.
- Solves: R1, R4, R5, N1 to N5. Reuses orchestrator, sinks, WAL, MDM script,
  per-user attribution.
- Costs: the walker and extractors (see Option C for where they come from),
  proto and control-tower changes, a new local schema.
- Fails when: users expect `vet scan -D` to be this. Handled with the hint in
  4.3.

### Option C. Use OSV-Scalibr as the extraction engine

Bump `github.com/google/osv-scalibr` from v0.4.4 to v0.5.2 and run the
scalibr library (`scalibr.New().Scan(ctx, &scalibr.ScanConfig{...})`) as the
walker and extractor inside Option B.

What v0.5.2 gives us out of the box:

- `ScanConfig` fields: `ScanRoots`, `PathsToExtract`, `DirsToSkip`,
  `SkipDirRegex`, `SkipDirGlob`, `UseGitignore`, `MaxFileSize`, `MaxInodes`,
  `ReadSymlinks`, `StoreAbsolutePath`, `Stats`, `ErrorOnFSErrors`,
  `ExtractorOverride`. These are exactly the knobs 2.1 lacks.
- Installed-package extractors we do not have: `javascript/packagejson`
  (walks `node_modules`), `python/wheelegg`, `python/condameta`,
  `ruby/gemspec`, `go/binary`, `java/archive`, `os/homebrew`, `os/macapps`,
  `javascript/vsix`, plus every lockfile vet parses today and more
  (`pylock`, `pdm.lock`, `bun.lock`, `deno`, `.NET`, Haskell, Julia).
- Enrichers that map onto R3: `vulnmatch` (OSV), `license`,
  `transitivedependency`, `packagedeprecation`, `secrets` (a separate
  product question).
- Line numbers in inventory for most lockfiles since v0.5.1.

What it does not give us:

- No incremental or delta scanning. The walker (`internal.WalkDirUnsorted`)
  is single-threaded and has no persistent index. Delta stays ours, built
  around scalibr: the index in Option B decides the changed roots and feeds
  them as `PathsToExtract` (or one `ScanRoot` per changed root).
- No malware verdicts. Matching stays with SafeDep (Options D and E).
- v0.5.x carries a breaking config refactor (central `PluginConfig`, plugin
  list API changes) and requires Go 1.26.3 (vet is on 1.26.2). Expect a
  half-day of build breakage in `pkg/parser`.

Two ways to use it:

- C1. Library inside the new scanner only. `vet scan` keeps its parsers.
  Lowest risk. Two extraction stacks live side by side.
- C2. Migrate `pkg/readers` and `pkg/parser` to scalibr as the single
  extraction core, with a `scalibr.Inventory` to `models.PackageManifest`
  adapter. One stack, all of scalibr's ecosystems for every reader, at the
  price of a larger migration and re-validation of every parser-specific
  behaviour vet relies on (dependency graph shape, dev-dependency flags,
  lockfile poisoning analyzer inputs, GitHub Actions and Terraform parsers
  that scalibr models differently).

Recommendation for the brainstorm: start with C1, decide on C2 once the
adapter exists and we have measured it on the same trees.

### Option D. Cloud-side matching on the inventory

The endpoint sends only inventory (purls with paths). Control-tower keeps a
current snapshot per endpoint and user, and matches it against the maldb
and OSV continuously: at ingest time for new items, and by a job whenever the
maldb gains a verdict, for every endpoint that holds that purl.

- Solves: R2, R6, R7 with zero per-package calls from the endpoint. The
  endpoint never hangs on threat intel. Findings become cloud objects
  (alerts, assignment, exclusions) instead of a line in a terminal.
- Costs: a snapshot table keyed by (endpoint, user, purl), a matcher job,
  the `PmgPackageDecision`-shaped verdict on the endpoint page (the page
  already counts advisor events by `PackageSecurityStatus`). The endpoint
  learns the verdict on its next check-in or sync, so the local CLI output
  for the first run needs the endpoint to also ask (Option E or a bounded
  client-side query on the delta only).
- Fails when: the customer runs without cloud. Then the endpoint must match
  locally (Option E).

### Option E. Local threat-intel feed for offline matching

Publish the known-malicious purl set as a signed, versioned feed (full
snapshot plus daily deltas, or a bloom filter plus a confirm RPC). vet
downloads it on a schedule and matches the baseline locally.

- Solves: R2 offline, R6 without a walk (re-match the local baseline against
  the new feed), N4. No per-package RPC at all for malware.
- Costs: a feed API that does not exist today. `MalwareAnalysisService` has
  `QueryPackageAnalysis` (one purl per call) and `ListPackageAnalysisRecords`;
  neither is a feed. Needs a decision on what the feed contains (verified
  malware only, or automated verdicts above a confidence), how exclusions
  apply, and licensing for community users.
- Fails when: the feed is stale and the machine is offline. Bound it with a
  max age and a warning.

Vulnerability data does not fit this model at endpoint scale. Keep vulns
cloud-side (Option D) or on demand.

### Option F. Continuous mode: scheduler vs. watcher

- F1. Scheduled. MDM runs the existing `scripts/mdm/vet_endpoint_scan.sh`
  hourly or daily. Delta scans make hourly cheap. No daemon, no new attack
  surface, matches the `pmg` check-in design. Optional `launchd` and
  `systemd --user` units for non-MDM fleets.
- F2. Watcher daemon. `fsnotify` on the roots, debounce, re-index the
  changed root. Near-real-time. Costs a long-running process per user, inode
  watch limits on Linux, macOS FSEvents quirks, and a supervision story.
- F3. Hook `pmg`. `pmg` already sees every install through it and has a
  `localdb`. It could append installed purls to the same baseline so the
  scheduled scan starts from a warmer index.

Start with F1. F2 is a follow-up if customers ask for sub-hour detection.

### Option G. Per-package cache in vet (the `pmg` pattern)

Port `pmg`'s `analyzer.MalysisCache` (SQLite through `dry/localdb`, benign
verdicts only, TTL) into vet's malware query enricher, and add a cross-
manifest unique-purl cache in `pkg/scanner`.

- Solves: the 600-lookups-for-one-purl problem in both `vet scan` and the
  new scanner, and shares one code path with `pmg`.
- Does not solve: the walk, the baseline, retroactive detection.
- Cheap and independent. Belongs in Option A and in Option B's verdict step.

### Option H. Batch verdict RPC

Add `BatchQueryPackageAnalysis` (100 purls per call) to
`MalwareAnalysisService`, mirroring `SyncEventsRequest` limits. Cuts round
trips 100x for whoever still queries from the client.

- Cheap on the API side, moderate on malysis. Useful for Option A and for
  the first-run CLI output in Option B. Redundant once D or E exists for the
  endpoint case.

## 6. Comparison

| Option | Walk cost | Verdict cost | Baseline / delta | Retroactive (R6) | Fleet (R7) | Offline | Effort |
|---|---|---|---|---|---|---|---|
| A. Fix `vet scan -D` | Better | Better with G | No | No | No | No | S |
| B. `oss-package` scanner | Index once, delta after | Depends on D/E/G | Yes | With D or E | With D | Inventory yes | M |
| C1. Scalibr in scanner | Same walker, more extractors | n/a | Ours | n/a | n/a | Yes | S |
| C2. Scalibr core | Same | n/a | Ours | n/a | n/a | Yes | L |
| D. Cloud matching | n/a | Zero on endpoint | Cloud snapshot | Yes | Yes | No | M |
| E. Local feed | n/a | Zero RPC | Local | Yes | No | Yes | M + API |
| F1. Scheduled | n/a | n/a | Needs B | Needs D/E | n/a | Yes | XS |
| F2. Watcher | Lowest | n/a | Needs B | Needs D/E | n/a | Yes | M |
| G. Verdict cache | n/a | Better | No | No | No | Partial | S |
| H. Batch RPC | n/a | Better | No | No | No | No | S |

## 7. Recommendation to open the brainstorm

Compose: **B + C1 + D + G + F1**, with **A** as an immediate, independent
fix, and **E** as the offline follow-up.

1. Now: Option A and G in `vet scan`. Unique-purl cache, deadlines,
   parallel walk, size caps. Ships in a release, unblocks the user today, and
   removes the hang class.
2. Slice 1: Option B with C1. `vet endpoint scan --kind oss-package`,
   scalibr v0.5.2 as the extractor, local baseline and delta, `OSS_PACKAGE`
   kind and `PackageDetail` in the proto, control-tower ingest. Verdicts for
   the CLI output come from the delta's unique purls through the cached
   query enricher (G), bounded to a fixed budget so the scan never waits on
   the network beyond it.
3. Slice 2: Option D. Cloud snapshot per endpoint and user, matcher job on
   maldb changes, findings on the endpoint page, fleet query by purl. This
   is where R6 and R7 land and where the product value is.
4. Slice 3: Option E when a customer needs offline, or when community usage
   makes per-purl queries too expensive.
5. Decide C2 after slice 1, with numbers.

## 8. Open questions for the session

1. Scope of roots. Home only, or the whole disk as root with per-user
   attribution by path owner? Container volumes and VM disks (scalibr can
   read `qcow2`, `vmdk`) in or out?
2. Which sources count as "installed" for the malware verdict: only artifact
   directories, or also package-manager caches (`~/.npm/_cacache`,
   `~/.cache/uv`) where a malicious tarball sits unpacked but not installed?
3. Verdict location. Is a finding a cloud object (Option D) or a scan-time
   CLI result? Both, and which is the source of truth?
4. Wire model. New `InventoryItemKind.OSS_PACKAGE` in `VetInventoryEvent`,
   or a new `VetPackageEvent` payload on `ToolEvent` that mirrors
   `PmgPackageDecision`, so the endpoint page's security-status counters work
   for vet with no new query paths?
5. Baseline store. The endpointsync `sync.db` (ADR 0001 reserved it) or the
   `dry/localdb` file that `pmg` uses, so `pmg` and vet can share one index
   per user (F3)?
6. Delta signal. mtime plus manifest hash per root, or a full content hash?
   How do we treat a root whose `node_modules` changed but whose lockfile did
   not?
7. Budget. What does the scan do when the walk exceeds `MaxInodes` or the
   time budget: stop and report partial with a resume marker, or continue at
   lower priority?
8. Vulnerabilities and policy. Are they in slice 1 (scalibr `vulnmatch`
   runs locally against OSV) or cloud-only in slice 2?
9. Scalibr C2. Do we want one extraction core for `vet scan`, container
   image scan, and endpoint scan, and who owns the re-validation?
10. Community users. Do they get the feed (E), a rate-limited query, or
    inventory only?
