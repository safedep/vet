# Design: local malicious-package feed for offline malware protection in vet and pmg

**Date:** 2026-09-02
**Status:** Draft, for brainstorm
**Area:** cross-cutting: `api`, `dry`, `control-tower`, `pmg`, `vet`
**Companion to:** [extraction trade-offs](2026-09-02-extraction-engine-tradeoffs.md),
[endpoint filesystem scan design](2026-09-02-endpoint-filesystem-oss-package-scan-design.md)

## 1. Problem

Both tools decide "is this package version malicious" with one gRPC call per
package to `MalwareAnalysisService.QueryPackageAnalysis`. When SafeDep Cloud
is unreachable, both tools fail open.

- pmg: `proxy/interceptors/base_registry.go` wraps the call in a 10 s timeout
  and a circuit breaker. `NotFound` is "allow". Any other error, including a
  timeout or an open breaker, is logged and the package is allowed. pmg's
  persistent cache (`analyzer/malysiscache`) stores benign verdicts only, so
  it cannot block anything offline.
- vet: `pkg/scanner/enrich_malware_query.go` returns the error, the scanner
  logs it, the package has no result, and `pkg/analyzer/malware.go` treats
  a missing result as "not malware".

A backend outage, a captive portal, a corporate proxy that drops gRPC, or a
laptop on a plane turns malware protection off. The user asked for the
opposite: protection that works when the backend is offline. A local copy
of the malicious set is the way to get it. "Bloom filter based local
caching" is close to the right name. The precise name is a local threat
feed served through a probabilistic membership filter. It is a feed, not a
cache, because the server pushes knowledge the client has not asked for.
The filter is the data structure that makes the feed small.

## 2. What the tools need from a verdict

Read from the code, not from the proto.

| Field | pmg (`analyzer/malysis_query.go`) | vet (`pkg/analyzer/malware.go`) |
|---|---|---|
| `report.inference.is_malware` | flags the package. Action `Confirm` (prompt), or `Block` with `--paranoid` | required for any flag |
| `verification_record.is_malware` | `Block`, sets `IsVerified` | malicious |
| `report.inference.confidence` | not read | with `--malware-trust-tool-result`, malicious when at or above `--malware-analysis-min-confidence` (default HIGH), else suspicious |
| `malicious_package_exclusion` | downgrades a flag to `Allow` (authenticated only) | skips the result |
| `analysis_id` | report URL in the block message and audit log | report URL and `SD-MAL-` id in reports |
| `inference.summary` | block message and audit log | markdown and JSON reports |
| `NotFound` | allow | no result, not flagged |
| transport error | allow | no result, not flagged |

So the offline decision needs four bits per package version: known, verified,
inference-malicious, high confidence. The display fields (`analysis_id`,
`summary`) are needed only on a hit, and hits are rare. Exclusions are per
tenant and small.

## 3. What the server serves

`services/malysis/query_adapter.go` and `models/malware_analysis.go` define
the serving rules the feed must reproduce.

- Table `malware_analyses`, unique on `(ecosystem, name, version)`. About
  20 million rows. Sources: `malysis` (analyses), `osv` (imported `MAL-*`
  advisories), `static_records` (2,571 YAML verification records in
  `etl/maldb/fs`), and `malysis_verdict` (verdict events).
- A row is served when `status = COMPLETED`, `dirty = false`,
  `withdrawn_at IS NULL`, `expires_at IS NULL OR expires_at > now()`, and
  it is not a stale legacy false positive (unverified `is_malware` rows not
  updated in 30 days).
- `version = '0'` is a wildcard for every version of the package. The
  lookup fetches the specific row and the wildcard row and prefers the
  specific one (`pickSpecificOverWildcard`). A specific benign row therefore
  overrides a wildcard malicious row.
- `verified = true` rows produce a `VerificationRecord`. Proposed verdicts
  from Malysis are `is_malware = true, verified = false` with an
  `expires_at`, and are served as suspicious until then.
- Exclusions are per tenant, keyed on `(ecosystem, name, version | "*")`,
  with their own expiry, and only for tenants with the exclusions feature.

Only the malicious rows matter for the feed. At most 5 percent of 20
million is 1 million. The likely number is lower.

## 4. How a filter holds a million purls in a few megabytes

A filter answers one question: "is this key in the set?" It never stores
the key. It stores a few bits per key that a hash of the key selects.

- Bloom filter. An array of `m` bits and `k` hash functions. Insert sets
  the `k` bits the hashes pick. Lookup checks them. If any bit is clear, the
  key is not in the set, with certainty. If all are set, the key is
  probably in the set. The size depends only on the number of keys and the
  false positive rate `p`, not on key length: `m = -n ln p / (ln 2)^2`.
  At `p = 1e-4` that is 19.2 bits per key. One million purls cost 2.4 MB.
  Twenty million cost 48 MB. A 40 byte purl string costs 320 bits; the
  filter spends 19.
- Binary fuse filter (the successor to xor filters). Stores one fingerprint
  of 8, 16, or 32 bits per slot with 1.125 slots per key. Lookup XORs three
  fingerprints and compares. Smaller and faster than a bloom filter at the
  same `p`, but immutable: build once from the full key set on the server.
- Both give zero false negatives. A malicious purl that is in the feed is
  always reported. The only error is a false positive, which the client
  resolves with one online query, or reports as "unconfirmed" offline.

Measured on this session's container with `FastFilter/xorfilter` v0.5.1
and `bits-and-blooms/bloom` v3.7.1 over synthetic purls, false positives
measured against two million keys not in the set:

| Filter | 1M keys | 20M keys | Measured false positive rate | Build time (20M) | Probe |
|---|---|---|---|---|---|
| Binary fuse, 8-bit | 1.1 MB | 22.5 MB | 3.9e-3 | 7.0 s | 16 ns to 78 ns |
| Binary fuse, 16-bit | 2.3 MB | 45.1 MB | 2.1e-5 | 6.6 s | |
| Binary fuse, 32-bit | 4.5 MB | 90 MB | about 2e-10 (computed) | | |
| Bloom, p = 1e-4 | 2.4 MB | 47.9 MB | 1.0e-4 | | |
| Exact, 64-bit hash key in SQLite | 16.5 MB | 330 MB | 0 | | 8.6 us |
| Exact, purl text in SQLite | 45.5 MB | 910 MB | 0 | | |

That is the 45 MB in the question: a 16-bit binary fuse filter over all 20
million records. The malicious subset is 20 to 50 times smaller.

## 5. Design

### 5.1 Feed contents

A snapshot is a small set of files plus a signed manifest.

| File | Keys | Filter | Why |
|---|---|---|---|
| `verified.bf32` | `eco/name@version` and `eco/name@*` for rows with `is_malware = true, verified = true` | binary fuse, 32-bit | A hit here can block offline. The false positive rate must be effectively zero: 2e-10 means no wrong block in the life of the product. 4.5 MB at one million keys, under 2 MB at the likely size. |
| `unverified.bf16` | same key shape for `is_malware = true, verified = false` that the serving predicates admit | binary fuse, 16-bit | A hit here prompts or marks suspicious, never blocks. 2e-5 false positives cost one prompt per 50,000 packages. |
| `benign-overrides.txt` | specific versions with `is_malware = false` whose package has a wildcard malicious row | plain list, tiny | Reproduces `pickSpecificOverWildcard`. |
| `delta-<from>-<to>.txt` | added and withdrawn keys since a snapshot, one per line with a `+` or `-` prefix | plain list | Daily change is thousands of lines, kilobytes. |
| `manifest.json` | version, generated_at, row counts, file hashes, filter parameters, hash seed, minimum client version, `max_age` | signed (Ed25519 or cosign) | Tamper and rollback protection. A client refuses an unsigned or older manifest. |

Keys are canonical purls without qualifiers. The client and the builder
share one canonicaliser in `dry` (npm names lowercased, PyPI names PEP 503
normalised, ecosystem as the `packagev1.Ecosystem` enum name). A mismatch
here is a silent miss, so the canonicaliser gets a fixture test on both
sides with the same vectors.

Exclusions are not in the feed. An authenticated client fetches its
tenant's exclusion list (hundreds of rows at most) with the manifest and
applies it after a hit, as `applyExclusion` does today.

### 5.2 Lookup

```text
Lookup(pv):
  k1 = canonical(pv), k2 = canonical(pv without version) + "@*"
  if k1 in withdrawn overlay          -> Miss
  if k1 in benign overrides           -> Miss
  if k1 or k2 in verified.bf32 or in added overlay (verified)   -> HitVerified
  if k1 or k2 in unverified.bf16 or in added overlay (unverified) -> HitUnverified
  -> Miss
```

The overlay is a small SQLite table in `dry/localdb`, filled from delta
files between snapshots. The filters stay immutable. Same-day retractions
work through the withdrawn overlay, which a bloom filter alone could not
give.

`Lookup` also returns the feed version and age. A `Miss` from a feed older
than `max_age` is reported as `Unknown`, not `Miss`.

### 5.3 Decision tables

pmg, per package at install time:

| Feed | Online query | Result |
|---|---|---|
| HitVerified | succeeds | as today: Block, with `analysis_id` and summary from the response, exclusion applied |
| HitVerified | fails or times out | Block, with the feed version as evidence and a generic summary. This is the new behaviour. |
| HitUnverified | succeeds | as today: Confirm, or Block under `--paranoid` |
| HitUnverified | fails | Confirm, with "unconfirmed, feed vN" in the prompt |
| Miss, feed fresh | succeeds | as today, the online verdict. New and unanalysed packages still get an online look. |
| Miss, feed fresh | fails | Allow, as today, plus a warning that names the feed version. The user knows the package is not in the known malicious set as of that date. |
| Unknown (feed stale or absent) | fails | Allow, as today, plus a doctor warning |

vet, `vet scan --malware-query` and the endpoint scan:

- Every package goes through `Lookup` first. Misses make no network call
  by default. This alone removes the per-package round trip that made the
  400 GB scan take four hours.
- Hits query online for the report and the exclusion. Offline, a hit is
  reported with the feed evidence and no report body.
- `--malware-query-all` keeps today's behaviour of querying every package,
  for users who want inference results for unknown packages.
- The endpoint scan re-runs `Lookup` over its stored baseline whenever the
  feed version changes. That is retroactive detection with no filesystem
  walk and no network per package.

### 5.4 Client library

`dry/threatfeed` (name open), shared by vet and pmg.

- `Fetch(ctx)`: download the manifest, verify the signature, download the
  files whose hash changed, apply deltas, or fall back to a full snapshot.
  Respect `ETag`. Store under the tool's cache dir through `dry/localdb`,
  module `threatfeed`: manifest, filter blobs, overlay table, exclusion list.
- `Lookup(pv) Decision`: as in 5.2. Under one microsecond, no allocation.
- `Status()`: version, generated_at, age, counts, last fetch error. Surfaces
  in `pmg setup doctor`, `pmg setup cache status`, `vet endpoint status`.
- Refresh policy: at process start if older than an hour, in the
  background, never blocking a package decision. MDM fleets can pre-seed
  the files.

### 5.5 Server

- A control-tower job (River, hourly) runs the serving predicates over
  `malware_analyses`, builds the three key sets, writes the filters (about
  a second at one million keys, seven at twenty million), computes the
  delta against the previous snapshot, signs the manifest, and uploads to
  object storage behind the CDN.
- API: `MalwareFeedService.GetFeedManifest` returns the manifest and signed
  URLs. Unauthenticated (community) access serves the same feed. The
  malicious set is the same knowledge OSV publishes as `MAL-*` advisories.
  Authenticated access adds the tenant exclusion list. Alternatively a
  fixed public URL with no RPC at all. The RPC is better because it can
  carry the exclusion list and rate the client version.
- Optional: `BatchQueryPackageAnalysis` for confirming a batch of hits in
  one call. Hits are rare, so this is a later optimisation.

### 5.6 What does not change

- The online path, the report format, the exclusion semantics, and the
  `SD-MAL-` ids.
- pmg's benign verdict cache. It still removes online calls for packages
  the feed does not cover.
- Who decides. A hit is a fact about the feed. The action is decided by
  the same code as today.

## 6. Trade-offs

- Size versus certainty. 32-bit fingerprints on the verified set cost
  double the bytes of 16-bit and buy a false positive rate that never
  produces a wrong offline block. Take it.
- Freshness. A daily snapshot plus hourly deltas gives a worst case of one
  hour between a verdict landing in `malware_analyses` and a fleet knowing
  it, if the client refreshes hourly. Today the worst case is zero online
  and infinite offline.
- Immutable filter plus overlay versus a mutable structure. A cuckoo filter
  supports delete in place but costs more bits at the same `p` and is not
  as simple to ship as a blob. The overlay is a table with a few thousand
  rows. Keep the filter immutable.
- Privacy. Offline, no package name leaves the machine. Online, only hits
  are queried, so the backend sees a fraction of what it sees today. This
  matters for community users.
- Trust. The feed is a code path that can block installs on every endpoint.
  Signing, rollback protection, and a minimum client version are not
  optional. The key lives with the release signing key.
- Coverage. The feed says "known malicious". It does not say "analysed and
  benign". New packages still need the online path for Malysis to analyse
  them. A separate 20 million key filter for "analysed" is possible (22 to
  45 MB) but its false positives point the unsafe way, so it needs 32-bit
  fingerprints (90 MB) or an exact list. Decide after measuring how many
  calls the malicious feed plus the benign cache already remove.

## 7. Rollout

1. `dry`: canonicaliser, `threatfeed` fetch, verify, store, lookup, with
   fixtures shared with the builder.
2. control-tower: builder job, manifest signing, object storage upload.
   `api`: `GetFeedManifest`.
3. pmg: `threatfeed` in the analyzer chain ahead of the online analyzer,
   decision table 5.3, doctor and status output. Ship behind a config key,
   default on after one release.
4. vet: `Lookup` ahead of the malware query enricher, `--malware-query-all`,
   endpoint scan re-match on feed change.

## 8. Open questions

1. Feed name and package name in `dry`.
2. Community access to the feed: open, or behind a free key for rate
   control.
3. Whether unverified proposed verdicts belong in the feed at all, or only
   verified ones. Including them makes offline behaviour match online
   behaviour. Excluding them makes the feed smaller and the false positive
   budget simpler.
4. Signing mechanism: Ed25519 key in the binary, or cosign with the release
   identity.
5. Hourly deltas versus daily only.
6. Whether the endpoint scan should send its baseline to the cloud for
   server-side matching as well (companion design, option D), or rely on
   the feed alone.
