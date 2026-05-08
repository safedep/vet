# ADR 0001: `vet endpoint scan`

Status: Accepted
Date: 2026-05-07

## Context

vet has a local AI tool discoverer (`vet ai discover`) whose output never reaches SafeDep Cloud. We need a per-endpoint inventory in the Endpoint Hub UI. Cloud-side ingestion (`VetInventoryEvent`, `vet_inventory_events` table, denormalised filter columns) and the Hub list shipped to prod on 2026-05-07. This ADR fixes the vet-side surface: command shape, sync model, credentials, and the producer architecture that subsequent endpoint scanners will share.

## Decision

### Command

- New top-level: `vet endpoint scan`. Scans the endpoint, syncs to cloud when credentials are present.
- `vet ai discover` is kept as a permanent alias for `vet endpoint scan --kind ai-tool`.
- No `--no-sync` flag. Behaviour is determined by credential presence:
  - credentials present and valid: scan, stream events to the WAL, background flusher delivers to cloud, command exits after discovery completes and the WAL has drained (bounded grace).
  - credentials present but rejected by cloud (wrong key, missing scope): scan continues; transient delivery failures are logged at the cloud-sink boundary and do not abort the scan. Undelivered events stay in the WAL up to endpointsync's pending cap and retry on the next run.
  - credentials absent: scan, render the local table, exit 0 with a one-line hint pointing at `vet auth configure` or env vars (`SAFEDEP_API_KEY`, `SAFEDEP_TENANT_ID`). The cloud sink is never constructed in this path, so no WAL is ever opened.

### Scope of `vet endpoint scan`

In scope, by milestone:

- M1: AI tools (existing `pkg/aitool` discoverers).
- Near term: IDE extensions (already emitted by `pkg/aitool` via `vsix_ext_reader`; reaches cloud as `ITEM_OBSERVED` with `kind=AI_EXTENSION`), browser extensions.
- Medium term: OS packages (brew, dnf, apt, choco), full filesystem OSS package inventory (npm, pypi and other ecosystems detected by walking the user's project trees), CycloneDX SBOM emission for the discovered inventory.

Each new kind plugs in via the `pkg/inventory/scanners` registry (`Descriptor` literal + a sub-package implementing `inventory.Scanner`); the orchestrator, sinks, and wire format are unchanged.

Out of scope, permanently:

- Anything that is not "what is installed or configured on this endpoint." Project-level vulnerability scanning stays in `vet scan`. Policy evaluation, remediation, and incident workflows live elsewhere.

### Sync model

- One `invocation_id` per scan, generated in vet, attached to every emitted event.
- Each discovered item produces one `ITEM_OBSERVED` event. End of scan emits one `SCAN_SUMMARY` event. Errors during scan emit `ERROR` events.
- Two goroutines, one durable buffer:
  - The producer goroutine (the command) runs scanners and writes events to the local `endpointsync` WAL (a SQLite file at the endpointsync default path). Each write is a local insert, on the order of microseconds. The producer never blocks on the network.
  - The consumer goroutine lives inside `endpointsync.SyncClient`. It drains the WAL and ships batches to cloud over gRPC. It runs concurrently with the producer.
  - The WAL persists across runs by design. Two reasons:
    1. Events queued while offline (or during cloud-side outages) ship on the next successful scan, preserving the audit trail of transient observations (e.g. a tool that was installed and uninstalled between two scans).
    2. The spec designates this WAL as the persistence layer for the deferred client-side-delta feature: future versions of vet will store last-scan fingerprints in this same SQLite file and emit `ITEM_ADDED` / `ITEM_REMOVED` / `ITEM_CHANGED` events. A per-scan tmp WAL would defeat that.
  - Delivered events are purged after every successful Sync; undelivered pending events are bounded by endpointsync's `defaultMaxPending = 100_000` ceiling so the on-disk footprint cannot grow without bound.
- End of scan: the command calls `Close` on the cloud sink, which waits for the WAL to drain up to a bounded deadline (default 30s, configurable). If the deadline hits, undelivered events stay in the WAL and ship on the next run.

### Credentials

1. vet env vars: API key from `VET_API_KEY` / `SAFEDEP_API_KEY` / `VET_INSIGHTS_API_KEY`, tenant from `SAFEDEP_TENANT_ID` (the canonical name) or its `VET_*` alias. Both halves required.
2. vet's `~/.safedep/vet-auth.yml` (existing legacy file; respected if present but won't be extended).
3. DRY keychain provider, constructed without an insecure file fallback. On WSL/headless Linux where no OS keyring is reachable, this layer falls through silently to step 4.
4. Fail with a hint: "SafeDep cloud sync available; run `vet auth configure` or set `SAFEDEP_API_KEY` and `SAFEDEP_TENANT_ID` to enable."

A layer that holds one half of a credential pair (key without tenant, or vice versa) returns `ErrIncompleteCredentials` and stops the chain. The user clearly intended that layer; missing the other half is a configuration error, not a fall-through trigger.

vet's `vet-auth.yml` is the legacy insecure store. It is not deprecated by this ADR but no new write paths are added to it. Headless and WSL environments are served by env vars.

### Producer architecture

A new package, `pkg/inventory`, owns the producer pipeline. Three concepts:

- `Item`: domain struct mirroring the proto `VetInventoryEvent.ItemObserved` 1:1 (kind, identity, source id, name, app, scope, config path, enabled, optional typed details, metadata). Scanners emit `*Item`. The wire proto is not used as the in-process type.
- `Scanner`: `Scan(ctx, ScanConfig, emit func(*Item) error) error`. The orchestrator iterates a `[]Scanner`. Adding a new scanner kind is one new implementation plus one registration.
- `Sink`: `Begin(Session) → Emit(*Item) → End(ScanSummary) → Close`. The orchestrator owns session lifecycle (invocation_id, started_at, counts), fans each item to all sinks, builds the summary. M1 sinks: `LocalSink` (table, `--report-json`), `CloudSink` (wraps `endpointsync.SyncClient`).

Constraints on the implementation:

- The orchestrator is single-goroutine. Scanners run serially, items fan to sinks in registration order, sinks are not required to be thread-safe. Concurrency between the producer and cloud delivery comes from the `endpointsync` flusher goroutine (see Sync model).

  Parallel scanner execution is not in M1; if a future scanner's runtime justifies it, parallelism slots in via `errgroup` over `[]Scanner` and sinks gain a thread-safety requirement at that point.

- `CloudSink.Emit` writes to the WAL and returns. It does not call gRPC, does not retry, does not block on the network. Retry and backoff are owned by `endpointsync`.

- Transient sink errors (a WAL write that fails, a cloud delivery rejection inside the flusher) are logged and do not abort the scan. Only fatal or programming errors propagate up.

- The orchestrator never sees `*AITool` or wire proto types. Translation `*AITool` to `*Item` lives in one adapter (`pkg/inventory/scanners/aitool`); translation `*Item` to wire proto lives in `CloudSink`.

For M1, AI tool discovery is wired in by a single `Scanner` that wraps `aitool.Registry.Discover`. Existing readers under `pkg/aitool` are unchanged.

## Consequences

- Forward path is open. When `aitool.Registry` folds into the orchestrator, each existing reader becomes a `Scanner` directly, the adapter is deleted, and the orchestrator, sinks, and cmd code are unchanged.
- New scanner kinds (browser extensions, OS packages, filesystem OSS) plug into `[]Scanner` without changes to ingestion, sinks, or the wire format. The proto's `InventoryItemKind` enum already reserves slots.
- `vet ai discover` users on the upgrade path who have cloud credentials configured will start syncing automatically. Documented in the changelog.

## Open

- Whether `vet endpoint status` is added in a follow-up.
- Whether and when vet's `vet-auth.yml` writes are deprecated.

Not recorded in this ADR.
