# vet MDM Scripts

Run [`vet endpoint scan`](https://github.com/safedep/vet) across a fleet through
an MDM (Jamf, Mosyle, Kandji, Intune, JumpCloud), so every user's AI-tool and
MCP inventory reaches SafeDep Cloud.

## Layout

| File | Purpose |
| --- | --- |
| `vet_endpoint_scan.sh` | One file, Linux and macOS. Scans every local user (as root) or the current user, and syncs to SafeDep Cloud. |
| `tests/vet_endpoint_scan_test.sh` | Behavior tests that run as a normal user. |

## Execution model

The script detects how the MDM invoked it:

- **As root** (typical MDM): it scans every local human account, each in its own
  context via `sudo -u`. HOME and per-user config resolve as that user, and
  `vet` — running as the user — reports the OS username and uid on each event,
  so the cloud attributes the inventory to the right user on a shared machine.
- **As the logged-in user** (a "run as current user" payload, or a person
  running it by hand): it scans just that user, with their full login
  environment. This is the highest-fidelity mode for CLI-tool discovery, which
  reads the user's `PATH`.

Target users:

- **Linux**: local accounts from `/etc/passwd` with UID ≥ `UID_MIN`
  (`/etc/login.defs`, default 1000) and a home under `/home`.
- **macOS**: local accounts from Directory Services with UID ≥ 500 and a home
  under `/Users`.

## Usage

```sh
# Local inventory only (no cloud sync), every user:
sudo ./vet_endpoint_scan.sh

# With cloud sync — pass credentials in the environment:
sudo SAFEDEP_API_KEY=... SAFEDEP_TENANT_ID=... ./vet_endpoint_scan.sh

# Forward flags to `vet endpoint scan`:
sudo ./vet_endpoint_scan.sh --silent --kind ai-tool
```

Cloud sync turns on only when `SAFEDEP_API_KEY` and `SAFEDEP_TENANT_ID` are both
set. The keys are streamed into each per-user scan over stdin — never through
argv or a shared environment — so they do not leak through `ps` on a multi-user
host. Set both or neither; a half-set pair is rejected.

The script needs `vet` already installed. It resolves the binary from `PATH`,
then falls back to `/usr/local/bin/vet` and `/opt/homebrew/bin/vet` (root's
`PATH` under an MDM is often minimal).

A failed scan for one user is non-fatal: the script warns, continues, and
reports how many users it scanned.

### macOS note

Per-user scans run under `sudo -u <user> -H`, so `vet`'s file-based discovery
(MCP servers, coding agents, skills, project configs) resolves against each
user's home. CLI-tool discovery reads the user's `PATH`; for full fidelity there,
run the script as the logged-in user via an MDM user-context payload.

## Tests

```sh
bash tests/vet_endpoint_scan_test.sh
```

The tests run as a normal user and cover the OS guard, binary resolution,
credential handling, the current-user scan path (with a mock `vet`), and the
Linux user-enumeration filter. CI runs them on Linux and macOS, plus
`shellcheck`.
