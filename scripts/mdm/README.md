# vet MDM Scripts

Run `vet endpoint scan` across a fleet through an MDM (Jamf, Mosyle, Kandji,
Intune, JumpCloud), so every user's AI tool and MCP inventory reaches SafeDep
Cloud.

## Files

| File | Purpose |
| --- | --- |
| `vet_endpoint_scan.sh` | One script for Linux and macOS. Scans every local user (as root) or the current user, then syncs to SafeDep Cloud. |
| `tests/vet_endpoint_scan_test.sh` | Behavior tests that run as a normal user. |

## How it runs

The script detects how the MDM invoked it.

As root (the typical MDM case), it scans every local human account. Each scan
runs in that user's own context with `sudo -u`, so the home directory and
per-user config resolve as that user. `vet` runs as the user and reports the OS
username and uid on each event, so the cloud attributes the inventory to the
right user on a shared machine.

As the logged-in user (a "run as current user" payload, or a person running it
by hand), it scans just that user with their full login environment. This is the
best mode for CLI tool discovery, which reads the user's `PATH`.

Target users:

- Linux: accounts from `getent passwd` (NSS, so local accounts plus directory
  users from LDAP, SSSD, or AD) with a UID of `UID_MIN` (`/etc/login.defs`,
  default 1000) or higher, a real home under `/home`, and a login shell.
  Accounts with a `nologin` or `false` shell are skipped.
- macOS: local accounts in Directory Services with a UID of 500 or higher, and
  a home under `/Users`.

## Usage

```sh
# Local inventory only (no cloud sync), every user:
sudo ./vet_endpoint_scan.sh

# With cloud sync. Pass the credentials in the environment:
sudo SAFEDEP_API_KEY=... SAFEDEP_TENANT_ID=... ./vet_endpoint_scan.sh

# Forward flags to `vet endpoint scan`:
sudo ./vet_endpoint_scan.sh --silent --kind ai-tool
```

Cloud sync turns on only when both `SAFEDEP_API_KEY` and `SAFEDEP_TENANT_ID` are
set. The script streams the keys into each per-user scan over stdin, never
through argv or a shared environment, so they do not leak through `ps` on a
multi-user host. Set both or neither. A half-set pair is rejected.

The script needs `vet` already installed. It resolves the binary from `PATH`,
then falls back to `/usr/local/bin/vet` and `/opt/homebrew/bin/vet`, because
root's `PATH` under an MDM is often minimal.

A failed scan for one user is not fatal. The script warns, continues, and
reports how many users it scanned.

## macOS note

Per-user scans run under `sudo -u <user> -H`, so file based discovery (MCP
servers, coding agents, skills, project configs) resolves against each user's
home. CLI tool discovery reads the user's `PATH`. For full fidelity there, run
the script as the logged-in user through an MDM user-context payload.

## Tests

```sh
bash tests/vet_endpoint_scan_test.sh
```

The tests run as a normal user. They cover the OS guard, binary resolution,
credential handling, the current-user scan path (with a mock `vet`), and the
Linux user-enumeration filter. CI runs them on Linux and macOS, plus
`shellcheck`.
