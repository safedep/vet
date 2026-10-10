# vet endpoint audit

Audit the tools on this machine.

## Synopsis

```text
vet endpoint audit [--all-users] [--projects DIR]... [--fail-on SEVERITY|attacks] [--policy FILE] [--report FORMAT=PATH]...
                   [--strict] [--resume | --fresh] [--no-cache] [--cooldown-days N]
                   [--ephemeral] [--state-dir DIR] [--cache-dir DIR] [-o FORMAT]
```

## Description

`vet endpoint audit` checks the machine that it runs on. `vet scan` checks a project and never
reads the home directory.

| What vet finds | How the report holds it |
| --- | --- |
| AI tools, coding agents, MCP servers, agent skills, Neovim plugins | Inventory records. An MCP server record holds the names of its environment variables and headers, never their values. |
| VS Code, Cursor, Windsurf and VSCodium extensions | Packages of the `vscode` or `openvsx` ecosystem. The malware control checks them. |
| Global npm packages (`~/.npm-global`, nvm, the Windows npm prefix) | Packages of the `npm` ecosystem. Every package control checks them. |
| Agent and editor config files (`.vscode/tasks.json`, `.claude/settings.json`, MCP configs, the user tasks and settings of each editor) | Manifests that the agent configuration controls read. |
| With `--projects DIR`, the agent and editor configs, build configs, fonts and images, and scripts of the repositories under `DIR` | Manifests that the agent configuration and hidden-code controls read. |

The table counts the tools by kind and lists each one, with its client and its path. It shows
10 rows. `vet report show --all` lists every tool.

vet reads the home directory of the current user. `--all-users` reads the home directory of every
user and the machine-wide global packages (`/usr/local/lib/node_modules` and others). It needs
root: run it with `sudo`. Under sudo, vet keeps its state in the directories of root.

`--projects DIR` also checks the repositories under `DIR`. Repeat it for more folders. A worm such
as PolinRider adds its loader to the build configs of each repository on an infected machine, and
the audit finds each one. vet skips `node_modules`, `.git` and other folders that hold no file of
the project, and it does not read the source files. A path that does not exist exits 2.

The target key is `endpoint:<hostname>`. `vet report show`, `vet report list` and
`vet report diff` work on the audits of the machine as on the scans of a project. The gate,
the policy, the reports and the state flags work as in `vet scan`.

vet keeps the inventory in the local report. With `plugins.cloud-inventory.enabled: true`, vet also
writes the inventory of each audit to `inventory-sync.wal` in the state directory, with mode 0600,
for SafeDep Cloud. The sync is a stub until its contract exists, so the report gets an
`inventory_sync_unavailable` diagnostic and the batches wait in the log. The log keeps the last 50
audits.

## Examples

```text
vet endpoint audit
vet endpoint audit --fail-on high -o json
vet endpoint audit --projects ~/code --fail-on attacks
sudo vet endpoint audit --all-users --report sarif=endpoint.sarif
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The audit completed, and the gate passed or no gate was set. |
| 1 | The gate failed. |
| 2 | A flag is not valid, `--all-users` runs without root, or a `--projects` folder does not exist. |
| 3 | A runtime error. |
| 130 | A signal stopped the audit. It continues on the next run. |
