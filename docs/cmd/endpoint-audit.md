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
| Global npm packages (`~/.npm-global`, nvm, volta, fnm, asdf, mise, the Windows npm prefix) | Packages of the `npm` ecosystem. Every package control checks them. |
| Agent and editor config files (`.vscode/tasks.json`, `.claude/settings.json`, MCP configs, the user tasks and settings of each editor) | Manifests that the agent configuration controls read. |
| The entry scripts of the global npm (`npm/lib/cli.js`, `npm/lib/cli/entry.js`, `npm/bin/npm-cli.js`, `npm/bin/npx-cli.js`) of the user, and of the machine with `--all-users` | Manifests that the hidden-code controls read. A changed entry script runs at each npm command. |
| With `--projects DIR`, the agent and editor configs, build configs, fonts and images, and scripts of the repositories under `DIR` | Manifests that the agent configuration and hidden-code controls read. |

The table counts the tools by kind and lists each one, with its client and its path. It shows
10 rows. `vet report show --all` lists every tool.

vet reads the home directory of the current user. `--all-users` reads the home directory of every
user and the machine-wide global packages (`/usr/local/lib/node_modules` and others). It needs
root: run it with `sudo`. Under sudo, vet keeps its state in the directories of root.

`--projects DIR` also checks the repositories under `DIR`. Repeat it for more folders. A worm such
as PolinRider adds its loader to the build configs of each repository on an infected machine, and
the audit finds each one. vet skips `node_modules`, `.git` and other folders that hold no file of
the project, and it does not read the source files. It checks at most 100,000 files of each folder.
A relative path is read from the current folder. A path that does not exist, or that is not a
folder, exits 2.

The target key is `endpoint:<hostname>`. `vet report show`, `vet report list` and
`vet report diff` work on the audits of the machine as on the scans of a project. The gate,
the policy, the reports and the state flags work as in `vet scan`.

vet keeps the inventory in the local report. With credentials (`vet auth login`, or
`SAFEDEP_API_KEY` and `SAFEDEP_TENANT_ID`), vet also sends the inventory to SafeDep Cloud. Each
item names the user whose home directory holds it. An MCP server record holds the names of its
variables and headers, never their values.

- `plugins.cloud-inventory.enabled: false` turns the sync off.
- Set `plugins.cloud-inventory.options.endpoint_id` on a machine that changes on each run, such
  as a CI runner. vet otherwise names the endpoint with the host name and the machine id, as pmg
  does.
- When vet cannot reach SafeDep Cloud, the audit completes, and the report gets an
  `inventory_sync_unavailable` diagnostic. The events wait in `inventory-sync.db` in the state
  directory, and the next audit sends them.

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
| 2 | A flag is not valid, `--all-users` runs without root, or a `--projects` path is not a folder. |
| 3 | A runtime error. |
| 130 | A signal stopped the audit. It continues on the next run. |
