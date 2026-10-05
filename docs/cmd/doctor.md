# vet doctor

Check the state, the config, the credentials and the endpoints.

## Synopsis

```text
vet doctor [--fix] [--state-dir DIR] [--cache-dir DIR] [-o table|plain|json|jsonl]
```

## Description

`vet doctor` checks that vet can work. Each check has a stable id, a status (`pass`, `warn` or
`fail`), a message and a fix. vet prints one line for each check, with an icon for its status, and
a `›` line with the fix under a check that did not pass. `-o json` returns the list for agents.

| Check | What it checks |
| --- | --- |
| `vet.version`, `vet.release` | The version of vet, and whether a newer release of the same major version exists. An alpha build compares with the newer alpha builds. |
| `config.file` | The config file loads and has no unknown key. |
| `github.token` | The GitHub token and its source: `GITHUB_TOKEN`, `GH_TOKEN` or `gh auth token`. With no token, vet calls the GitHub API anonymously, with 60 calls an hour. |
| `install.path` | The vet that PATH finds first is this vet. |
| `plugins` | Each `plugins` section names a built-in plugin and has valid options. `codeusage` needs a vet build with CGO. |
| `state.dir` | The state directory exists and vet can write to it. |
| `state.filesystem` | The state directory is on a local file system. SQLite is not safe on a network file system. |
| `state.index` | The scan index opens. |
| `state.mode` | The state directory has mode 0700. |
| `state.scans` | Each scan has its file and its index entry, and no scan is marked running after its process stopped. |
| `state.size` | The scans are under the `state.retention.max_size` limit. |
| `credentials` | The SafeDep credentials: anonymous, or the tenant, the source and the profile. |
| `endpoint.insights`, `endpoint.malysis` | The SafeDep Insights and Threat Intel endpoints answer in 5 seconds. |

`--fix` repairs the state: it marks a scan whose process stopped as interrupted, adds index entries
for scan files that have none, removes the entries whose file is gone, sets the directory mode to
0700, and applies the retention rules over the size limit. It never deletes a completed scan. That
needs `vet state delete`.

## Examples

```text
vet doctor
vet doctor --fix
vet doctor -o json
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | No check failed. A check can warn. |
| 1 | A check failed. |
| 2 | A flag is not valid. |
