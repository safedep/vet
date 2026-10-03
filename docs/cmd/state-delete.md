# vet state delete

Delete scans or the enrichment cache.

## Synopsis

```text
vet state delete [--target PATH] [--scan ID] [--older-than DURATION] [--interrupted]
                 [--cache] [--all] [--dry-run] [--yes]
                 [--state-dir DIR] [--cache-dir DIR] [-o table|plain|json|jsonl]
```

## Description

`vet state delete` deletes saved scans or the enrichment cache. vet applies its retention rules at
the end of each scan, so most users never need this command.

| Flag | Selects |
| --- | --- |
| (none) | The scans that the retention rules select now. |
| `--target PATH` | The scans of one target: a directory or a target key. |
| `--scan ID` | The scan with this id prefix. |
| `--older-than DURATION` | The scans that started before this age, for example `7d`. |
| `--interrupted` | Interrupted scans only. |
| `--cache` | The enrichment cache. |
| `--all` | Every scan and the cache. The index stays, empty. |

The scan selectors combine: a scan must match each one. vet never deletes a scan that a vet process
runs.

vet asks before it deletes. In agent mode, with `--no-input` or with no terminal, vet cannot ask:
pass `--yes`, or the command exits 2 and names the flag. `--dry-run` shows what vet would delete and
deletes nothing.

## Examples

```text
vet state delete --older-than 7d
vet state delete --interrupted --yes
vet state delete --all --dry-run -o json
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | vet deleted the selection, or showed it with `--dry-run`. |
| 2 | A flag is not valid, or vet needs `--yes` and cannot ask. |
| 3 | vet could not delete a file. |
