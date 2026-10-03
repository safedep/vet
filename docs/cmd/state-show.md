# vet state show

Show the state and cache directories, the scans and the retention rules.

## Synopsis

```text
vet state show [--state-dir DIR] [--cache-dir DIR] [-o table|plain|json|jsonl]
```

## Description

`vet state show` shows where vet keeps its scan state and its enrichment cache, and the rule that
chose each directory: a flag, a `VET_*` variable, the config file or the default. It shows the
number of scans, the number of targets and their size, each interrupted scan that the next
`vet scan` can continue, the number of cache entries and their size, and the retention rules. The
table wraps a long value in a narrow terminal.

## Examples

```text
vet state show
vet state show -o json
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | vet showed the state. |
| 2 | A flag or a directory is not valid. |
| 3 | vet could not read the state. |
