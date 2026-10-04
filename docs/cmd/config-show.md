# vet config show

Show the effective config.

## Synopsis

```text
vet config show [--origin] [-o table|plain|json|jsonl]
```

## Description

`vet config show` shows each key of the effective config with its value. vet builds the config from
the defaults, the managed file, the user file (or `--config`), the `VET_*` variables and the flags,
from the lowest layer to the highest. `--origin` adds the source of each value. `-o json` always
holds the source of each value and the directories of vet with the rule that chose each one.

## Examples

```text
vet config show
vet config show --origin
vet config show -o json
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | vet showed the config. |
| 2 | The config or a flag is not valid. |
