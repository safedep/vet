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

The list has the key `plugins.<name>.enabled` of each plugin with a switch, also when no layer sets
it. A key that no layer sets has the built-in state of the plugin and the origin `default`. A report
format has no enabled key, because `-o` and `--report` select it. `vet config schema get` describes
each plugin and its options.

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
