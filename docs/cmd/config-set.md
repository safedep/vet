# vet config set

Set a key in the user config file.

## Synopsis

```text
vet config set KEY VALUE [--config FILE]
```

## Description

`vet config set` sets a key in the user config file, or in the `--config` file. vet checks the key,
the value and the whole file before it writes, and writes through a temporary file and a rename
with mode 0600. It edits the YAML node tree, so the comments and the key order of the file stay. A
list takes values with commas, for example `vendor,testdata`. A plugin option takes a YAML scalar,
for example `plugins.dependency-cooldown.options.days 7`.

When a managed file is in force, vet sets the key and says that the user file has no effect.

## Examples

```text
vet config set policy.fail_on high
vet config set scan.exclude vendor,testdata
vet config set plugins.dependency-cooldown.options.days 7
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | vet set the key. |
| 2 | The key or the value is not valid. vet writes nothing. |
| 3 | vet could not write the file. |
