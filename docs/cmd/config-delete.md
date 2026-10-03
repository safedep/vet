# vet config delete

Remove a key from the user config file.

## Synopsis

```text
vet config delete KEY [--config FILE]
```

## Description

`vet config delete` removes a key from the user config file, or from the `--config` file, so that
the next layer down applies. vet removes the sections that the key leaves empty, and keeps the
comments of the file. When the file has no key left, vet writes only its comments.

## Examples

```text
vet config delete policy.fail_on
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | vet removed the key. |
| 2 | The file does not set the key, or the key is not a config key. |
| 3 | vet could not write the file. |
