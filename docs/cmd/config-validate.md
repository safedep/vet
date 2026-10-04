# vet config validate

Check a config file.

## Synopsis

```text
vet config validate [FILE]
```

## Description

`vet config validate` checks a config file: the YAML, each value and each key. An unknown key is an
error here, with the closest known key, although a scan only warns about it. The default is the
config file of the run. validate changes nothing.

## Examples

```text
vet config validate
vet config validate ./ci/vet.yml
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The file is valid, or there is no config file. |
| 2 | The file is not valid or has an unknown key. |
