# vet policy init

Write a starter policy file.

## Synopsis

```text
vet policy init [NAME] [--force]
```

## Description

`vet policy init` writes a starter policy v2 file. Its rules fail the gate on malware, on a critical
vulnerability and on a dangerous workflow trigger or a template injection, and warn on a version
that the registry published in the last 5 days. Its suppression list is empty, with a commented
example.

A NAME with a `.yml` or `.yaml` extension, or with a directory, is a path, for example
`vet-policy.yml` in a repository. Another NAME writes `policies/NAME.yml` in the vet config
directory. The default NAME is `default`. vet does not replace a file that exists unless `--force`
is set.

## Examples

```text
vet policy init vet-policy.yml
vet policy init strict
vet scan . --policy vet-policy.yml
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | vet wrote the file. |
| 2 | The file exists and `--force` is not set, or a flag is not valid. |
| 3 | vet could not write the file. |
