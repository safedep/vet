# vet version

Show the version and the build of vet.

## Synopsis

```text
vet version [-o table|plain|json|jsonl]
```

## Description

`vet version` prints the version of vet, the commit that it was built from, the Go version and the
platform. A build from `go install` shows the module version. A local build shows `devel`.

## Examples

```text
vet version
vet version -o json
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | vet printed the version. |
| 2 | A flag is not valid. |
