# vet version

Show the version and the build of vet.

## Synopsis

```text
vet version [-o table|plain|json|jsonl]
```

## Description

`vet version` prints the version of vet, the commit that it was built from, the Go version and the
platform on one line, for example `vet v2.0.1 (8957dc6) go1.26.3 linux/amd64`. A build from
`go install` shows the module version. A Go pseudo-version shows as `dev (<commit>)`, as in the
banner. A local build shows `devel`. `-o json` prints each field.

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
