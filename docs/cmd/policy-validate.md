# vet policy validate

Check a policy file.

## Synopsis

```text
vet policy validate [FILE] [-o table|plain|json|jsonl]
```

## Description

`vet policy validate` checks a policy v2 file, or each `.yml` and `.yaml` file of a directory: the
version, the id, the CEL condition and the action of each rule, and the selectors, the reason and
the expiry of each suppression. A rule id must be unique across the files. vet lists every problem
in one error. The default is the file of the `policy.file` config key. validate changes nothing.

## Examples

```text
vet policy validate vet-policy.yml
vet policy validate policies/ -o json
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The policy is valid. |
| 2 | The policy is not valid, the file does not exist, or no file is named. |
