# vet policy control list

List the controls and their default severities.

## Synopsis

```text
vet policy control list [-o table|plain|json|jsonl]
```

## Description

`vet policy control list` lists each control id of vet, with the plugin that emits it, its family,
its default severity, its title and what it checks. A policy rule matches a control id, a
suppression names one, and `--fail-on` compares the severity of each finding. A finding can have
another severity than the default. For example, a vulnerability finding takes the severity of its
advisory.

## Examples

```text
vet policy control list
vet policy control list -o json
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | vet listed the controls. |
| 2 | A flag is not valid. |
