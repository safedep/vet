# vet report capability list

List the AI and crypto capabilities of a saved scan, with each call site.

## Synopsis

```text
vet report capability list [--tag TAG]... [--scan ID|FILE] [--state-dir DIR] [-o table|plain|json|jsonl]
```

## Description

`vet report capability list` lists the capabilities of the last scan of the current directory: the
AI SDKs, models and agent frameworks, and the cryptographic algorithms, protocols and certificates
that the code calls. Each call site has its own row, so you can open each place in the code. The
list shows AI first, then weak crypto, then the other crypto.

A scan finds capabilities only when `plugins.codeusage.enabled` is `true`. The scan view shows the
first ten of them. This command shows all of them, with no new scan.

`--tag` keeps the capabilities that have each tag. `ai`, `cryptography` and `weak` are the common
tags. `--scan` names another scan, by an id prefix, by `last` or by a report file. `-o json` prints
the whole capabilities, the same records as the report.

## Flags

| Flag | Description |
| --- | --- |
| `--tag TAG` | Keep the capabilities with this tag. Repeat the flag to keep the capabilities with all the tags. |
| `--scan ID\|FILE` | Read this scan, by an id prefix, by `last` or by a report file. |
| `--state-dir DIR` | Directory of the scan index and the scan files. |

## Examples

```text
vet report capability list
vet report capability list --tag cryptography --tag weak
vet report capability list --tag ai -o json
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | vet listed the capabilities. An empty list also exits 0. |
| 2 | A flag is not valid, or no scan matches. |
| 3 | vet could not read the saved scan. |
