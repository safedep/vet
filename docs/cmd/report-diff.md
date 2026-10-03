# vet report diff

Compare the findings of two saved scans.

## Synopsis

```text
vet report diff [BASE [HEAD]] [--state-dir DIR] [-o table|plain|json|jsonl]
```

## Description

`vet report diff` compares two saved reports by finding id. It lists the findings that HEAD adds and
the findings that it removes, the number of findings that both have, and the packages that HEAD
adds and removes. A suppressed finding does not count.

With no argument, BASE and HEAD are the last two completed scans of the current directory. With one
argument, HEAD is the last scan. An argument is a scan id prefix, `last` or a report file.

A pull request scan holds only the findings of the changes. vet warns when it compares a pull
request scan with a full scan, because the diff is then not complete.

## Examples

```text
vet report diff
vet report diff 9b11 7f3a
vet report diff base.json head.json -o json
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | vet compared the reports. |
| 2 | The current directory has fewer than two completed scans, or no scan matches an argument. |
| 3 | vet could not read a saved scan. |
