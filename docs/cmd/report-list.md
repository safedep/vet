# vet report list

List the saved scans of the current directory.

## Synopsis

```text
vet report list [--all-targets] [--state-dir DIR] [-o table|plain|json|jsonl]
```

## Description

`vet report list` lists the saved scans of the current directory, the newest first. When the current
directory has no scan, vet looks at each parent directory in turn. Each row has the scan id, the
target, the start time, the run time, the status, the package and finding counts and the gate. A
scan that continued after an interrupt shows `(continued)`. The run time is the sum of its runs.
The table shows the first 8 characters of the scan id. In a narrow terminal, the table drops the
run time and the status first, and cuts the start of the target path. `-o json` and `-o plain`
show the full id.

`--all-targets` lists the scans of every target.

## Examples

```text
vet report list
vet report list --all-targets -o json
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | vet listed the scans. |
| 2 | A flag is not valid. |
| 3 | vet could not read the scan index. |
