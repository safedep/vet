# vet report finding show

Show one finding of a saved scan.

## Synopsis

```text
vet report finding show ID [--scan ID|FILE] [--state-dir DIR] [-o table|plain|json|jsonl]
```

## Description

`vet report finding show` shows one finding of the last scan of the current directory: the control,
the severity, the subject, the place, the description, the evidence, the fix and the references. The
scan view and every report print the finding ids. A unique prefix of an id works.

The table shows each value in full. It wraps a long value in a narrow terminal.

`--scan` names another scan, by an id prefix, by `last` or by a report file. `-o json` prints the
whole finding, so an agent can explain it with no guess.

## Examples

```text
vet report finding show f-7c2a
vet report finding show f-7c2a -o json
vet report finding show f-7c2a --scan vet.json
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | vet showed the finding. |
| 2 | No finding or no scan matches. |
| 3 | vet could not read the saved scan. |
