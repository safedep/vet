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

A vulnerability finding of a scan that computed reach also shows its reach and what to do about its
cause. A `called` finding shows the call path: the entry point and the rule that found it, then each
call with its line, its kind and its confidence. A `not-called` finding shows how many entry points
the search used. Each finding at the function level shows its fix sites and its symbol record, with
the coverage, the review state, the source and the license of the record.

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
