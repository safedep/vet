# vet report root list

List the entry points of the call graph of a saved scan.

## Synopsis

```text
vet report root list [--scan ID|FILE] [--state-dir DIR] [-o table|plain|json|jsonl]
```

## Description

`vet report root list` lists the entry points where the call graph search of the last scan of the
current directory started. Each row gives the kind, the function, the file and line, and the rule
that marks the entry point. The kinds are:

| Kind | Entry point |
| --- | --- |
| `main` | A main function. |
| `manifest` | A script or a binary that a manifest names. |
| `framework` | A handler that a framework rule marks, such as an HTTP route. |
| `test` | A test function. |
| `library-surface` | An exported function of a library, by a rule of the library. |
| `query` | A function that `--entrypoint` or `plugins.codeusage.options.entrypoints` names. |

A scan at the function level of reach searches the call graph of a Go or Rust project with a
vulnerability. A path from an entry point to a vulnerable function makes the finding `called`.
Use the list to find an entry point that vet missed, then add it with `vet scan --entrypoint
path:function`. When vet finds no entry point, the search starts from every exported function, and
the list says so, also when `--entrypoint` adds one. No finding of such a scan is `not-called`.

The scan header keeps the first 1000 entry points, and the list says how many more there are.
`--scan` names another scan, by an id prefix, by `last` or by a report file. `-o json` prints the
whole list as the header holds it.

## Flags

| Flag | Description |
| --- | --- |
| `--scan ID\|FILE` | Read this scan, by an id prefix, by `last` or by a report file. |
| `--state-dir DIR` | Directory of the scan index and the scan files. |

## Examples

```text
vet report root list
vet report root list --scan last -o json
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | vet listed the entry points. An empty list also exits 0. |
| 2 | A flag is not valid, or no scan matches. |
| 3 | vet could not read the saved scan. |
