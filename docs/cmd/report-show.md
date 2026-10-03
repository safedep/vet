# vet report show

Render a saved report.

## Synopsis

```text
vet report show [ID|FILE] [--fail-on SEVERITY] [--policy FILE] [--report FORMAT=PATH]...
                [--all] [--state-dir DIR]
                [-o table|plain|json|jsonl|sarif|markdown|cyclonedx|gitlab|bitbucket]
```

## Description

`vet report show` renders a saved scan in any `-o` format, and writes `--report` files, with no new
scan and no call to SafeDep. The default is the last completed scan of the current directory. When
the current directory has no scan, vet looks at each parent directory in turn, as git looks for
`.git`.

The argument names another report:

| Argument | Report |
| --- | --- |
| `last` | The last completed scan of the current directory. This is the default. |
| A scan id, or a unique prefix of it | That scan. `vet report list --all` lists the ids. |
| A file | A report that `vet scan -o json` or `-o jsonl` wrote, or a scan file (`.db`). |

`--fail-on` and `--policy` apply a new gate to the saved report. This tests a policy against a scan
before you use it in CI. The `policy.fail_on` and `policy.file` config keys apply too, as in
`vet scan`. The saved scan does not change. The exit code follows the gate of the rendered report.

The table shows the ten most severe rows. A row holds one finding, or the vulnerabilities of one
package. `--all` shows each finding on its own row, with no row limit. The ID column holds a short id
that `vet report finding show` accepts.

## Examples

```text
vet report show
vet report show last -o json
vet report show 3f2a --report sarif=vet.sarif
vet report show --policy vet-policy.yml
vet report show vet.json -o markdown
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | vet rendered the report, and its gate passed or no gate is set. |
| 1 | The gate of the rendered report failed. |
| 2 | No scan matches the argument, or a flag or the policy is not valid. |
| 3 | vet could not read the saved scan or write a report file. |
