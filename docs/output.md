# Output and saved scans

The terminal view goes to stderr. Report data goes to stdout with `-o`, and to files with
`--report FORMAT=PATH`. One scan writes many formats. A format that publishes the report itself,
such as a pull request comment, also takes `--report FORMAT` with no path. A failure to publish is a
warning, and the gate alone sets the exit code.

```bash
vet scan -o json > vet.json
vet scan --report sarif=vet.sarif --report markdown=vet.md
```

| Format | Use |
| --- | --- |
| `table`, `plain` | People, and `grep` |
| `json`, `jsonl` | Programs. `vet report schema get` prints the JSON Schema |
| `sarif` | GitHub code scanning and other SARIF tools |
| `markdown` | A job summary, or a comment that you post with your own tools. It has one row and one card for each cause: the findings of one control, gate rule, fix and file to edit |
| `pr-comment` | One pull request comment that vet edits on each run, with the progress since the last run. `--report pr-comment` posts it in CI. `--report pr-comment=FILE` writes the body |
| `cyclonedx` | An SBOM with the findings as vulnerabilities, and the AI and crypto inventory (CycloneDX 1.7) |
| `gitlab` | A GitLab dependency scanning report, for `artifacts:reports:dependency_scanning` |
| `bitbucket` | A Bitbucket Code Insights report and its annotations |

Every format lists the findings in one order. The findings of the attack controls come first, then
the most severe. A long list of critical vulnerabilities does not push an attack out of the table.
A finding of an attack control has an `attack` field in JSON, with its technique and its MITRE
ATT&CK ids. SARIF tags it `attack` and `external/mitre-attack/<id>`.

A vulnerability finding of a scan that computed reach shows it in every format: a REACH column in
the table, the last column of `plain`, a Reach column in `markdown`, the `reach` property in SARIF
and the `reach` object in JSON. The value names its evidence, as `called · 3 hops`, `not called`,
`imported · no symbol data` or `unknown · budget`. The table shows the riskiest reach of a row, so a
called vulnerability never hides behind one that is not called. A target with no source code has no
REACH column, and the scan view says `Reach: not computed, the target has no source code`. The scan
view also names the symbol bundle and counts each reach and each cause. The call graph search
covers the whole target. In a target with two `go.mod` files that require one module, a call from
one project makes the finding of the module `called` in both.

For a Go module, the dependency graph comes from the code. vet reads the import blocks of the Go
files of the project and of each module of the build list. It finds a module in `vendor`, in the
directory of a local `replace` inside the target, or in the module cache. It runs no build and
downloads nothing, so run `go mod download` before a scan. A module with no source on the disk is
open: vet does not know what it imports. A package that only an open module can reach is `unknown ·
no dependency source`, and the scan warns with `module_graph`. A path in the graph starts at a
module that the code of that `go.mod` imports. A path from a module that only the test files of that
`go.mod` import, and that no other import reaches, is from tests only. A `tool` directive of
`go.mod` counts as an import, because `go tool` builds and runs the code of the tool. Each Go
program links the standard library, so its findings are `imported`. The `vendor/modules.txt` of a
module gets the graph of its `go.mod`. A module of `vendor/modules.txt` that is not in the build
list gives no graph and a `module_graph` warning. Run `go mod vendor` to refresh the list. cache.db keeps the imports of each module version of the
module cache, so a later scan, or another `go.mod` of the same scan, does not read them again.

For a module of a `go.work` workspace, vet uses the build list of the workspace, as the go command
does. Another module of the workspace is local code: an import of it passes on the imports of its
code. vet finds the `go.work` as the go command does, from the `GOWORK` environment variable or the
parents of the module directory. It does not read a `GOWORK` that `go env -w` sets. Run
`go mod download` in the workspace: vet builds no graph when the build list needs a `go.mod` that is
not on the disk. A finding gives the version that its `go.mod` requires, and the workspace can
build a higher version. The reach then describes the code of the version that the workspace builds.

vet builds no graph for a `go.mod` with a `go` directive below 1.17, for a workspace module outside
the target, or for a workspace with an `exclude` directive. The findings of a `go.mod` with no graph
keep `unknown · no graph`.

For a Python manifest, as `requirements.txt`, `pyproject.toml` or a lockfile, the dependency graph
also comes from the code, when the target has a virtual environment. vet reads the import statements
of the Python files of the target and of each distribution in the site-packages directory of the
environment: the one that `VIRTUAL_ENV` names, or `.venv`, `venv` or `env` under the target with a
`pyvenv.cfg`, or a `__pypackages__` directory. It runs no Python and downloads nothing, so install
the project before a scan, as `pip install -r requirements.txt` or `uv sync`. A distribution whose
imports vet cannot read is open: one with an extension module, one that imports a computed name, or
one that imports a module that no distribution holds outside a `try` statement that catches
`ImportError`. A package that only an open distribution can reach is `unknown · no dependency
source`, and the scan warns with `module_graph`. A distribution that the manifest does not list, as a
dependency of a dependency that `requirements.txt` leaves out, passes its imports on. A package of
the manifest that is not installed is open. vet builds no graph when the target has no virtual
environment, when the environment holds another version of a package that the code reaches, or when
the code of the target imports a module that no distribution holds. The findings then keep
`unknown · no graph`, and the scan says why.

At the function level, the code of a Python dependency is the distribution of its name at its
version in the site-packages directory. The standard library of the interpreter of the environment,
which the `home` line of `pyvenv.cfg` names, joins the search, so a call of the library on the code
of the target, as `Thread.start` on `run`, is a call in the graph. The call graph trusts the type
hints of the code as it trusts TypeScript types. An editable install is the project itself, so it is
no dependency code. vet never says `not called` for a Python package yet: the reach corpus in
`test/reach` still has a call that the search misses.

Each package in a report has a `purl`. It follows the purl-spec type definition of its ecosystem,
and it keeps the version as the manifest writes it. `name` and `version` hold the canonical form
that vet compares.

## Debug log

`--debug` writes the debug log of vet and of its libraries on stderr, with the rich view off.
`--log FILE` appends the same log to a file as JSON lines, for a support case. Stdout keeps the
report in both cases, so `vet scan --debug -o json | jq` still works. `-v` shows more of the view
and no log line. `--debug` and `-q` cannot be used together.

## Saved scans

vet saves each scan in its state directory. These commands read the saved scans, with no new scan:

| Command | Does |
| --- | --- |
| `vet report show` | Renders the last scan, or writes it in another format |
| `vet report show last --policy FILE` | Applies a new gate to the last scan |
| `vet report list` | Lists the scans of the current directory |
| `vet report diff` | Compares the findings of two scans |
| `vet report finding show ID` | Shows one finding with its evidence |
| `vet report capability list` | Lists the AI and crypto capabilities |
| `vet report root list` | Lists the entry points of the call graph search |

A scan that stops, for example with Ctrl-C or a lost connection, continues on the next run.
`vet state show` prints the state directory and the retention rules. `vet state delete` deletes
scans or the enrichment cache.

## Configuration

vet reads `config.yml` from the user config directory, then the `VET_*` variables, then the flags.
`vet config show` prints the path and each value with its source. A config file inside the scanned
target changes nothing. `vet config schema get` prints the JSON Schema of the file.
