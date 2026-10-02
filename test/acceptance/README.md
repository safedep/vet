# vet acceptance suite

The suite runs the real `vet` binary through user-facing commands and checks that vet keeps its
promises. Every script is hermetic by default: it calls no network. A script under the `live`
category calls production and runs only when `ACCEPTANCE_LIVE=1` is set.

The unit tests own functions and packages. `plugintest` owns the plugin API. This suite owns the
guarantees of the real binary.

## Files

```text
test/acceptance/
  catalog.yaml          the guarantee inventory: id, category, tier, guarantee, labels
  catalog.go            the catalog schema, the loader, the feature id and the selector
  commands.go           the script commands: execexit, expandenv, replace, capture
  sandbox.go            the per-script home and the script conditions
  integrity_test.go     TestCatalogIntegrity (runs under go test ./...)
  acceptance_test.go    TestAcceptance, the real-binary harness (//go:build acceptance)
  report/               joins JUnit results with the catalog into a Markdown report
  scripts/
    <category>/<capability>/<name>.txtar
```

The parts have the `dry/acceptance` shape, so that they can move to dry later (decisions D17).

## Run

```bash
go test -tags acceptance ./test/acceptance/ -run TestAcceptance
ACCEPTANCE_CATEGORY=report go test -tags acceptance ./test/acceptance/
ACCEPTANCE_LABELS=gate,agent go test -tags acceptance ./test/acceptance/
VET_BIN=/path/to/vet go test -tags acceptance ./test/acceptance/
```

The harness builds `./cmd/vet` when `VET_BIN` is not set.

## Feature id

The feature id of a script is its path under `scripts/` without `.txtar`:

```text
scripts/errors/useful/help-line.txtar   ->   errors/useful/help-line
```

Put every script at least two levels deep. The first segment is the category.

## Add a case

1. Add a script at `scripts/<category>/.../<name>.txtar`.
2. Add a row to `catalog.yaml` with `id`, `title`, `category`, `tier` (P0, P1 or P2), `guarantee`
   and optional `labels`.

That is the whole change. `TestCatalogIntegrity` fails when a script has no catalog row. A row with
no script is a gap. The report shows it, and it does not fail the build.

## Write a script

Scripts are [`testscript`](https://pkg.go.dev/github.com/rogpeppe/go-internal/testscript) files.
`exec vet ...` runs the built binary.

The harness gives each script its own `HOME` under `$WORK/home`, with the XDG directories and the
Windows profile directories under it. No script reads the host config, state, cache or keychain.
`testscript` does not forward the host environment, so `SAFEDEP_*`, `CLAUDECODE`, `AI_AGENT` and
`CI` are unset. A script sets the mode that it tests. `testscript` never gives vet a TTY.

| Command | Use |
| --- | --- |
| `execexit <code> <cmd>...` | Assert the exact exit code. Every exit-code check uses it, never `! exec` alone. |
| `expandenv <file>...` | Put `$VAR` values from the script environment into a file. |
| `replace <file> <old> <new>` | Edit a file in place. The strings take Go escapes such as `\n`. |
| `capture <var> <regexp> [file]` | Keep a value, such as a scan id, from stdout or a file. |

| Condition | True when |
| --- | --- |
| `unix` | The OS is not Windows. Use it for file modes and signals. |
| `git` | The `git` binary is on `PATH`. |
| `docker` | The `docker` binary is on `PATH`. |
| `live` | `ACCEPTANCE_LIVE=1` is set. |

Assert coarse, stable facts: an exit code, a field, a record count.
