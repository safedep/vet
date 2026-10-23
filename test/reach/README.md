# Reach corpus

The reach corpus measures the call graph search of the `codeusage` enricher. Each case is a small
synthetic project with the code of its dependencies, as `vendor` holds it. `TestReachCorpus` runs
the search on each case and checks each answer against the truth of the case. It writes the
result to [coverage.md](coverage.md). The test needs a build with CGO.

```bash
go test ./test/reach/ -count=1                  # check the cases and the table
UPDATE_GOLDEN=1 go test ./test/reach/ -count=1  # rewrite coverage.md
```

## The release bar

- A found path is a call. The precision of found must be 100%.
- No path is no call. A target that the code calls must never come back with no path. A miss
  of this kind is a false negative.
- An unproved answer, as an unresolved call, is always safe. The engine keeps the finding
  `imported` with a cause.
- A path with a call that the graph only guesses, as a call by name or a `cha` call through an
  interface, is a weak path. The engine keeps such a finding `imported · weak path`, so a weak path
  is no claim. A scan of 10 real Go projects showed that such paths are often false.

vet says `not-called` only for the ecosystems in `notCalledEcosystems` in
`internal/engine/reach.go`. A false negative in such an ecosystem fails the test. A false
negative in another ecosystem must have a `miss` line, and it keeps `not-called` off for that
ecosystem until the search finds the call. Turn an ecosystem on only when its corpus has no
false negative.

[field.md](field.md) records a run on real projects, with the comparison with govulncheck.

## Case format

A case is a `txtar` file under `cases/go/` or `cases/rust/`. The comment section holds:

| Line | Meaning |
| --- | --- |
| `# <summary>` | One line that says what the case does. The table shows it. |
| `lang: go` | The language, `go` or `rust`. |
| `unit: <key> <dir>` | The unit key and the directory of the code of one dependency, as `go:example.com/dep@v1.2.0 vendor/example.com/dep`. |
| `called: <name>` | A vulnerable function that an entry point calls, as the symbol data names it. |
| `not-called: <name>` | A function that no entry point calls. |
| `entrypoint: <path:function>` | Optional. An entry point that the user names. |
| `miss: <reason>` | Optional. The search does not give the truth for the case yet, and this is why. Name the issue that fixes it. |

## Rules for a case

- Write synthetic code. Do not copy a real dependency.
- Keep each file name inside the case folder. The test rejects `../` and absolute paths.
- Give a Go case `vendor/modules.txt` with the module and the version of the unit, as `go mod
  vendor` writes it. A scan reads a vendor tree only with that list. The corpus passes the units
  to the search itself.
- Add a `not-called` target next to each `called` target where you can. It keeps the search from
  growing into false paths.
