# AGENTS.md

This file gives guidance to AI coding agents that work on vet. `.claude/CLAUDE.md` imports it, so
Claude Code loads it. Git ignores a `CLAUDE.md` at the root.

## Build and test

```bash
make check     # the gate before a push: build, vet for each OS, tests, lint, hermetic acceptance
make fmt       # format with the gci and gofumpt rules of the lint
make golden    # rewrite the golden files and the report schemas, then read the diff
go test ./internal/engine/ -run TestName -count=1   # one test
```

- Run `make check` before each push. CI runs the same steps.
- `make check` lints only the lines that changed since `origin/v2`. Set `LINT_BASE` for another base.
- `make golden` sets `UPDATE_GOLDEN=1` and `UPDATE_SCHEMA=1`. Commit a golden change only when the
  output change is the purpose of the commit.
- The acceptance suite runs the real binary against an in-process stub, with no network. It needs the
  build tag: `go test -tags acceptance ./test/acceptance/ -run TestAcceptance/scan/output`.
- A bug fix needs a test that fails without the fix. Run the test against the old code before you
  commit.

## Find what exists before you write it

Read [docs/glossary.md](docs/glossary.md) before you name a thing. It names each concept of vet and
the code that owns it. Use its term and its type. Do not add a second word or a second type for a
concept that it lists. When a change adds a concept, or overrules a term, update the glossary in the
same pull request.

vet and `dry` already have most of the parts that a change needs. Search before you add a type, a
helper or a list. Each row is the one place for its concern.

| Concern | Use |
| --- | --- |
| Terminal output: messages, tables, panels, progress, prompts, banner | `internal/tui/...`, which wraps `dry/tui`. Look in `dry/tui` first for a missing part. |
| Stderr view of a scan: steps, diagnostics, gate line | `internal/view` |
| What a person sees first in a report: findings in order, diagnostics, what a change adds | `internal/overview`. The view and the sinks read it. |
| Stdout data in the `-o` format | `internal/tui/printer` |
| Untrusted text on a terminal (package names, paths from a repository) | `internal/tui/escape` |
| Log lines of libraries | `internal/logging`. They print only with `-v`. Do not write to the standard `log` package. |
| The list of built-in plugins with a config section | `internal/plugins/builtin`. Do not list plugins by hand. |
| The extractor set of a scan, declared and installed packages | `internal/plugins/extractors` (`For`), with `internal/plugins/extractors/installed` |
| Control plugins, report formats | `internal/plugins/controls`, `internal/plugins/sinks` |
| Enrichers and their cache settings | `internal/plugins/enrichers` |
| The JSON Schema of plugin options | `internal/plugins/internal/optschema` |
| Config: struct, defaults, layers, validation, lockdown | `internal/config` |
| Global flags, exit codes, usage errors | `internal/app` |
| Scan state, scan files, enrichment cache | `internal/state` |
| Wiring of one scan from the config | `internal/runner` |
| A token in a git URL | `git.Redact` in `internal/plugins/sources/git` |
| GitHub token and client | `internal/github` |
| The CI platform and the change that it builds, the adapters that write to it, and the setup files of `vet ci` | `internal/ci` |
| Package identity: compare, key, order, PURL and the wire form of a package version | `model.PackageVersion`. It wraps the `dry/api/pb` rules. |
| SPDX license expressions: parse, compare, allow and deny, the OSI and FSF sets | `internal/spdxlicense`. Do not call `go-spdx` from another package. |
| Report types and the JSON Schema of the report | `report` |
| Golden file comparison in tests | `internal/golden` |
| Sample report for sink and view tests | `plugin/plugintest` |

When two places need the same list or the same logic, move it to one package and make both read it.
If the duplicate can come back, add a test in `internal/archtest` that fails on it.

## Rules

`internal/archtest` and `.golangci.yml` enforce the import rules. A failure there means the code is in
the wrong package. Move the code. Do not change the rule to make the test pass.

- Only `internal/tui` imports `dry/tui`. `internal/tui` imports no other vet package.
- Only the enrichers and the cloud plugins import the SafeDep API contract.
- Only `model` imports the identity rules of `dry/api/pb`. Compare package versions with `Equal`,
  `Key` or `Compare`, never with the name and version strings or the PURL. The PURL is for display
  and for the wire.
- Only the API clients call `RawProto`. A remote API gets the raw name and version and applies its
  own rules.
- Only `plugin`, the extractors and the sources import Scalibr.
- The public packages `model`, `finding`, `report` and `plugin` import nothing from `internal`.
- Only `internal/plugins/builtin` and `internal/runner` import both the controls and the sinks.
- Read [docs/DEVGUIDE.md](docs/DEVGUIDE.md) before you add, rename or remove a command or a flag.
  Obey each rule that it marks **(lint)**. Use the skill `.claude/skills/vet-commands/SKILL.md`.
- A new user-facing guarantee gets an acceptance script and its row in `test/acceptance/catalog.yaml`.
  See [test/acceptance/README.md](test/acceptance/README.md).
- An enricher that changes how it maps data bumps its `Version`, so the cache drops the old results.
- Use `testify` and table-driven tests.
- `test/release` keeps a v2 build out of the release channels of v1. Users of v1 run the `latest`
  container image. Never write the `latest` image tag, the latest GitHub release or the
  `vet` cask from the v2 branch. The release workflow `release-edge.yml` runs on a push to `v2`. It
  publishes only a commit that a merged pull request brought in.

## Commits

On the `v2` branch, start the subject with the Linear issue id in square brackets, as in
`[FOU-424] Send the endpoint inventory to SafeDep Cloud`. The Linear project "vet v2: production"
holds the backlog and the status. A docs-only change adds `docs:` after the id. The body says what
was wrong and why the change fixes it.

The commits of the first implementation start with a task id of the vet v2 plan, as in `[2b.6]`.
The plan, with the decisions and the gap table, is `docs/specs/2026-10-02-vet-v2-plan.md` in
`safedep/control-tower`.

## Writing

Write in ASD-STE100, Simplified Technical English. This applies to code comments, user-facing
messages, commit messages, pull requests and docs.

- One sentence, one idea.
- Use the active voice and name the actor.
- Cut every word that does no work.
- Do not end a message with a full stop right after a value that a user copies: a path, a scan
  id, a config key, a flag or a command. Put the value earlier in the sentence, or end the message
  with the value and no full stop.
- Say SafeDep Threat Intel in user-facing text. Malysis is an internal name. The plugin and the
  config key keep the name `malysis`.
