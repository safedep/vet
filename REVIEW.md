# Review instructions

These instructions apply to the managed Claude Code Review of a pull request. `AGENTS.md` and
`docs/glossary.md` give the project context. This file says what to report and how severe it is.

## What Important means here

Report a finding as Important when the change can do one of these:

- Give a wrong scan result: a missed finding, a false attack finding, a wrong gate result or a wrong
  exit code.
- Print untrusted text to a terminal with no escape, or show a token or a credential.
- Break the report contract: a report field, the JSON Schema in `schema/`, a SARIF or CycloneDX field,
  or a command or flag that users or CI scripts call.
- Publish a v2 build to a release channel of v1.
- Break an import rule that `internal/archtest` or `.golangci.yml` enforces, or relax that rule.

A finding about style, names, comments or a refactor is a Nit at most.

## Cap the nits

Report at most five Nits in one review. Do not report a Nit on a line that the pull request did not
change.

## Do not report

CI and `make check` already enforce these. Do not report them:

- Lint and format findings: golangci-lint, gci, gofumpt, go vet. `make check` lints the changed lines.
- Compile errors and failed tests, including `internal/archtest`, the command conventions test in
  `internal/cmd` and the hermetic acceptance suite.
- Secrets that TruffleHog and gitleaks find, and CodeQL findings.
- Dependency versions that Dependabot and the dependency review own.
- Lockfiles (`go.sum`, `go.work.sum`, `pnpm-lock.yaml`) and the fixture trees under `testdata/`,
  `test/extraction/corpus` and `test/evasion/cases`. A fixture is often a fake attack on purpose.

## Always check

Each rule comes from `AGENTS.md` or a doc that it names. The severity follows each rule.

1. **Code in the wrong package.** A change that edits `internal/archtest` or the depguard rules of
   `.golangci.yml` to let new code pass is Important. The code must move. The rule stays.
2. **Package identity.** Code compares package versions only with `model.PackageVersion` (`Equal`,
   `Key`, `SamePackage`, `Compare`), and groups the versions of one package with `NameKey`. A
   compare or a map key on the name and version strings or on the PURL is Important.
3. **Terminal output.** Only `internal/tui` imports `dry/tui`. Untrusted text (package names, paths,
   text from a repository or a registry) goes through `internal/tui/escape` before vet prints it.
   A missing escape is Important.
4. **Bug fix test.** A bug fix needs a test that fails without the fix. A fix with no such test is
   Important.
5. **Enricher version.** An enricher that changes how it maps data bumps its `Version`, so the cache
   drops old results. A missing bump is Important.
6. **Golden files and schemas.** A change to a golden file or to `schema/` is correct only when the
   output change is the purpose of the pull request. An unexplained change is Important.
7. **Commands and flags.** A new, renamed or removed command or flag follows `docs/DEVGUIDE.md` and
   updates its page under `docs/cmd/`. A break of a rule that the conventions test does not catch is
   Important.
8. **User guarantees.** A new user-facing guarantee has an acceptance script and a row in
   `test/acceptance/catalog.yaml`. A missing script or row is Important.
9. **Detections.** A change to an attack detection adds cases to the evasion corpus and commits the
   diff of `test/evasion/coverage.md`. A new detection with a risk of false positives starts as a
   control that warns, with no `Attack: true`. A new attack control with that risk and no clean
   false-positive run is Important. See
   `CONTRIBUTING-DETECTIONS.md`.
10. **Release channels.** Code on `v2` never writes the `latest` image tag, the latest GitHub release
    or the `vet` cask. A change to `release-edge.yml`, `.goreleaser*` or `test/release` that can do
    this is Important.
11. **Product name.** User-facing text says SafeDep Threat Intel, not Malysis. The plugin and the
    config key keep the name `malysis`. A wrong name in user-facing text is a Nit.
12. **Glossary terms.** A new type, flag or report field uses the term in `docs/glossary.md`, not a
    word from its `_Avoid_` list. A second type for a concept that the glossary lists is Important.
    A wrong word in a comment is a Nit.

## Evidence

A claim about behavior needs a file:line citation in the source, not an inference from a name. If you
cannot cite the line, do not report the claim.
