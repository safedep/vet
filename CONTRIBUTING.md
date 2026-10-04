# Contributing Guide

You can contribute to `vet` and help make it better. Apart from bug fixes,
features, we particularly value contributions in the form of:

- Documentation improvements
- Bug reports
- Using `vet` in your projects and providing feedback

## How to contribute

1. Fork the repository
2. Add your changes
3. Submit a pull request

## How to report a bug

Create a new issue and add the label "bug".

## How to suggest a new feature

Create a new issue and add the label "enhancement".

## Development workflow

When contributing changes to repository, follow these steps:

1. Make sure that the tests pass.
2. Write tests for new code. A new user-facing guarantee also needs an acceptance script and a
   catalog row. See [test/acceptance/README.md](test/acceptance/README.md).
3. Read [docs/DEVGUIDE.md](docs/DEVGUIDE.md) before you add or change a command or a flag.
4. Add a `Signed-off-by` line to each commit message (use the `-s` flag when you commit).

## Developer Setup

### Requirements

- Go, at the version in `go.mod`
- Node.js 24 with Corepack (for the nx/npm distribution pipeline only)

### Install Dependencies

- Install [mise](https://mise.jdx.dev/)
- Install the development tools. mise reads their versions from `.tool-versions`.

```bash
mise install
```

- Install git hooks (using Go toolchain)

```bash
go tool github.com/evilmartians/lefthook install
```

Install `golangci-lint`

```shell
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0
```

### Build

```bash
make
```

The release builds use CGO. The `codeusage` enricher parses source files with tree-sitter, and
tree-sitter needs CGO. `CGO_ENABLED=0 go build ./cmd/vet` also works. That build records a
diagnostic and scans with no code usage.

### Format Code

```bash
golangci-lint fmt
```

### Run Tests

```bash
make test                 # unit tests, the conventions tests and the catalog check
make lint-conventions     # the command and documentation conventions only
golangci-lint run ./...   # lint
go test -tags acceptance -count=1 ./test/acceptance/ -run TestAcceptance   # the hermetic acceptance suite
```

The acceptance suite builds `vet` and runs it against a local stub server. It calls no network.
`ACCEPTANCE_LIVE=1` also runs the `live` scripts against production.

## npm Distribution (nx)

The Go build and tests use `make` (above). The npm distribution pipeline is
orchestrated by nx. `vet` ships on npm as a thin wrapper (`packages/vet`) whose
`optionalDependencies` are per-platform binary packages
(`@safedep/vet-<platform>-<arch>`). There is no postinstall binary download.

The sync tool is a separate Go module under `scripts/`, wired into the build via
`go.work` (matching pmg/safedep-cli).

```bash
pnpm install                              # install nx + workspace packages
pnpm nx run vet:build-snapshot            # goreleaser snapshot (all platforms)
pnpm nx run vet:verify                    # full chain incl. smoke (vet version)
pnpm nx run vet:release-preflight         # verify + pnpm publish --dry-run
pnpm nx run vet:publish-npm               # release build + publish all packages
```

`vet:verify` runs the wrapper typecheck, the nested sync-tool tests, and the
end-to-end smoke chain (`build-snapshot -> sync-binaries:run ->
@safedep/vet:build -> smoke:verify`). `vet:release-preflight` depends on that
verification before the dry-run publish. The release path is self-contained:
`vet:publish-npm` depends on `@safedep/vet:build-release`, which depends on
`sync-binaries:run-release`, which in turn depends on `vet:build-release`.
