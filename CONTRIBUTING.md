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

1. If you modified code that requires generation (e.g., enum registrations, ent schemas), run `make generate` and commit the generated files
2. Ensure tests are passing
3. Ensure you write test cases for new code
4. `Signed-off-by` line is required in commit message (use `-s` flag while committing)

## Developer Setup

### Requirements

- Go 1.25.6+

### Install Dependencies

- Install [ASDF](https://asdf-vm.com/)
- Install the development tools

```bash
asdf plugin add golang
asdf plugin add gitleaks
asdf install
```

- Install git hooks (using Go toolchain)

```bash
go tool github.com/evilmartians/lefthook install
```

Install `golangci-lint`

```shell
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.5.0
```

### Build

Install build tools

```bash
make dev-setup
```

Generate code from API specs and build `vet`

```bash
make
```

Quick build without regenerating code from API specs

```bash
make quick-vet
```

### Generate Code

If you modify code that requires generation (enum registrations in `pkg/analyzer/filterv2/enums.go`, ent schemas in `ent/schema/*.go`), run:

```bash
make generate
```

**Important**: Generated files must be committed to the repository. CI will fail if generated code is out of sync.

### Format Code

```bash
golangci-lint fmt
```

### Run Tests

```bash
make test
```

## npm Distribution (nx)

The Go build and tests use `make` (above). The npm distribution pipeline is
orchestrated by nx. `vet` ships on npm as a thin wrapper (`packages/vet`) whose
`optionalDependencies` are per-platform binary packages
(`@safedep/vet-<platform>-<arch>`). There is no postinstall binary download.

Because `vet` is a CGO binary, the snapshot and release builds need the full
cross-compile toolchain (osxcross, mingw, cross-gcc) wherever they run. The
sync tool is a separate Go module under `scripts/`, wired into the build via
`go.work` (matching pmg/safedep-cli). Note: `ent/generate.go` uses `go run`
(not `go run -mod=mod`) so `go generate` works in workspace mode; after an ent
version bump, run `go mod tidy` before regenerating.

```bash
pnpm install                              # install nx + workspace packages
pnpm nx run vet:build-snapshot            # goreleaser snapshot (all platforms)
pnpm nx run vet:verify                    # full chain incl. smoke (vet version)
pnpm nx run vet:release-preflight         # verify + pnpm publish --dry-run
pnpm nx run vet:publish-npm               # release build + publish all packages
```

The task graph: `build-snapshot -> sync-binaries:run -> @safedep/vet:build ->
build-dev -> smoke:verify -> verify -> release-preflight`. The release path uses
the `*-release` variants (`build-release -> sync-binaries:run-release`).
