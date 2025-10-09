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

- Go 1.24.3+

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

### Generate Docs

If you modify the CLI tree, i.e add, update or remove any CLI commands or descriptions.
You have to regenerate the manual in the [docs/manual directory](./docs/manual) with `markdown` format.

```bash
./vet doc generate --markdown ./docs/manual
```

Or simply run:

```bash
make docgen
```

**Important**: Generated files must be committed to the repository. CI will fail if generated code is out of sync.

### Run Tests

```bash
make test
```
