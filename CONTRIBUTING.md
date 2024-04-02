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

1. Ensure tests are passing
2. Ensure you write test cases for new code
3. `Signed-off-by` line is required in commit message (use `-s` flag while committing)

## Developer Setup

### Requirements

* Go 1.22+

### Install Dependencies

* Install [ASDF](https://asdf-vm.com/)
* Install the development tools

```bash
asdf install
```

* Install `lefthook`

```bash
go install github.com/evilmartians/lefthook@latest
```

* Install git hooks

```bash
$(go env GOPATH)/bin/lefthook install
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

### Run Tests

```bash
go test -v ./...
```



