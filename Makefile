SHELL := /bin/bash
GITCOMMIT := $(shell git rev-parse HEAD)
# Only a v2 tag names a v2 build, as v2.0.1-3-gabc1234. With no v2 tag, the
# Go build info gives the version. A v1 tag would make vet doctor ask for
# an upgrade.
VERSION := $(shell git describe --tags --match 'v2.*' 2>/dev/null)

all: quick-vet

GO_CFLAGS=-X github.com/safedep/vet/v2/internal/version.commit=$(GITCOMMIT) $(if $(VERSION),-X github.com/safedep/vet/v2/internal/version.version=$(VERSION))
GO_LDFLAGS=-ldflags "-w $(GO_CFLAGS)"

quick-vet:
	go build ${GO_LDFLAGS} -o vet ./cmd/vet

vet: quick-vet

.PHONY: test
test:
	go test ./...

GOLANGCI_LINT ?= golangci-lint
# CI lints the lines that changed since this ref.
LINT_BASE ?= origin/v2

# check is the gate to run before a push. It runs what CI runs: the build,
# go vet for each OS, the tests, the lint of the changed lines and the
# hermetic acceptance suite.
.PHONY: check
check:
	go build ./...
	go vet ./...
	GOOS=darwin go vet ./...
	GOOS=windows go vet ./...
	go test -count=1 ./...
	$(GOLANGCI_LINT) run --new-from-rev=$(LINT_BASE) ./...
	go test -tags acceptance -count=1 ./test/acceptance/ -run TestAcceptance

# fmt formats the code with the gci and gofumpt rules of the lint.
.PHONY: fmt
fmt:
	$(GOLANGCI_LINT) fmt ./...

# golden rewrites the golden files and the committed report schemas. Read
# the diff before you commit it.
.PHONY: golden
golden:
	UPDATE_GOLDEN=1 UPDATE_SCHEMA=1 go test -count=1 ./...

.PHONY: acceptance
acceptance:
	go test -tags acceptance -count=1 ./test/acceptance/ -run TestAcceptance

.PHONY: lint-conventions
lint-conventions:
	go test -count=1 -run 'TestConventions|TestIsAllowedVerb|TestAllowedVerbs' ./internal/cmd/

.PHONY: clean
clean:
	-rm -rf out

gosec:
	-docker run --rm -it -w /app/ -v `pwd`:/app/ securego/gosec \
	/app/...
