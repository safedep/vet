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

.PHONY: lint-conventions
lint-conventions:
	go test -count=1 -run 'TestConventions|TestIsAllowedVerb|TestAllowedVerbs' ./internal/cmd/

.PHONY: clean
clean:
	-rm -rf out

gosec:
	-docker run --rm -it -w /app/ -v `pwd`:/app/ securego/gosec \
	/app/...
