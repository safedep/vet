SHELL := /bin/bash
GITCOMMIT := $(shell git rev-parse HEAD)
VERSION := "$(shell git describe --tags --abbrev=0)-$(shell git rev-parse --short HEAD)"

all: quick-vet

.PHONY: ent
ent:
	go generate ./ent

generate: ent

GO_CFLAGS=-X github.com/safedep/vet/v2/internal/version.commit=$(GITCOMMIT) -X github.com/safedep/vet/v2/internal/version.version=$(VERSION)
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
	-exclude-dir=/app/ent \
	/app/...
