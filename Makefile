SHELL := /bin/bash
GITCOMMIT := $(shell git rev-parse HEAD)
VERSION := "$(shell git describe --tags --abbrev=0)-$(shell git rev-parse --short HEAD)"

all: clean setup vet

oapi-codegen-install:
	go install github.com/deepmap/oapi-codegen/cmd/oapi-codegen@v1.10.1

oapi-codegen:
	oapi-codegen -package insightapi -generate types ./api/insights-v1.yml > ./gen/insightapi/insights.types.go
	oapi-codegen -package insightapi -generate client ./api/insights-v1.yml > ./gen/insightapi/insights.client.go
	oapi-codegen -package controlplane -generate types ./api/cp-v1-trials.yml > ./gen/controlplane/trials.types.go
	oapi-codegen -package controlplane -generate client ./api/cp-v1-trials.yml > ./gen/controlplane/trials.client.go

setup:
	mkdir -p out gen/insightapi gen/controlplane

GO_CFLAGS=-X main.commit=$(GITCOMMIT) -X main.version=$(VERSION)
GO_LDFLAGS=-ldflags "-w $(GO_CFLAGS)"

vet: oapi-codegen
	go build ${GO_LDFLAGS}

.PHONY: test
test:
	go test ./...

.PHONY: clean
clean:
	-rm -rf out
	-rm -rf gen

gosec:
	-docker run --rm -it -w /app/ -v `pwd`:/app/ securego/gosec \
	-exclude-dir=/app/gen -exclude-dir=/app/spec \
	/app/...
