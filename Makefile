SHELL := /bin/bash
GITCOMMIT := $(shell git rev-parse HEAD)
VERSION := "$(shell git describe --tags --abbrev=0)-$(shell git rev-parse --short HEAD)"

all: quick-vet

.PHONY: ent
ent:
	go generate ./ent

.PHONY: filterv2-gen
filterv2-gen:
	go generate ./pkg/analyzer/filterv2/...

generate: ent filterv2-gen

docgen: quick-vet
	./vet doc generate --markdown ./docs/manual

protoc-install:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest

dev-setup: protoc-install

protoc-codegen:
	protoc -I ./api \
		--go_out=./gen/filterinput \
		--go_opt=paths=source_relative \
		./api/filter_input_spec.proto
	protoc -I ./api \
		--go_out=./gen/filtersuite \
		--go_opt=paths=source_relative \
		./api/filter_suite_spec.proto
	protoc -I ./api \
		--go_out=./gen/exceptionsapi \
		--go_opt=paths=source_relative \
		./api/exceptions_spec.proto
	protoc -I ./api \
		--go_out=./gen/models \
		--go_opt=paths=source_relative \
		./api/models.proto
	protoc -I ./api \
		--go_out=./gen/models \
		--go_opt=paths=source_relative \
		./api/insights_models.proto
	protoc -I ./api \
		--go_out=./gen/jsonreport \
		--go_opt=paths=source_relative \
		./api/json_report_spec.proto
	protoc -I ./api \
		--go_out=./gen/violations \
		--go_opt=paths=source_relative \
		./api/violations.proto
	protoc -I ./api \
		--go_out=./gen/checks \
		--go_opt=paths=source_relative \
		./api/checks.proto

setup:
	mkdir -p out \
		gen/insightapi \
		gen/cpv1trials \
		gen/cpv1 \
		gen/syncv1 \
		gen/filterinput \
		gen/filtersuite \
		gen/exceptionsapi \
		gen/models \
		gen/jsonreport \
		gen/violations \
		gen/checks

GO_CFLAGS=-X main.commit=$(GITCOMMIT) -X main.version=$(VERSION)
GO_LDFLAGS=-ldflags "-w $(GO_CFLAGS)"

quick-vet:
	go build ${GO_LDFLAGS}

vet: oapi-codegen protoc-codegen
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
