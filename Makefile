all: clean setup vet

oapi-codegen-install:
	go install github.com/deepmap/oapi-codegen/cmd/oapi-codegen@v1.10.1

oapi-codegen:
	oapi-codegen -package insightapi -generate types ./api/insights-v1.yml > ./gen/insightapi/insights.types.go
	oapi-codegen -package insightapi -generate client ./api/insights-v1.yml > ./gen/insightapi/insights.client.go

setup:
	mkdir -p out gen/insightapi

vet: oapi-codegen
	go build

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
