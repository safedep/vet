FROM --platform=$BUILDPLATFORM golang:1.24.2-bullseye@sha256:f50ff25f8331682b44c1582974eb9e620fcb08052fc6ed434f93ca24636fc4d6 AS build
# Original: golang:1.24-bullseye

WORKDIR /build

COPY go.mod go.sum ./

RUN go mod download

COPY . .

ENV CGO_ENABLED=1

RUN make quick-vet

FROM debian:11-slim@sha256:e4b93db6aad977a95aa103917f3de8a2b16ead91cf255c3ccdb300c5d20f3015
# Original: debian:11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
	ca-certificates \
	&& rm -rf /var/lib/apt/lists/*

ARG TARGETPLATFORM

LABEL org.opencontainers.image.source=https://github.com/safedep/vet
LABEL org.opencontainers.image.description="Open source software supply chain security tool"
LABEL org.opencontainers.image.licenses=Apache-2.0

COPY ./samples/ /vet/samples
COPY --from=build /build/vet /usr/local/bin/vet

ENTRYPOINT ["vet"]
