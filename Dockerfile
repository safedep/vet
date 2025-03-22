FROM --platform=$BUILDPLATFORM golang:1.24-bullseye@sha256:3c669c8fed069d80d199073b806243c4bf79ad117b797b96f18177ad9c521cff AS build
# Original: golang:1.24-bullseye

WORKDIR /build

COPY go.mod go.sum ./

RUN go mod download

COPY . .

ENV CGO_ENABLED=1

RUN make quick-vet

FROM debian:11-slim@sha256:e4b93db6aad977a95aa103917f3de8a2b16ead91cf255c3ccdb300c5d20f3015
# Original: debian:11-slim

# Create nonroot user and group with specific IDs
RUN groupadd -r nonroot --gid=65532 && \
    useradd -r -g nonroot --uid=65532 nonroot

USER nonroot:nonroot

ARG TARGETPLATFORM

LABEL org.opencontainers.image.source=https://github.com/safedep/vet
LABEL org.opencontainers.image.description="Open source software supply chain security tool"
LABEL org.opencontainers.image.licenses=Apache-2.0

COPY ./samples/ /vet/samples
COPY --from=build /build/vet /usr/local/bin/vet

ENTRYPOINT ["vet"]
