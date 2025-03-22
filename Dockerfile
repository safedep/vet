FROM --platform=$BUILDPLATFORM golang:1.24-bullseye AS build

WORKDIR /build

COPY go.mod go.sum ./

RUN go mod download

COPY . .

ENV CGO_ENABLED=1

RUN make quick-vet

FROM debian:bullseye-slim

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
