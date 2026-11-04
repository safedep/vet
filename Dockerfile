FROM --platform=$BUILDPLATFORM golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS build

WORKDIR /build

# Install cross-compilation tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc-aarch64-linux-gnu \
    libc6-dev-arm64-cross \
    && rm -rf /var/lib/apt/lists/*

COPY go.mod go.sum ./

RUN go mod download

COPY . .

ARG TARGETPLATFORM
# make sets VERSION from a git tag, so the build passes it on the command line.
ARG VERSION
ENV CGO_ENABLED=1

# Set up cross-compilation environment based on target platform
RUN case "${TARGETPLATFORM}" in \
    "linux/amd64") \
    CC=gcc CXX=g++ GOOS=linux GOARCH=amd64 make quick-vet ${VERSION:+VERSION=$VERSION} ;; \
    "linux/arm64") \
    CC=aarch64-linux-gnu-gcc CXX=aarch64-linux-gnu-g++ GOOS=linux GOARCH=arm64 make quick-vet ${VERSION:+VERSION=$VERSION} ;; \
    *) echo "Unsupported platform: ${TARGETPLATFORM}" && exit 1 ;; \
    esac

FROM debian:13-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

ARG TARGETPLATFORM

LABEL org.opencontainers.image.source=https://github.com/safedep/vet
LABEL org.opencontainers.image.description="Open source software supply chain security tool"
LABEL org.opencontainers.image.licenses=Apache-2.0

COPY --from=build /build/vet /usr/local/bin/vet

ENTRYPOINT ["vet"]
