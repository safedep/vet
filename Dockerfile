FROM --platform=$BUILDPLATFORM golang:1.26.9-bookworm@sha256:d9c68c2c51161e12fd77e4c6320687c9cd86e1af1e3ad6e6cd63ff970641453c AS build

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

FROM debian:12-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

ARG TARGETPLATFORM

LABEL org.opencontainers.image.source=https://github.com/safedep/vet
LABEL org.opencontainers.image.description="Open source software supply chain security tool"
LABEL org.opencontainers.image.licenses=Apache-2.0

COPY --from=build /build/vet /usr/local/bin/vet

ENTRYPOINT ["vet"]
