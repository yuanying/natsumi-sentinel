# Build sentinel and authd as static binaries and ship each on a base with
# nothing else on it.
#
# One Dockerfile with a target per image: the two programs are one module,
# built by the same stage from the same sources, and keeping them here means
# a release cannot build them from different Go versions or flags.
#
#   docker build --target sentinel .   ghcr.io/yuanying/natsumi-sentinel
#   docker build --target authd .      ghcr.io/yuanying/natsumi-sentinel-authd
#
# Each image carries one executable and a set of root certificates. It has no
# shell, so the only thing that can run in the container is that program.

# The build stage runs on the builder's own platform and cross-compiles, so
# the arm64 images are built without emulation.
FROM --platform=$BUILDPLATFORM golang:1.27 AS build
WORKDIR /src

COPY go.mod go.sum ./
COPY cmd/ cmd/
COPY internal/ internal/

# CGO off makes the result static, which is what lets it run on a base image
# with no libc. The caches are mounts rather than layers so that rebuilding
# after an edit does not start from an empty module cache.
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    for app in sentinel authd; do \
      CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
      go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/$app ./cmd/$app || exit 1; \
    done

# 65532 is distroless's "nonroot". The two images share it only as a default
# that is not root: in the Pod, sentinel and authd run under UIDs of their
# own, set by the manifest, because each checks the other's UID on its
# socket (docs/adr/0001).
FROM gcr.io/distroless/static:nonroot AS authd
WORKDIR /
COPY --from=build /out/authd /authd
USER 65532:65532
ENTRYPOINT ["/authd"]

# Last, so that a build without --target gives the gate.
FROM gcr.io/distroless/static:nonroot AS sentinel
WORKDIR /
COPY --from=build /out/sentinel /sentinel
USER 65532:65532
ENTRYPOINT ["/sentinel"]
