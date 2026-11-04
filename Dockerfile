# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# claymod control server image
#
#   docker build -t claymod .
#   docker run --rm -p 8443:8443/tcp -p 51821:51821/udp --cap-add NET_ADMIN \
#     -v claymod-data:/var/lib/claymod claymod \
#     serve --config /etc/claymod/server.yaml --wg-endpoint <public-ip>:51821
#
# Contents: the `claymod` control server + full CLI, the `pkl` CLI
# (playbook evaluation is server-side only), `ip`/`wg` (the WireGuard
# interface `serve` creates), `git` (git-pinned PKL libraries), and the
# `claymod-agent` binaries the bootstrap endpoint hands out to hosts.
#
# The agent itself is NOT installed here: hosts download it from
# https://<control>:8443/agent/<os>/<arch> during enrollment.
# ---------------------------------------------------------------------------

ARG GO_VERSION=1.27
ARG PKL_VERSION=0.32.2

# --- pkl CLI ---------------------------------------------------------------
# The Linux native binary is dynamically linked against glibc and
# libstdc++, so the runtime image is Debian, not Alpine. Installed through
# the repo's own verified installer (checksum-checked download, cache
# hits included); PKL_SHA256 is an optional out-of-band authenticity anchor.
FROM debian:bookworm-slim AS pkl
ARG PKL_VERSION
ARG PKL_SHA256=
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl libstdc++6 zlib1g \
 && rm -rf /var/lib/apt/lists/*
COPY scripts/bootstrap-pkl.sh /usr/local/lib/claymod/bootstrap-pkl.sh
# A single transient GitHub failure must not sink the image build — the
# foreign-arch leg of a multi-arch build runs this under emulation, where a
# dropped connection shows up as an SSL/curl error. The installer is safe to
# re-run (it only installs after a verified download).
RUN set -eu; \
    attempt=0; \
    until PREFIX=/opt/pkl PKL_VERSION="${PKL_VERSION}" PKL_SHA256="${PKL_SHA256}" \
            sh /usr/local/lib/claymod/bootstrap-pkl.sh; do \
      attempt=$((attempt + 1)); \
      if [ "$attempt" -ge 3 ]; then \
        echo "pkl install failed after 3 attempts" >&2; \
        exit 1; \
      fi; \
      echo "pkl install failed, retrying (attempt $((attempt + 1))/3)" >&2; \
      sleep 5; \
    done

# --- binaries --------------------------------------------------------------
# Cross-compiles on the build platform (no QEMU for Go): CGO is off, the
# sqlite driver is pure Go, so both binaries are static.
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ENV CGO_ENABLED=0

# Dependencies first: the module layer survives source edits.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

# The control server + CLI (version is stamped like `make build` does).
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    mkdir -p /out/agents \
 && GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build -trimpath \
      -ldflags "-s -w -X github.com/claymod/claymod/internal/cli.version=${VERSION}" \
      -o /out/claymod ./cmd/claymod

# Agent binaries served at /agent/{os}/{arch} so hosts need only curl.
# Asset names follow uname(1) spelling (aarch64, not arm64).
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    for pair in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do \
      os="${pair%/*}"; goarch="${pair#*/}"; \
      arch="$(echo "$goarch" | sed 's/arm64/aarch64/')"; \
      GOOS="$os" GOARCH="$goarch" \
        go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
          -o "/out/agents/claymod-agent-${os}-${arch}" ./cmd/claymod-agent; \
    done \
 && ls -l /out/agents

# --- runtime ---------------------------------------------------------------
FROM debian:bookworm-slim AS runtime
ARG VERSION=dev

LABEL org.opencontainers.image.title="claymod" \
      org.opencontainers.image.description="Push-based IaC control server: PKL playbooks over a WireGuard overlay" \
      org.opencontainers.image.source="https://github.com/Claymod/Claymod" \
      org.opencontainers.image.version="${VERSION}"

# iproute2 + wireguard-tools: `serve` shells out to `ip link add … type
# wireguard`, `ip address`, `wg set` (see internal/wgmgr). git: git-pinned
# PKL libraries. curl: healthcheck and operator convenience.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl git iproute2 libstdc++6 wireguard-tools zlib1g \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/claymod /usr/local/bin/claymod
COPY --from=build /out/agents/ /var/lib/claymod/agents/
COPY --from=pkl /opt/pkl/bin/pkl /usr/local/bin/pkl
COPY docker/server.yaml /etc/claymod/server.yaml

# One writable directory holds the CA + identities, inventory DB, WireGuard
# keys/config, the served agent binaries and the schema/library caches, so a
# single volume preserves the whole control-server state.
ENV HOME=/var/lib/claymod \
    XDG_CACHE_HOME=/var/lib/claymod/.cache \
    CLAYMOD_CACHE_DIR=/var/lib/claymod/.cache/claymod
WORKDIR /var/lib/claymod
VOLUME ["/var/lib/claymod"]

# HTTPS bootstrap (agents + operators) and the WireGuard overlay.
EXPOSE 8443/tcp 51821/udp

# Startup only needs the bootstrap listener; the certificate is issued by
# the internal CA, hence -k. Override if bootstrap_listen moves.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsSk https://127.0.0.1:8443/healthz

# Runs as root on purpose: `ip link add` and wgctrl need NET_ADMIN
# (docker run --cap-add NET_ADMIN). A rootless demo run is possible with
# `--wg-backend fake --manage-interface=false`.
ENTRYPOINT ["claymod"]
CMD ["serve", "--config", "/etc/claymod/server.yaml"]
