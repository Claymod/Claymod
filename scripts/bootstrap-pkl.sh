#!/usr/bin/env sh
# bootstrap-pkl.sh — install the pkl CLI for the claymod control server.
#
# The PKL evaluation happens ONLY on the control server: playbooks compile
# server-side to primitive ops, so agents never need the pkl binary.
# This script fetches the official native binary from apple/pkl releases.
#
# Default install location: the user's own bin directory (~/.local/bin —
# same convention on Linux and macOS), so no sudo is needed. When run as
# root (the server setup flow), the default is /usr/local/bin instead;
# PREFIX overrides either way.
#
# Usage:
#   scripts/bootstrap-pkl.sh                   # latest release, user-local
#   sudo scripts/bootstrap-pkl.sh              # root: /usr/local/bin
#   PKL_VERSION=0.32.2 scripts/bootstrap-pkl.sh # pin a release
#   PKL_SHA256=<digest> scripts/bootstrap-pkl.sh # out-of-band trust anchor
#   PREFIX="$HOME/.local" scripts/bootstrap-pkl.sh # explicit location
#
# Already have pkl? This exits 0 immediately.
set -eu

if [ "$(id -u)" = "0" ]; then
  PREFIX="${PREFIX:-/usr/local}"
else
  PREFIX="${PREFIX:-$HOME/.local}"
fi
DEST="$PREFIX/bin"
CACHE="${TMPDIR:-/tmp}/pkl-bootstrap"

if command -v pkl >/dev/null 2>&1; then
  echo "pkl already installed: $(command -v pkl) ($(pkl --version 2>/dev/null || true))"
  exit 0
fi

# --- resolve platform -------------------------------------------------------
os="$(uname -s)"
arch="$(uname -m)"
case "$os" in
  Linux)  os_name="linux" ;;
  Darwin) os_name="macos" ;;
  *)
    echo "error: unsupported OS '$os'. Install pkl manually from https://pkl-lang.org" >&2
    exit 1
    ;;
esac
case "$arch" in
  x86_64|amd64)  arch_name="amd64" ;;
  arm64|aarch64) arch_name="aarch64" ;;
  *)
    echo "error: unsupported architecture '$arch'. Install pkl manually from https://pkl-lang.org" >&2
    exit 1
    ;;
esac
asset="pkl-${os_name}-${arch_name}"

# --- resolve version --------------------------------------------------------
if [ -n "${PKL_VERSION:-}" ]; then
  version="$PKL_VERSION"
else
  echo "resolving latest pkl release..."
  # Resolve via the releases/latest REDIRECT, not the GitHub API: the API
  # rate-limits unauthenticated requests (60/h per IP) and shared CI
  # runners hit 403 there constantly. The redirect endpoint is not
  # API-rate-limited. The API stays as a fallback.
  version="$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
    https://github.com/apple/pkl/releases/latest 2>/dev/null | sed -n 's|.*/tag/||p' || true)"
  if [ -z "$version" ]; then
    echo "(redirect resolution failed, falling back to the GitHub API...)"
    version="$(curl -fsSL https://api.github.com/repos/apple/pkl/releases/latest 2>/dev/null \
      | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1 || true)"
  fi
  if [ -z "$version" ]; then
    echo "error: could not resolve latest pkl version (set PKL_VERSION=x.y.z)" >&2
    exit 1
  fi
fi

# --- helpers ------------------------------------------------------------
# digest_of prints the lowercase sha-256 of file $1 (sha256sum on Linux,
# shasum -a 256 on macOS).
digest_of() {
  (sha256sum "$1" 2>/dev/null || shasum -a 256 "$1") | cut -d' ' -f1
}

# verify_digest fails when the digest of file $1 differs from $2
# (case-insensitive, whitespace-tolerant; fails on an empty expected).
verify_digest() {
  want="$(echo "$2" | tr 'A-Z' 'a-z' | tr -d '[:space:]')"
  [ -n "$want" ] || return 1
  [ "$(digest_of "$1")" = "$want" ]
}

# --- download and verify ----------------------------------------------------
url="https://github.com/apple/pkl/releases/download/${version}/${asset}"
mkdir -p "$CACHE"
work="$CACHE/$asset-$version"
sidecar="$work.sha256"
if [ ! -f "$work" ]; then
  echo "downloading $url ..."
  curl -fsSL -o "$work.tmp" "$url"
  mv "$work.tmp" "$work"
  # apple/pkl publishes no SHA256SUMS asset: the sidecar records the
  # digest at download time, giving cache hits a transfer-integrity
  # check (re-verified on every run below).
  digest_of "$work" > "$sidecar"
fi

# NEVER trust the predictable cache path: verify before installing, on
# every run. For authenticity set PKL_SHA256 to a digest from a trusted
# source (out-of-band anchor) — any mismatch aborts and removes the file.
if ! verify_digest "$work" "$(cat "$sidecar" 2>/dev/null)"; then
  rm -f "$work" "$sidecar"
  echo "error: pkl binary in the cache failed verification — removed, re-run to download again" >&2
  exit 1
fi
if [ -n "${PKL_SHA256:-}" ]; then
  if ! verify_digest "$work" "$PKL_SHA256"; then
    rm -f "$work" "$sidecar"
    echo "error: PKL_SHA256 mismatch — do not use this binary" >&2
    exit 1
  fi
fi

echo "pkl $version ($asset) -> $DEST/pkl"
mkdir -p "$DEST"
chmod 0755 "$work"
if [ -w "$DEST" ]; then
  cp "$work" "$DEST/pkl"
else
  echo "(write access to $DEST required, retrying with sudo)"
  sudo cp "$work" "$DEST/pkl"
fi
case ":$PATH:" in
  *":$DEST:"*) ;;
  *)
    rc="$HOME/.profile"
    case "${SHELL:-}" in *zsh*) rc="$HOME/.zshrc" ;; esac
    echo "note: $DEST is not on your PATH — add it, e.g.:"
    echo "  echo 'export PATH=\"$DEST:\$PATH\"' >> $rc && source $rc"
    ;;
esac

echo "installed: $("$DEST/pkl" --version)"
echo "done. claymod's control server will find pkl on PATH."
