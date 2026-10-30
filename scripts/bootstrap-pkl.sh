#!/usr/bin/env sh
# bootstrap-pkl.sh — install the pkl CLI for the claymod control server.
#
# The PKL evaluation happens ONLY on the control server: playbooks compile
# server-side to primitive ops, so agents never need the pkl binary.
# This script fetches the official native binary from apple/pkl releases
# and installs it to /usr/local/bin (or $PREFIX/bin).
#
# Usage:
#   sudo scripts/bootstrap-pkl.sh              # installs latest release
#   PKL_VERSION=0.32.2 scripts/bootstrap-pkl.sh # pin a release
#   PREFIX="$HOME/.local" scripts/bootstrap-pkl.sh # user-local install
#
# Already have pkl? This exits 0 immediately.
set -eu

PREFIX="${PREFIX:-/usr/local}"
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

# --- download and verify ----------------------------------------------------
url="https://github.com/apple/pkl/releases/download/${version}/${asset}"
mkdir -p "$CACHE"
work="$CACHE/$asset-$version"
if [ ! -f "$work" ]; then
  echo "downloading $url ..."
  curl -fsSL -o "$work.tmp" "$url"
  mv "$work.tmp" "$work"
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

echo "installed: $("$DEST/pkl" --version)"
echo "done. claymod's control server will find pkl on PATH."
