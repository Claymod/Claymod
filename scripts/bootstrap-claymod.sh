#!/usr/bin/env sh
# bootstrap-claymod.sh — install the claymod CLI for a DEV environment.
#
# Audience: DevOps/SREs who want claymod on their workstation to author
# and lint playbooks (`playbook init|validate|plan`) without standing up
# a control server. This installs the CLI binary only — it does NOT
# create a data dir, CA, keys or WireGuard anything, and it never starts
# `claymod serve`. When you later need a control server, that is a
# separate, deliberate step (see docs/homelab.md).
#
# Usage:
#   scripts/bootstrap-claymod.sh                  # latest release
#   CLAYMOD_VERSION=v1.2.3 scripts/bootstrap-claymod.sh   # pin a release
#   PREFIX="$HOME/.local" scripts/bootstrap-claymod.sh    # user-local
#   SKIP_PKL=1 scripts/bootstrap-claymod.sh       # CLI only, no pkl
#   FORCE=1 scripts/bootstrap-claymod.sh          # reinstall/upgrade
#
# Air-gapped / mirrored: set CLAYMOD_RELEASES_BASE to a mirror of
# https://github.com/<repo>/releases/download (plus CLAYMOD_VERSION —
# a mirror has no latest-release redirect). SHA256SUMS travels the same
# channel as the binary, so for a mirror also set CLAYMOD_SHA256 to the
# digest from a trusted source (out-of-band anchor).
#
# Already installed? Exits 0 unless FORCE=1.
set -eu

REPO="${CLAYMOD_REPO:-Claymod/Claymod}"
PREFIX="${PREFIX:-/usr/local}"
DEST="$PREFIX/bin"
CACHE="${TMPDIR:-/tmp}/claymod-bootstrap"

if [ -z "${FORCE:-}" ] && command -v claymod >/dev/null 2>&1; then
  echo "claymod already installed: $(command -v claymod) ($(claymod version 2>/dev/null || true))"
  echo "(set FORCE=1 to reinstall or upgrade)"
  exit 0
fi

# --- resolve platform (uname names, matching the release assets) ------
os="$(uname -s)"
case "$os" in
  Linux)  os_name="linux" ;;
  Darwin) os_name="darwin" ;;
  *)
    echo "error: unsupported OS '$os'. Grab a build from https://github.com/${REPO}/releases" >&2
    exit 1
    ;;
esac
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64)  arch_name="amd64" ;;
  arm64|aarch64) arch_name="aarch64" ;;
  *)
    echo "error: unsupported architecture '$arch'" >&2
    exit 1
    ;;
esac
asset="claymod-${os_name}-${arch_name}"

# --- resolve version ---------------------------------------------------
if [ -n "${CLAYMOD_VERSION:-}" ]; then
  version="$CLAYMOD_VERSION"
else
  echo "resolving latest claymod release..."
  # Resolve via the releases/latest REDIRECT, not the GitHub API: the
  # API rate-limits unauthenticated requests and shared office/CI IPs
  # hit 403 there. The redirect endpoint does not.
  version="$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
    "https://github.com/${REPO}/releases/latest" 2>/dev/null | sed -n 's|.*/tag/||p' || true)"
  if [ -z "$version" ]; then
    echo "error: could not resolve latest release (set CLAYMOD_VERSION=vX.Y.Z)" >&2
    exit 1
  fi
fi

# --- download and verify -----------------------------------------------
base="${CLAYMOD_RELEASES_BASE:-https://github.com/${REPO}/releases/download}/${version}"
dir="$CACHE/$version"
mkdir -p "$dir"
work="$dir/$asset"

if [ ! -f "$work" ]; then
  echo "downloading $base/$asset ..."
  # Download under the real asset name: `sha256sum -c` matches the file
  # name recorded in SHA256SUMS.
  curl -fsSL -o "$work" "$base/$asset"
  curl -fsSL -o "$dir/SHA256SUMS" "$base/SHA256SUMS"
  line="$(grep "  $asset\$" "$dir/SHA256SUMS" || true)"
  if [ -z "$line" ]; then
    rm -f "$work"
    echo "error: $asset is not listed in SHA256SUMS (asset naming changed?)" >&2
    exit 1
  fi
  if ! printf '%s\n' "$line" | (cd "$dir" && { sha256sum -c - >/dev/null 2>&1 || shasum -a 256 -c - >/dev/null 2>&1; }); then
    rm -f "$work"
    echo "error: checksum verification FAILED for $asset (do not use this binary)" >&2
    exit 1
  fi
  # SHA256SUMS travels the same channel as the binary: it proves
  # transfer integrity, not authenticity. For an out-of-band anchor
  # (mirrors, air-gapped), set CLAYMOD_SHA256 to the digest from a
  # trusted source — the install aborts on any mismatch.
  if [ -n "${CLAYMOD_SHA256:-}" ]; then
    got="$((sha256sum "$work" 2>/dev/null || shasum -a 256 "$work") | cut -d' ' -f1)"
    if [ "$got" != "$(echo "$CLAYMOD_SHA256" | tr 'A-Z' 'a-z')" ]; then
      rm -f "$work"
      echo "error: CLAYMOD_SHA256 mismatch (got ${got:-none}) — do not use this binary" >&2
      exit 1
    fi
  fi
fi

# --- install ------------------------------------------------------------
echo "claymod $version ($asset) -> $DEST/claymod"
mkdir -p "$DEST"
chmod 0755 "$work"
if [ -w "$DEST" ]; then
  cp "$work" "$DEST/claymod"
else
  echo "(write access to $DEST required, retrying with sudo)"
  sudo cp "$work" "$DEST/claymod"
fi

# --- pkl (playbook validate/plan = the linting this setup is for) ------
if [ "${SKIP_PKL:-}" = "1" ]; then
  echo "SKIP_PKL=1: pkl not installed (claymod playbook validate/plan need it)"
elif command -v pkl >/dev/null 2>&1; then
  echo "pkl already installed: $(command -v pkl)"
elif [ -f "$(dirname "$0")/bootstrap-pkl.sh" ]; then
  "$(dirname "$0")/bootstrap-pkl.sh"
else
  echo "note: pkl is not installed and bootstrap-pkl.sh was not found next to this script." >&2
  echo "      install pkl (scripts/bootstrap-pkl.sh) — playbook validate/plan need it." >&2
fi

echo "installed: $("$DEST/claymod" version)"
cat <<EOF

dev environment ready — CLI only, no control server was set up.

  authoring and linting playbooks:
    claymod playbook init my-playbook
    claymod playbook validate my-playbook/playbook.pkl
    claymod playbook plan    my-playbook/playbook.pkl

  a control server (claymod serve, CA, WireGuard) is a separate,
  deliberate step — see docs/homelab.md when you need it.

EOF
