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
#   SKIP_PKL=1 scripts/bootstrap-claymod.sh       # CLI only, no pkl
#   INSTALL_PKL=1 scripts/bootstrap-claymod.sh    # install pkl without prompting
#   FORCE=1 scripts/bootstrap-claymod.sh          # reinstall/upgrade
#
# pkl: this script is self-contained (it ships alone, e.g. via curl | sh),
# so the pkl installer is embedded below — no sibling bootstrap-pkl.sh
# needed. When pkl is missing the script ASKS before installing
# (INSTALL_PKL=1 pre-answers yes; SKIP_PKL=1 skips entirely; without a
# terminal it prints a note instead of asking).
#
# Default install location: the user's own bin directory (~/.local/bin —
# same convention on Linux and macOS), so no sudo is needed. When run as
# root (a server setup flow), the default is /usr/local/bin instead;
# PREFIX overrides either way.
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
if [ "$(id -u)" = "0" ]; then
  PREFIX="${PREFIX:-/usr/local}"
else
  PREFIX="${PREFIX:-$HOME/.local}"
fi
DEST="$PREFIX/bin"
CACHE="${TMPDIR:-/tmp}/claymod-bootstrap"

if [ -z "${FORCE:-}" ] && command -v claymod >/dev/null 2>&1; then
  echo "claymod already installed: $(command -v claymod) ($(claymod version 2>/dev/null || true))"
  echo "(set FORCE=1 to reinstall or upgrade)"
  exit 0
fi

# --- helpers ------------------------------------------------------------
# path_hint prints an export line when dir is not on PATH.
path_hint() {
  case ":$PATH:" in
    *":$1:"*) return 0 ;;
  esac
  rc="$HOME/.profile"
  case "${SHELL:-}" in *zsh*) rc="$HOME/.zshrc" ;; esac
  echo "note: $1 is not on your PATH — add it, e.g.:"
  echo "  echo 'export PATH=\"$1:\$PATH\"' >> $rc && source $rc"
}

# install_pkl is the embedded bootstrap-pkl.sh logic, kept in sync with
# scripts/bootstrap-pkl.sh (same resolution, same redirect-not-API
# lesson). It installs into the same DEST as claymod.
install_pkl() {
  pkl_os="$(uname -s)"
  case "$pkl_os" in
    Linux)  pkl_os_name="linux" ;;
    Darwin) pkl_os_name="macos" ;;
    *)
      echo "error: unsupported OS '$pkl_os'. Install pkl manually from https://pkl-lang.org" >&2
      return 1
      ;;
  esac
  pkl_arch="$(uname -m)"
  case "$pkl_arch" in
    x86_64|amd64)  pkl_arch_name="amd64" ;;
    arm64|aarch64) pkl_arch_name="aarch64" ;;
    *)
      echo "error: unsupported architecture '$pkl_arch'" >&2
      return 1
      ;;
  esac
  pkl_asset="pkl-${pkl_os_name}-${pkl_arch_name}"

  if [ -n "${PKL_VERSION:-}" ]; then
    pkl_version="$PKL_VERSION"
  else
    echo "resolving latest pkl release..."
    pkl_version="$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
      https://github.com/apple/pkl/releases/latest 2>/dev/null | sed -n 's|.*/tag/||p' || true)"
    if [ -z "$pkl_version" ]; then
      echo "(redirect resolution failed, falling back to the GitHub API...)"
      pkl_version="$(curl -fsSL https://api.github.com/repos/apple/pkl/releases/latest 2>/dev/null \
        | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1 || true)"
    fi
    if [ -z "$pkl_version" ]; then
      echo "error: could not resolve latest pkl version (set PKL_VERSION=x.y.z)" >&2
      return 1
    fi
  fi

  pkl_url="https://github.com/apple/pkl/releases/download/${pkl_version}/${pkl_asset}"
  mkdir -p "$CACHE"
  pkl_work="$CACHE/pkl-$pkl_asset-$pkl_version"
  if [ ! -f "$pkl_work" ]; then
    echo "downloading $pkl_url ..."
    curl -fsSL -o "$pkl_work.tmp" "$pkl_url"
    mv "$pkl_work.tmp" "$pkl_work"
  fi

  echo "pkl $pkl_version ($pkl_asset) -> $DEST/pkl"
  mkdir -p "$DEST"
  chmod 0755 "$pkl_work"
  if [ -w "$DEST" ]; then
    cp "$pkl_work" "$DEST/pkl"
  else
    echo "(write access to $DEST required, retrying with sudo)"
    sudo cp "$pkl_work" "$DEST/pkl"
  fi
  echo "installed pkl: $("$DEST/pkl" --version)"
}

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

# A cached binary is NEVER trusted blindly: an interrupted prior run
# (curl keeps partial output) or a planted file at the predictable
# cache path must not reach `cp`/`sudo cp`. Verification runs on every
# invocation; only the big binary download is skipped on a cache hit.
if [ ! -f "$work" ]; then
  echo "downloading $base/$asset ..."
  # Download under the real asset name: `sha256sum -c` matches the file
  # name recorded in SHA256SUMS.
  curl -fsSL -o "$work" "$base/$asset"
fi
if [ ! -f "$work" ] || [ ! -f "$dir/SHA256SUMS" ] || [ "$work" -nt "$dir/SHA256SUMS" ]; then
  curl -fsSL -o "$dir/SHA256SUMS" "$base/SHA256SUMS"
fi
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
# SHA256SUMS travels the same channel as the binary: it proves transfer
# integrity, not authenticity. For an out-of-band anchor (mirrors,
# air-gapped), set CLAYMOD_SHA256 to the digest from a trusted source —
# the install aborts on any mismatch. Checked on every run.
if [ -n "${CLAYMOD_SHA256:-}" ]; then
  got="$((sha256sum "$work" 2>/dev/null || shasum -a 256 "$work") | cut -d' ' -f1)"
  if [ "$got" != "$(echo "$CLAYMOD_SHA256" | tr 'A-Z' 'a-z')" ]; then
    rm -f "$work"
    echo "error: CLAYMOD_SHA256 mismatch (got ${got:-none}) — do not use this binary" >&2
    exit 1
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
# The installer is embedded below: this script ships alone (curl | sh)
# and cannot rely on bootstrap-pkl.sh sitting next to it. When pkl is
# missing, ASK before downloading (INSTALL_PKL=1 pre-answers yes;
# SKIP_PKL=1 skips; without a terminal, print a note instead of asking).
pkl_missing_action() {
  if [ "${INSTALL_PKL:-}" != "1" ]; then
    if ! [ -r /dev/tty ]; then
      echo "note: pkl not installed — 'claymod playbook validate/plan' need it." >&2
      echo "      install with scripts/bootstrap-pkl.sh, or re-run with INSTALL_PKL=1." >&2
      return 0
    fi
    printf "pkl is not installed (needed for 'claymod playbook validate/plan'). Install it now? [Y/n] "
    answer=""
    read -r answer < /dev/tty 2>/dev/null || answer="n"
    case "$answer" in
      n*|N*)
        echo "skipped pkl — install later with scripts/bootstrap-pkl.sh."
        return 0
        ;;
    esac
  fi
  install_pkl
}

if [ "${SKIP_PKL:-}" = "1" ]; then
  echo "SKIP_PKL=1: pkl not installed (claymod playbook validate/plan need it)"
elif command -v pkl >/dev/null 2>&1; then
  echo "pkl already installed: $(command -v pkl)"
else
  pkl_missing_action
fi

path_hint "$DEST"

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
