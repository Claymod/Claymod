#!/usr/bin/env sh
# test-docker-image.sh — build the claymod control-server image and exercise
# it for real (bootstrap endpoint, served agent binaries, WireGuard interface).
#
# The same script runs on a workstation and in CI, so an image that breaks
# fails identically in both places.
#
# Usage:
#   scripts/test-docker-image.sh                  # build + test
#   NO_BUILD=1 IMAGE=claymod:ci scripts/test-docker-image.sh
#   scripts/test-docker-image.sh --multiarch      # also cross-build amd64+arm64
#   scripts/test-docker-image.sh --keep           # keep containers for inspection
#
# Environment:
#   IMAGE=claymod:dev       image tag to build/use
#   VERSION=dev             version stamped into the binaries (and asserted)
#   NO_BUILD=1              use an existing image instead of building
#   SKIP_WG=1               skip the real-WireGuard check (no NET_ADMIN/module)
#   KEEP=1                  keep containers after the run
#
# Exit code: 0 only when every required check passed (SKIPs are reported
# separately and do not fail the run).
set -eu

IMAGE=${IMAGE:-claymod:dev}
VERSION=${VERSION:-dev}
NO_BUILD=${NO_BUILD:-0}
SKIP_WG=${SKIP_WG:-0}
KEEP=${KEEP:-0}
MULTIARCH=0
BUILDER="claymod-smoke-$$"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/claymod-image-test.XXXXXX")
FAKE_NAME="claymod-smoke-fake-$$"
WG_NAME="claymod-smoke-wg-$$"
PASSED=0
FAILED=0
SKIPPED=0
FAILURES=""

usage() {
  sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
  case "$1" in
    --multiarch) MULTIARCH=1 ;;
    --keep) KEEP=1 ;;
    --no-build) NO_BUILD=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

pass() { PASSED=$((PASSED + 1)); printf 'PASS  %s\n' "$1"; }
fail() {
  FAILED=$((FAILED + 1))
  FAILURES="${FAILURES}
  - $1"
  printf 'FAIL  %s\n' "$1"
}
skip() { SKIPPED=$((SKIPPED + 1)); printf 'SKIP  %s\n' "$1"; }

digest() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

dump_logs() {
  printf -- '--- docker logs %s ---\n' "$1"
  docker logs "$1" 2>&1 || true
  printf -- '--- end logs ---\n'
}

cleanup() {
  for c in "$FAKE_NAME" "$WG_NAME"; do
    if [ "$KEEP" = 1 ] && docker inspect "$c" >/dev/null 2>&1; then
      printf 'kept container %s\n' "$c"
    else
      docker rm -f "$c" >/dev/null 2>&1 || true
    fi
  done
  docker buildx rm "$BUILDER" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM HUP

# --- build -----------------------------------------------------------------
if [ "$NO_BUILD" = 1 ]; then
  if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "image $IMAGE not found and NO_BUILD=1" >&2
    exit 1
  fi
  echo "== using existing image $IMAGE"
else
  echo "== building $IMAGE (VERSION=$VERSION)"
  docker build --build-arg "VERSION=$VERSION" -t "$IMAGE" .
fi
echo "== size: $(docker images "$IMAGE" --format '{{.Size}}' | head -n 1)"

# --- 1. binaries and version -----------------------------------------------
out=$(docker run --rm "$IMAGE" version)
case "$out" in
  *"claymod $VERSION"*) pass "claymod version reports '$VERSION'" ;;
  *) fail "claymod version: got '$out', want 'claymod $VERSION'" ;;
esac

pkl_out=$(docker run --rm --entrypoint pkl "$IMAGE" --version 2>&1 || true)
case "$pkl_out" in
  Pkl\ *) pass "pkl runs: $pkl_out" ;;
  *) fail "pkl --version failed: $pkl_out" ;;
esac

# --- 2. runtime dependencies ----------------------------------------------
missing=$(docker run --rm --entrypoint sh "$IMAGE" -c \
  'for b in claymod pkl ip wg git curl; do command -v "$b" >/dev/null || printf "%s " "$b"; done')
if [ -z "$missing" ]; then
  pass "runtime tools present (claymod, pkl, ip, wg, git, curl)"
else
  fail "missing runtime tools: $missing"
fi

agents=$(docker run --rm --entrypoint sh "$IMAGE" -c \
  'ls /var/lib/claymod/agents/claymod-agent-* 2>/dev/null | wc -l' | tr -d ' ')
if [ "$agents" = 4 ]; then
  pass "4 agent binaries baked in (linux/darwin, amd64/aarch64)"
else
  fail "agent binaries baked in: found $agents, want 4"
fi

# --- 3. fake backend: bootstrap endpoint, download, shutdown ---------------
echo "== starting serve (fake WG backend)"
docker run -d --name "$FAKE_NAME" -p 127.0.0.1::8443 "$IMAGE" \
  serve --data-dir /tmp/data --wg-backend fake --bootstrap-listen :8443 \
  --agent-bin-dir /var/lib/claymod/agents >/dev/null

mapped=$(docker port "$FAKE_NAME" 8443/tcp 2>/dev/null || true)
PORT=${mapped##*:}
if [ -z "$mapped" ]; then
  fail "could not resolve the published port"
  dump_logs "$FAKE_NAME"
else
  BASE="https://127.0.0.1:${PORT}"
  i=0
  up=0
  while [ "$i" -lt 60 ]; do
    if curl -fsSk -o /dev/null "$BASE/healthz" 2>/dev/null; then up=1; break; fi
    i=$((i + 1))
    sleep 1
  done
  if [ "$up" = 1 ]; then
    pass "bootstrap endpoint answers /healthz on :${PORT}"
  else
    fail "bootstrap endpoint never answered /healthz"
    dump_logs "$FAKE_NAME"
  fi

  if docker logs "$FAKE_NAME" 2>&1 | grep -q "agent binaries offered for download"; then
    pass "startup log advertises the served agent binaries"
  else
    fail "startup log does not advertise agent binaries"
  fi

  if curl -fsSk -o "$WORK/agent" "$BASE/agent/linux/amd64" 2>/dev/null &&
     curl -fsSk -o "$WORK/agent.sha256" "$BASE/agent/linux/amd64.sha256" 2>/dev/null; then
    got=$(digest "$WORK/agent")
    want=$(awk '{print $1}' "$WORK/agent.sha256")
    if [ "$got" = "$want" ] && [ -n "$want" ]; then
      pass "agent download matches its served sha256 ($want)"
    else
      fail "agent download digest mismatch (local=$got served=$want)"
    fi
  else
    fail "agent binary or its .sha256 could not be downloaded"
  fi

  code=$(curl -s -k -o /dev/null -w '%{http_code}' "$BASE/agent/windows/amd64" 2>/dev/null || true)
  if [ "$code" = 404 ]; then
    pass "unknown platform is refused with 404"
  else
    fail "unknown platform returned HTTP ${code:-<none>}, want 404"
  fi

  if curl -fsSk -o "$WORK/enroll.sh" "$BASE/enroll.sh" 2>/dev/null &&
     grep -q -- '--token' "$WORK/enroll.sh"; then
    pass "enroll.sh is served and takes a token"
  else
    fail "enroll.sh is missing or does not mention --token"
  fi

  docker stop -t 20 "$FAKE_NAME" >/dev/null
  exit_code=$(docker inspect -f '{{.State.ExitCode}}' "$FAKE_NAME")
  if docker logs "$FAKE_NAME" 2>&1 | grep -q "shutting down" && [ "$exit_code" = 0 ]; then
    pass "docker stop shuts serve down gracefully (exit 0)"
  else
    fail "graceful shutdown failed (exit=$exit_code)"
    dump_logs "$FAKE_NAME"
  fi
fi

# --- 4. real WireGuard backend (NET_ADMIN) ---------------------------------
if [ "$SKIP_WG" = 1 ]; then
  skip "real WireGuard backend (SKIP_WG=1)"
else
  echo "== starting serve (real wgctrl backend, --cap-add NET_ADMIN)"
  if ! docker run -d --name "$WG_NAME" --cap-add NET_ADMIN "$IMAGE" >/dev/null 2>&1; then
    skip "real WireGuard backend (docker refused --cap-add NET_ADMIN)"
  else
    i=0
    ready=0
    while [ "$i" -lt 40 ]; do
      if docker logs "$WG_NAME" 2>&1 | grep -q "bootstrap endpoint listening"; then
        ready=1
        break
      fi
      if [ "$(docker inspect -f '{{.State.Running}}' "$WG_NAME" 2>/dev/null || echo false)" != "true" ]; then
        break
      fi
      i=$((i + 1))
      sleep 1
    done

    if [ "$ready" != 1 ]; then
      logs=$(docker logs "$WG_NAME" 2>&1 || true)
      case "$logs" in
        *"Operation not permitted"*|*"not supported"*|*"No such device"*|*"Unknown device"*)
          skip "real WireGuard backend (kernel/daemon cannot provide it: $(printf '%s' "$logs" | grep -E 'not permitted|not supported|No such device|Unknown device' | head -n 1))"
          ;;
        *)
          fail "serve with the real WireGuard backend did not come up"
          dump_logs "$WG_NAME"
          ;;
      esac
    else
      if docker logs "$WG_NAME" 2>&1 | grep -q "wireguard interface ensured"; then
        pass "WireGuard interface created at startup"
      else
        fail "startup log has no 'wireguard interface ensured'"
        dump_logs "$WG_NAME"
      fi

      if docker exec "$WG_NAME" ip -brief addr show claymod0 2>/dev/null |
           grep -q "10.42.0.1/24"; then
        pass "claymod0 carries the overlay address 10.42.0.1/24"
      else
        fail "claymod0 is missing or has the wrong overlay address"
        docker exec "$WG_NAME" ip -brief addr show claymod0 2>&1 || true
      fi

      port=$(docker exec "$WG_NAME" wg show claymod0 listen-port 2>/dev/null | tr -d ' ')
      if [ "$port" = 51821 ]; then
        pass "WireGuard listens on UDP 51821"
      else
        fail "WireGuard listen port is '${port:-<none>}', want 51821"
      fi

      if docker exec "$WG_NAME" claymod host token web01 \
           --config /etc/claymod/server.yaml >"$WORK/token.out" 2>&1 &&
         grep -q "enrollment token for web01" "$WORK/token.out"; then
        pass "host token works against the baked config"
      else
        fail "host token failed against /etc/claymod/server.yaml"
        sed -n '1,5p' "$WORK/token.out" || true
      fi

      if docker exec "$WG_NAME" test -s /var/lib/claymod/inventory.db &&
         docker exec "$WG_NAME" test -s /var/lib/claymod/claymod0.conf; then
        pass "state written under /var/lib/claymod (inventory.db, claymod0.conf)"
      else
        fail "expected state files missing under /var/lib/claymod"
      fi

      docker stop -t 20 "$WG_NAME" >/dev/null
    fi
  fi
fi

# --- 5. compose example ----------------------------------------------------
if [ -f examples/docker-compose.yaml ]; then
  if CLAYMOD_WG_ENDPOINT=203.0.113.10:51821 \
       docker compose -f examples/docker-compose.yaml config -q >/dev/null 2>&1; then
    pass "examples/docker-compose.yaml parses with an endpoint set"
  else
    fail "examples/docker-compose.yaml does not parse"
  fi
  if ( unset CLAYMOD_WG_ENDPOINT; \
       docker compose -f examples/docker-compose.yaml config -q >/dev/null 2>&1 ); then
    fail "compose accepted a missing CLAYMOD_WG_ENDPOINT"
  else
    pass "compose refuses to start without CLAYMOD_WG_ENDPOINT"
  fi
else
  skip "compose example not present yet"
fi

# --- 6. multi-arch build (opt-in) ------------------------------------------
# Each platform is built on its own: two concurrent Go builds of the sqlite
# driver exceed a small builder VM (2 GB colima dies with "cannot allocate
# memory"), and the point here is that each architecture's image builds.
# CI's publish job is free to build both in one invocation.
if [ "$MULTIARCH" = 1 ]; then
  if ! docker buildx version >/dev/null 2>&1; then
    skip "multi-arch build (docker buildx not installed)"
  elif ! docker buildx create --name "$BUILDER" --driver docker-container >/dev/null 2>&1; then
    skip "multi-arch build (cannot create a docker-container builder)"
  else
    built=0
    for platform in linux/amd64 linux/arm64; do
      printf '== building %s\n' "$platform"
      out="$WORK/image-$(printf '%s' "$platform" | tr '/' '-').tar"
      if docker buildx build --builder "$BUILDER" --build-arg "VERSION=$VERSION" \
           --platform "$platform" --output "type=oci,dest=$out" .; then
        built=$((built + 1))
      else
        fail "multi-arch build: $platform failed"
      fi
    done
    if [ "$built" = 2 ]; then
      pass "multi-arch build path: linux/amd64 and linux/arm64 both build"
    fi
  fi
fi

# --- summary ---------------------------------------------------------------
printf '\n%d passed, %d failed, %d skipped\n' "$PASSED" "$FAILED" "$SKIPPED"
if [ "$FAILED" -gt 0 ]; then
  printf 'failures:%s\n' "$FAILURES"
  exit 1
fi
echo "image $IMAGE: OK"
