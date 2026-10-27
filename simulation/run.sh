#!/usr/bin/env sh
# run.sh — run the claymod enrollment simulation.
#
#   simulation/run.sh            # docker compose mode (default)
#   simulation/run.sh --local    # loopback mode with local binaries (no Docker)
#
# Both modes exercise the REAL enrollment flow: `claymod serve` (HTTPS
# bootstrap) -> `claymod host token` -> `claymod enroll` (pinned) ->
# `claymod agent` -> TLS probe suite against the enrolled identity.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SIM="$ROOT/simulation"

if [ "${1:-}" = "--local" ]; then
  WORK="$SIM/.sim-local"
  rm -rf "$WORK"
  mkdir -p "$WORK/control" "$WORK/host" "$WORK/shared"

  echo "== building claymod"
  (cd "$ROOT" && go build -o "$WORK/claymod" ./cmd/claymod)

  echo "== starting control server (HTTPS bootstrap on 127.0.0.1:8443)"
  "$WORK/claymod" serve \
    --data-dir "$WORK/control" \
    --bootstrap-listen 127.0.0.1:8443 \
    --server-name localhost \
    --wg-backend fake \
    --wg-endpoint 127.0.0.1:51821 &
  CONTROL_PID=$!
  cleanup() {
    kill "$CONTROL_PID" "${AGENT_PID:-}" 2>/dev/null || true
    wait "$CONTROL_PID" "${AGENT_PID:-}" 2>/dev/null || true
  }
  trap cleanup EXIT INT TERM

  echo "== waiting for bootstrap endpoint"
  tries=0
  until curl -fsSk https://localhost:8443/healthz >/dev/null 2>&1; do
    tries=$((tries + 1))
    if [ "$tries" -gt 60 ]; then echo "bootstrap never came up" >&2; exit 1; fi
    sleep 1
  done

  # Publish CA + control identity where the probes can find them.
  cp "$WORK/control/ca/ca.pem" "$WORK/shared/ca.pem"
  cp "$WORK/control/control.pem" "$WORK/shared/control.pem"
  cp "$WORK/control/control-key.pem" "$WORK/shared/control-key.pem"

  echo "== issuing one-time enrollment token"
  "$WORK/claymod" host token agent \
    --data-dir "$WORK/control" \
    --token-file "$WORK/shared/token" --ttl 10m

  echo "== enrolling host (pinned CA bundle)"
  "$WORK/claymod" enroll \
    --server https://localhost:8443 \
    --token "$(tr -d '[:space:]' < "$WORK/shared/token")" \
    --hostname agent \
    --ca "$WORK/shared/ca.pem" \
    --out-dir "$WORK/host" \
    --listen 127.0.0.1:2323 \
    --skip-wg-config

  echo "== starting the enrolled agent on 127.0.0.1:2323"
  "$WORK/claymod" agent --config "$WORK/host/agent.yaml" &
  AGENT_PID=$!
  sleep 1

  echo "== running probes against the enrolled identity"
  # The agent's enrolled certificate carries its hostname ("agent") as the
  # DNS SAN: TLS ServerName must be "agent" even when dialing loopback.
  # NB: PATH must be assigned BEFORE WORK reassigns it — bash expands
  # env assignments left to right.
  PATH="$WORK:$PATH" AGENT_ADDR=127.0.0.1:2323 SERVER_NAME=agent \
    SHARED_DIR="$WORK/shared" WORK="$WORK/probe-tmp" \
    sh "$SIM/scripts/probes.sh"
else
  echo "== docker compose mode (enrollment flow)"
  set +e
  docker compose -f "$SIM/docker-compose.yml" up --build --exit-code-from probes
  status=$?
  docker compose -f "$SIM/docker-compose.yml" logs probes
  docker compose -f "$SIM/docker-compose.yml" down -v
  exit $status
fi
