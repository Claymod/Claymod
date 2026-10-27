#!/usr/bin/env sh
# run.sh — run the claymod TLS simulation.
#
#   simulation/run.sh            # docker compose mode (default)
#   simulation/run.sh --local    # loopback mode with local binaries (no Docker)
#
# Docker mode: builds the image, generates PKI in a volume, starts the
# agent and runs the probe suite from the control container. The compose
# project's exit code is the verdict.
#
# Local mode: generates PKI into simulation/.certs-local, starts the agent
# as a background process on 127.0.0.1:2323 and runs the same probe suite
# against it. Useful on machines without Docker.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SIM="$ROOT/simulation"

if [ "${1:-}" = "--local" ]; then
  WORK="$SIM/.certs-local"
  AGENT_ADDR="127.0.0.1:2323"

  echo "== building claymod and certgen"
  (cd "$ROOT" && go build -o "$SIM/.bin/claymod" ./cmd/claymod)
  (cd "$ROOT" && go build -o "$SIM/.bin/certgen" ./simulation/certgen)

  echo "== generating PKI into $WORK"
  rm -rf "$WORK"
  "$SIM/.bin/certgen" -out "$WORK" -agent-host localhost -listen "127.0.0.1:2323"

  echo "== starting agent on $AGENT_ADDR"
  "$SIM/.bin/claymod" agent --config "$WORK/agent.yaml" &
  AGENT_PID=$!
  # The agent logs to stderr; give the listener a moment to bind.
  sleep 1
  cleanup() {
    kill "$AGENT_PID" 2>/dev/null || true
    wait "$AGENT_PID" 2>/dev/null || true
  }
  trap cleanup EXIT INT TERM

  echo "== running probes"
  AGENT_ADDR="$AGENT_ADDR" SERVER_NAME=localhost CERTS="$WORK" \
    PATH="$SIM/.bin:$PATH" sh "$SIM/scripts/probes.sh"
else
  echo "== docker compose mode"
  set +e
  docker compose -f "$SIM/docker-compose.yml" up --build --exit-code-from control
  status=$?
  docker compose -f "$SIM/docker-compose.yml" logs control
  docker compose -f "$SIM/docker-compose.yml" down -v
  exit $status
fi
