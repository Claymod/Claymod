#!/bin/sh
# control-entry.sh — start the claymod control server and issue a
# one-time enrollment token for the simulated host.
#
# The enrollment flow is the real one: `claymod serve` creates the CA and
# bootstrap identity, then `claymod host token` issues a token that the
# host container consumes over HTTPS.
set -eu

DATA_DIR=/data
export CLAYMOD_SCHEMA_DIR="${CLAYMOD_SCHEMA_DIR:-/pkl}"

echo "== starting claymod serve (HTTPS bootstrap on :8443)"
mkdir -p "$DATA_DIR"
claymod serve \
  --data-dir "$DATA_DIR" \
  --bootstrap-listen :8443 \
  --server-name "${SERVER_NAME:-control}" \
  --wg-backend fake \
  --wg-endpoint control:51820 &
SERVE_PID=$!

# Wait for the bootstrap endpoint to answer.
echo "== waiting for bootstrap endpoint"
tries=0
until curl -fsS "https://control:8443/healthz" -k >/dev/null 2>&1; do
  tries=$((tries + 1))
  if [ "$tries" -gt 60 ]; then
    echo "bootstrap endpoint never came up" >&2
    exit 1
  fi
  sleep 1
done
echo "== bootstrap endpoint is up"

# Share the CA bundle and the control client identity (the runner's mTLS
# identity) with the probes container.
cp "$DATA_DIR/ca/ca.pem" /shared/ca.pem
cp "$DATA_DIR/control.pem" /shared/control.pem
cp "$DATA_DIR/control-key.pem" /shared/control-key.pem
chmod 0644 /shared/ca.pem /shared/control.pem
chmod 0600 /shared/control-key.pem

echo "== issuing one-time enrollment token for ${HOSTNAME_FOR_TOKEN:-agent}"
claymod host token "${HOSTNAME_FOR_TOKEN:-agent}" \
  --data-dir "$DATA_DIR" \
  --token-file /shared/token --ttl 10m

echo "== control ready; token published to /shared/token"
wait "$SERVE_PID"
