#!/bin/sh
# enroll-entry.sh — enroll this host through the real enrollment flow,
# then run the claymod agent on the enrolled identity.
#
# Nothing here is pre-generated: the WireGuard key pair is created by
# `claymod enroll` on this host, and the mTLS identity is issued by the
# control server over HTTPS in exchange for the one-time token.
set -eu

CONTROL_URL="${CONTROL_URL:-https://control:8443}"
HOSTNAME="${HOSTNAME_FOR_TOKEN:-agent}"
OUT_DIR=/etc/claymod

echo "== waiting for enrollment token"
tries=0
until [ -s /shared/token ] && [ -s /shared/ca.pem ]; do
  tries=$((tries + 1))
  if [ "$tries" -gt 120 ]; then
    echo "enrollment token never appeared" >&2
    exit 1
  fi
  sleep 1
done
TOKEN="$(tr -d '[:space:]' < /shared/token)"

echo "== enrolling $HOSTNAME with $CONTROL_URL (pinned CA bundle)"
claymod enroll \
  --server "$CONTROL_URL" \
  --token "$TOKEN" \
  --hostname "$HOSTNAME" \
  --ca /shared/ca.pem \
  --out-dir "$OUT_DIR" \
  --listen "0.0.0.0:2323" \
  --skip-wg-config

echo "== enrollment complete"

# The token must be single-use: a second enrollment with the same token
# has to fail (this asserts the implemented enrollment semantics).
echo "== asserting the token is single-use"
if claymod enroll \
  --server "$CONTROL_URL" \
  --token "$TOKEN" \
  --hostname "$HOSTNAME" \
  --ca /shared/ca.pem \
  --out-dir "$OUT_DIR" \
  --skip-wg-config >/dev/null 2>&1; then
  echo "SECURITY FAILURE: the enrollment token was accepted twice" >&2
  exit 1
fi
echo "== token single-use verified"

echo "== starting the agent"
exec claymod agent --config "$OUT_DIR/agent.yaml"
