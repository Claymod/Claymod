#!/bin/sh
# enroll-entry.sh — the air-gap bootstrap flow: download the agent binary
# from the control server over the pinned TLS channel, verify its
# digest, enroll, then run it. Nothing on this host is preinstalled: the
# agent binary itself comes from the server.
set -eu

CONTROL_URL="${CONTROL_URL:-https://control:8443}"
HOSTNAME="${HOSTNAME_FOR_TOKEN:-agent}"
OUT_DIR=/etc/claymod
WORK=/tmp/claymod-bootstrap

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

mkdir -p "$WORK"

echo "== downloading the agent binary from the control server (air-gap bootstrap)"
curl -fsS --cacert /shared/ca.pem   -o "$WORK/claymod-agent" "$CONTROL_URL/agent/linux/amd64"
chmod +x "$WORK/claymod-agent"

echo "== verifying the agent binary digest"
curl -fsS --cacert /shared/ca.pem   "$CONTROL_URL/agent/linux/amd64.sha256" > "$WORK/expected.sha256"
ACTUAL="$(sha256sum "$WORK/claymod-agent" | awk '{print $1}')"
EXPECTED="$(awk '{print $1}' "$WORK/expected.sha256")"
if [ "$ACTUAL" != "$EXPECTED" ]; then
  echo "SECURITY FAILURE: agent digest mismatch ($ACTUAL != $EXPECTED)" >&2
  exit 1
fi
echo "== agent digest verified ($ACTUAL)"

echo "== enrolling $HOSTNAME with $CONTROL_URL (pinned CA bundle)"
"$WORK/claymod-agent" enroll \
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
if "$WORK/claymod-agent" enroll \
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

echo "== starting the downloaded agent"
exec "$WORK/claymod-agent" agent --config "$OUT_DIR/agent.yaml"
