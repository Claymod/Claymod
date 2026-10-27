#!/bin/sh
# probes.sh — TLS verification against an agent that enrolled through the
# real enrollment flow. The agent's mTLS identity was issued by the
# control CA during `claymod enroll`; nothing here is pre-generated.
#
# Environment:
#   AGENT_ADDR   agent address (host:port), default agent:2323
#   SERVER_NAME  TLS server name on the agent certificate, default agent
#   SHARED_DIR   directory with ca.pem / control.pem / control-key.pem
#                (published by the control container), default /shared
#   WORK         scratch directory for generated fixtures
#
# Exits 0 when every probe behaves as expected.
set -eu

AGENT_ADDR="${AGENT_ADDR:-agent:2323}"
SERVER_NAME="${SERVER_NAME:-agent}"
SHARED_DIR="${SHARED_DIR:-/shared}"
WORK="${WORK:-/tmp/claymod-probes}"
mkdir -p "$WORK"

CA="$SHARED_DIR/ca.pem"
CERT="$SHARED_DIR/control.pem"
KEY="$SHARED_DIR/control-key.pem"

# The control container publishes the fixtures asynchronously: wait for
# them (bounded), the same way the host container waits for the token.
echo "== waiting for enrollment fixtures in $SHARED_DIR"
tries=0
while :; do
  ok=1
  for f in "$CA" "$CERT" "$KEY"; do
    [ -s "$f" ] || ok=0
  done
  [ "$ok" -eq 1 ] && break
  tries=$((tries + 1))
  if [ "$tries" -gt 120 ]; then
    echo "missing fixtures in $SHARED_DIR (did the control container publish them?)" >&2
    exit 1
  fi
  sleep 1
done
echo "== fixtures present"

probe() {
  # The smoke file lands on the AGENT's filesystem (the apply runs
  # there): use the /tmp-rooted default so its parent always exists.
  claymod probe \
    --addr "$AGENT_ADDR" \
    --server-name "$SERVER_NAME" \
    --ca "$CA" \
    "$@"
}

# The agent container enrolls and only then starts listening: wait for
# the enrolled agent to accept connections before probing (bounded).
echo "== waiting for the enrolled agent at $AGENT_ADDR"
tries=0
until probe --cert "$CERT" --key "$KEY" >/dev/null 2>&1; do
  tries=$((tries + 1))
  if [ "$tries" -gt 120 ]; then
    echo "enrolled agent never became reachable at $AGENT_ADDR" >&2
    exit 1
  fi
  sleep 1
done
echo "== enrolled agent is reachable"

fail=0
check() {
  name="$1"
  shift
  echo "=== $name"
  if "$@"; then
    echo "=== $name: PASS"
  else
    echo "=== $name: FAIL"
    fail=1
  fi
}

# 1. The control-side identity (issued by the same CA that enrolled the
#    agent) must connect: Ping, Facts and the Apply smoke over real mTLS.
check "enrolled identity connects (Ping/Facts/Apply)" \
  probe --cert "$CERT" --key "$KEY"

# 2. No client certificate at all must be refused (mTLS is mandatory).
check "anonymous client rejected" \
  probe --expect-reject

# 3. A self-signed rogue client certificate (never seen by the CA) must
#    be refused. Generated here with RSA — portable across OpenSSL and
#    LibreSSL (EC key encodings differ and Go rejects some).
openssl req -x509 -newkey rsa:2048 \
  -keyout "$WORK/rogue-key.pem" -out "$WORK/rogue.pem" \
  -days 1 -nodes -subj "/CN=rogue" || {
    echo "failed to generate the rogue fixture with openssl" >&2
    exit 1
  }
grep -q "BEGIN CERTIFICATE" "$WORK/rogue.pem" || {
  echo "rogue.pem is not a certificate" >&2
  exit 1
}
check "rogue client certificate rejected" \
  probe --cert "$WORK/rogue.pem" --key "$WORK/rogue-key.pem" --expect-reject

# 4. The probe must not trust the agent when it verifies against the
#    wrong CA bundle (the rogue self-signed cert works as an untrusted
#    one-cert bundle).
check "untrusted server rejected" \
  probe --ca "$WORK/rogue.pem" --cert "$CERT" --key "$KEY" --expect-reject

echo
if [ "$fail" -eq 0 ]; then
  echo "ALL PROBES PASSED: enrollment + TLS layer verified"
else
  echo "TLS PROBE FAILURES DETECTED"
fi
exit "$fail"
