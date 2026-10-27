#!/bin/sh
# probes.sh — TLS verification probes against a running claymod agent.
#
# Environment:
#   AGENT_ADDR  agent address (host:port), default agent:2323
#   SERVER_NAME TLS server name, default agent
#   CERTS       directory with the generated PKI, default /certs
#
# Exits 0 when every probe behaves as expected (successes succeed,
# rejections reject); non-zero otherwise.
set -eu

AGENT_ADDR="${AGENT_ADDR:-agent:2323}"
SERVER_NAME="${SERVER_NAME:-agent}"
CERTS="${CERTS:-/certs}"

probe() {
  claymod probe \
    --addr "$AGENT_ADDR" \
    --server-name "$SERVER_NAME" \
    --ca "$CERTS/ca.pem" \
    "$@"
}

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

# 1. Valid client cert: full Ping/Facts/Apply smoke must pass.
check "valid client certificate" \
  probe --cert "$CERTS/control.pem" --key "$CERTS/control-key.pem"

# 2. Client cert from an untrusted CA must be refused.
check "untrusted client CA rejected" \
  probe --cert "$CERTS/rogue.pem" --key "$CERTS/rogue-key.pem" --expect-reject

# 3. Wrong EKU (ServerAuth-only cert presented as client) must be refused.
check "wrong EKU rejected" \
  probe --cert "$CERTS/wrong-eku.pem" --key "$CERTS/wrong-eku-key.pem" --expect-reject

# 4. No client certificate at all must be refused (mTLS is mandatory).
check "missing client cert rejected" \
  probe --expect-reject

# 5. The probe must not trust a server signed by a different CA.
check "untrusted server rejected" \
  sh -c "claymod probe --addr '$AGENT_ADDR' --server-name '$SERVER_NAME' \
    --ca '$CERTS/rogue-ca.pem' --cert '$CERTS/control.pem' --key '$CERTS/control-key.pem' \
    --expect-reject"

echo
if [ "$fail" -eq 0 ]; then
  echo "ALL PROBES PASSED: TLS layer verified"
else
  echo "TLS PROBE FAILURES DETECTED"
fi
exit "$fail"
