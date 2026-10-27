# Enrollment runbook

Claymod enrolls hosts through a one-time token exchanged over the control
server's **HTTPS** bootstrap endpoint. The host's WireGuard private key is
generated locally and never leaves the host; the mTLS client certificate is
issued server-side by the internal CA and returned only over TLS.

## 1. Start the control server

```sh
claymod serve \
  --bootstrap-listen :8443 \
  --server-name claymod.internal \
  --wg-interface claymod0 \
  --wg-endpoint <public-ip-or-dns>:51820
```

First run creates the data dir (default `claymod-data/`): internal CA, the
bootstrap server certificate, the server's WireGuard key pair and the
inventory database. State is reloaded on restart — nothing is
regenerated.

The WireGuard interface `claymod0` must exist on the server before agents
can tunnel (root-only, see §5).

## 2. Create a one-time enrollment token

```sh
claymod host token web01 --ttl 15m
```

This prints the token and the exact `claymod enroll` command to run on the
host. Tokens are single-use, expire on TTL and are **bound to the
hostname** — an attempt to enroll as a different name is refused and does
not burn the token.

## 3. Enroll the host

On the host (with `claymod` available):

```sh
claymod enroll \
  --server https://claymod.internal:8443 \
  --token <token> \
  --hostname web01 \
  --ca-pin <sha256-of-bootstrap-server-cert>
```

Trust is **pinned**: either `--ca <bundle.pem>` (CA bundle) or
`--ca-pin <hex>` (SHA-256 fingerprint of the server's leaf certificate).
The fingerprint is printed by the server on startup and can be computed
with:

```sh
openssl s_client -connect claymod.internal:8443 -servername claymod.internal </dev/null 2>/dev/null \
  | openssl x509 -outform DER | shasum -a 256
```

`enroll` writes to `/etc/claymod/` (override with `--out-dir`):

| File | Purpose | Mode |
|---|---|---|
| `ca.pem` | CA bundle (verifies the control server) | 0644 |
| `agent.pem` | agent mTLS client certificate | 0644 |
| `agent-key.pem` | agent mTLS private key | 0600 |
| `agent.yaml` | agent configuration | 0644 |
| `wg-keys.json` | WireGuard key pair (generated locally) | 0600 |

## 4. Start the agent

```sh
claymod agent --config /etc/claymod/agent.yaml
```

The agent listens for framed mTLS connections on the WireGuard overlay
port (2323). No inbound port is exposed beyond the tunnel.

## 5. WireGuard interface setup (root-only, manual checklist)

**Control server** (once, before agents can tunnel):

```sh
# wg(8) wants the raw base64 key; wg-keys.json is JSON, so unpack it first.
sudo awk -F'"' '/private/ {print $4}' claymod-data/wg-keys.json | sudo tee /run/claymod-wg.key >/dev/null && sudo chmod 600 /run/claymod-wg.key
sudo ip link add dev claymod0 type wireguard
sudo ip address add 10.42.0.1/24 dev claymod0
sudo wg set claymod0 private-key /run/claymod-wg.key listen-port 51820
sudo ip link set up dev claymod0
sudo rm /run/claymod-wg.key
```

Peers are installed automatically by `claymod serve` (wgctrl backend) as
hosts enroll; `claymod host revoke` removes them.

**Agent host** (the `enroll` command prints these exact commands):

```sh
# wg(8) wants the raw base64 key; wg-keys.json is JSON, so unpack it first.
sudo awk -F'"' '/private/ {print $4}' /etc/claymod/wg-keys.json | sudo tee /run/claymod-wg.key >/dev/null && sudo chmod 600 /run/claymod-wg.key
sudo ip link add dev claymod0 type wireguard
sudo ip address add <allocated-ip>/24 dev claymod0
sudo wg set claymod0 private-key /run/claymod-wg.key listen-port 51820 \
  peer <server-public-key> endpoint <server-endpoint> \
  allowed-ips 10.42.0.0/24 persistent-keepalive 25
sudo ip link set up dev claymod0
sudo rm /run/claymod-wg.key
```

Verify the tunnel: `sudo wg show` (both sides should list each other) and
`ping 10.42.0.1` from the agent.

## 6. Revocation

```sh
claymod host revoke web01
```

Revoke is CRL-lite, inventory-driven: the WireGuard peer is removed, the
host row and IP allocation are freed (the IP is immediately reusable) and
the certificate **serial** is recorded in `revocations` — a revoked
certificate is rejected even if the file still exists on a compromised
host.

## 7. Verification (simulation)

The TLS and enrollment layers are verified end-to-end by the simulation,
which exercises this exact flow (token → HTTPS bootstrap → agent → probe):

```sh
simulation/run.sh          # docker compose (certgen era is gone: real enrollment)
simulation/run.sh --local  # loopback, no Docker
```

## 8. Security notes

- The bootstrap endpoint is HTTPS-only (TLS 1.3). A token sent over plain
  HTTP is never accepted: there is no plaintext listener.
- Enrollment requires a valid token, matching hostname and a pinned
  server identity (`--ca`/`--ca-pin`) — TOFU is not offered.
- The agent's WireGuard private key is generated on the host and is never
  transmitted; the mTLS keypair is transmitted exactly once, over TLS.
- `Command` ops run with the agent's privileges and are documented as the
  powerful escape hatch; `File` ops are restricted to absolute paths.
