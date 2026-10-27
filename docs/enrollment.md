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
  --wg-endpoint <public-ip-or-dns>:51821
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

### Air-gapped bootstrap: the agent binary comes from the server

Hosts need only `curl` and the pinned CA bundle (or the server cert
fingerprint). Everything else flows over the one pinned TLS channel:

```sh
# on the host, with ca.pem in hand:
curl --cacert ca.pem -o claymod-agent \
  https://control:8443/agent/linux/amd64
curl --cacert ca.pem https://control:8443/agent/linux/amd64.sha256
shasum -a 256 claymod-agent     # compare with the served digest
chmod +x claymod-agent
```

`claymod serve --agent-bin-dir` (default `<data-dir>/agents`) exposes
binaries placed there (`make agents` cross-compiles the matrix and
prints sha256 sums). `serve` logs each digest at startup — verify
against that channel out-of-band. Then enroll and run as usual:

```sh
./claymod-agent enroll --server https://control:8443 --token ... \
  --hostname web01 --ca ca.pem --out-dir /etc/claymod
sudo ./claymod-agent wg-setup          # WireGuard bring-up (root step)
sudo ./claymod-agent agent --config /etc/claymod/agent.yaml
```

## 4. Start the agent

```sh
claymod agent --config /etc/claymod/agent.yaml
```

The agent listens for framed mTLS connections on the WireGuard overlay
port (2323). No inbound port is exposed beyond the tunnel.

## 5. WireGuard interface setup

The overlay itself is the one part claymod does not silently own: bring
it up however fits your environment. Three supported paths, pick one.

Address layout (routed overlays): the control server owns `base+1`
(e.g. `10.42.0.1`), hosts are allocated from `base+2` up. Loopback dev
networks (127/8) share `127.0.0.1` and have no reservation. The default
UDP port is **51821** — deliberately not WireGuard's standard 51820 so
claymod never collides with a user's own tunnel (`--wg-port` to change).

### Path A — operator-managed (default, no root needed for claymod)

`claymod serve` maintains `claymod-data/<interface>.conf` (0600 — it
contains the server's private key), regenerated on every enroll/revoke
and on restart. Apply it yourself:

```sh
sudo wg-quick up /path/to/claymod-data/claymod0.conf   # first time
sudo wg syncconf claymod0 <(wg-quick strip /path/to/claymod-data/claymod0.conf)
```

On the host, `claymod enroll` writes `/etc/claymod/wg-setup.json` with
everything for its side (overlay address, locally generated private key,
the server's peer entry). Render the equivalent wg-quick config from it,
or run path B.

### Path B — `claymod wg-setup` (one root step on each side)

```sh
# control server (root):
sudo claymod serve --manage-interface ...
# or after the fact:
sudo claymod wg-setup   # host side; reads /etc/claymod/wg-setup.json
```

`--manage-interface` creates/refreshes the interface at startup (needs
`CAP_NET_ADMIN`); peers are kept in sync via wgctrl as hosts enroll.
`claymod wg-setup` does the same for the host side from its enrollment
output.

### Path C — wg-quick / networkd / container runtime

Read the generated files (server: `claymod0.conf`; host:
`wg-setup.json`) and drive your own networking. Nothing in claymod
fights you: peers land in the config file either way.

**Verify** after bring-up: `sudo wg show` on both sides should list each
other, and `ping <server-overlay-ip>` (e.g. 10.42.0.1) from the agent.

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
