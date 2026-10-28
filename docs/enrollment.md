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

This prints the token and the exact host-side commands (download the
`claymod-agent` binary, then `./claymod-agent enroll …`). Tokens are
single-use, expire on TTL and are **bound to the hostname** — an attempt
to enroll as a different name is refused and does not burn the token.

## 3. Enroll the host

On the host, with the **agent** binary in hand (`claymod-agent` — from
`make agent`, the release, or the pinned download in §3a):

```sh
claymod-agent enroll \
  --server https://claymod.internal:8443 \
  --token <token> \
  --hostname web01 \
  --ca-pin <CA-fingerprint>
```

The full `claymod` binary embeds the same `enroll`/`agent`/`wg-setup`
subcommands, so it works too — hosts just don't need its weight.

Trust is **pinned**: either `--ca <bundle.pem>` (CA bundle) or
`--ca-pin <hex>` (the CA fingerprint, printed by the server on
startup as "CA fingerprint (the pin: /enroll.sh and --ca-pin)"). Both
pin modes verify the served `/ca.pem` bundle against exactly this
value — one pin for the whole deployment. The two differ in hostname
handling: `--ca` performs stock TLS hostname verification (enroll via
the `--server-name` DNS name), while `--ca-pin` waives it — the pinned
CA *is* the identity, so enrolling against a bare IP works too (the
bootstrap certificate carries DNS SANs only). It can also be computed
with:

```sh
# hash the SERVED CA certificate (what --ca-pin compares against),
# not the TLS leaf the server presents in the handshake:
curl -fsSLk https://claymod.internal:8443/ca.pem \
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
| `wg-setup.json` | everything `wg-setup` needs to bring up the tunnel | 0600 |

### One-liner bootstrap (curl | sh)

For bulk or remote enrollment, `claymod serve` serves a generated
bootstrap script at `GET|POST /enroll.sh`:

```sh
# CA_FINGERPRINT is printed by `claymod serve` at startup:
#   CA fingerprint (the pin: /enroll.sh and --ca-pin):
#     <64 hex chars>
# The -k is required: the bootstrap certificate comes from claymod's
# internal CA — the fingerprint you pass IS the trust anchor.
curl -fsSLk -d "$CA_FINGERPRINT" https://control:8443/enroll.sh \
  | sudo sh -s -- --token <TOKEN> --hostname web01
```

Use a URL whose host name matches the server's `--server-name` (the
script's own downloads verify the hostname against the pinned CA;
resolve it via DNS or a hosts entry, or pass `--server` to the script to
override the URL baked into it). Note the pipeline reports `sh`'s exit
code, not curl's: if the fetch fails, `sh` silently succeeds on empty
input — check the output, or use the cautious fetch-first form in
[docs/security.md](security.md#one-liner-bootstrap).

What the script does, in order, failing closed at every step:

1. fetches the CA bundle over an untrusted channel and **verifies it
   against your pinned fingerprint** (this is the trust anchor — the
   transport itself is untrusted on purpose);
2. downloads `claymod-agent` for this platform from
   `GET /agent/{goos}/{goarch}` over the now-verified channel;
3. checks the agent binary against its served SHA-256 digest;
4. enrolls (single-use token, WireGuard key generated locally);
5. runs `claymod-agent wg-setup` (the one root-only step);
6. installs `/usr/local/bin/claymod-agent` plus a **systemd unit**
   (`claymod-agent.service`, `Restart=always`, `enable --now`) so the
   agent survives reboots. Note the unit starts only the agent: after a
   host reboot the WireGuard tunnel must be re-created first
   (`claymod-agent wg-setup`, or your own wg-quick unit) before the
   agent can be reached again.

Options: `--server`, `--pin`, `--out-dir`, `--bin-dir`, `--skip-wg`
(skip WireGuard bring-up), `--no-systemd` (install the binary only).
The script is POSIX sh and runs on any Linux; on macOS use
`--no-systemd` (no systemd) and `--skip-wg` unless you run as root.

Security properties and the inherent `curl | sh` caveats:
[docs/security.md](security.md#one-liner-bootstrap).

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
claymod-agent agent --config /etc/claymod/agent.yaml
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

### Path A — claymod-managed (default)

By default `claymod serve` **manages the interface itself**: at startup
it creates/refreshes the interface (needs `CAP_NET_ADMIN`, i.e. root),
assigns the overlay address, private key and listen port, and keeps
peers in sync via wgctrl as hosts enroll/revoke. Nothing to run by
hand. On the host side, `claymod-agent wg-setup` (run by the one-liner,
or by hand) does the same from the enrollment output
(`/etc/claymod/wg-setup.json`).

### Path B — operator-managed (opt out)

With `--manage-interface=false`, `serve` still writes
`claymod-data/<interface>.conf` (0600 — it contains the server's
private key), regenerated on every enroll/revoke and restart, but never
touches the interface. Apply it yourself:

```sh
sudo wg-quick up /path/to/claymod-data/claymod0.conf   # first time
sudo wg syncconf claymod0 <(wg-quick strip /path/to/claymod-data/claymod0.conf)
```

On the host, render the equivalent wg-quick config from
`wg-setup.json`, or run `claymod-agent wg-setup` — it only needs
`CAP_NET_ADMIN` for its one root step.

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
