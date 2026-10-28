# Security notes

Claymod's security posture in one line: *a small, pinned, mutual-TLS
core over a WireGuard overlay, with single-use enrollment and
inventory-driven revocation.* This document records the threat model,
the deliberate decisions behind it, and what claymod does **not** defend
against.

## Threat model

Defended:

- **Network attacker** on the path between control server and host —
  everything (bootstrap, protocol, agent traffic) is TLS 1.3 with mutual
  authentication, and the apply channel additionally rides inside a
  WireGuard tunnel.
- **Rogue host joining the overlay** — enrollment requires a one-time
  token bound to a hostname and a pinned server identity; the agent's
  certificate is issued only after the token is atomically consumed.
- **Stolen enrollment token** — tokens are single-use (atomic
  check-and-consume in the inventory transaction), TTL-bounded and
  hostname-bound. A mismatched or replayed attempt is refused and does
  not burn the token.
- **Compromised host (after revocation)** — `claymod host revoke`
  removes the WireGuard peer (cutting tunnel access), frees the overlay
  IP and records the certificate serial in the `revocations` table
  (CRL-lite): the certificate is rejected even if the file still exists.

Not defended (by design, documented boundaries):

- **Compromised control server** — it holds the CA and can issue
  identities. Protect `claymod-data/` (mode 0700, backups, disk
  encryption).
- **Compromised host before revocation** — an enrolled agent can run
  commands (`commands.Shell`) with its own privileges. That is the
  contract: playbooks are code. Revoke promptly.
- **Physical access / kernel compromise** on either end.

## Trust pinning (no TOFU)

The enrolling host pins the bootstrap server with **either** a CA bundle
(`--ca`) or the CA fingerprint (`--ca-pin`, printed by
`claymod serve` at startup) — or explicitly opts out of server
authentication with `--insecure-token-only` (the `/enroll.sh` one-liner
mode: the one-time token is the sole credential, bearer model). The
default is no trust-on-first-use: an enrollment without one of the
three modes is refused at the CLI.

The two pin modes differ in hostname handling, deliberately: `--ca`
uses stock TLS verification (the server name must match the
certificate's SANs — an IP-form `--server-name` becomes an IP SAN), while
`--ca-pin` **waives the hostname check** — the pinned CA is the
identity, so bare-IP enrollment works in both modes. Neither weakens
authentication: the chain must still verify against the pinned CA, and
appended certificates in a served bundle are never trusted (only the
pinned block becomes a trust root).

```sh
# hash the SERVED CA certificate — what --ca-pin compares against
# (the TLS leaf the handshake presents is not the pin):
curl -fsSLk https://control:8443/ca.pem \
  | openssl x509 -outform DER | shasum -a 256
```

## Key handling

| Key | Where generated | Where stored | Transmitted? |
|---|---|---|---|
| Internal CA | control (`serve`, first run) | `claymod-data/ca/` (0700 dir) | never |
| Bootstrap server cert | control | `claymod-data/` | over TLS (it is the TLS server cert) |
| Control mTLS client cert | control | `claymod-data/control*.pem` (key 0600) | never |
| **Agent WireGuard key** | **on the host** (`enroll`) | host `wg-keys.json` (0600) | **never** — only the public key |
| Agent mTLS cert/key | control (issued during enroll) | host `agent*.pem` (key 0600) | once, over TLS |

The agent's WireGuard private key is generated locally and never leaves
the host — enrollment transmits only its public key.

## Logging hygiene

Tokens, private keys and certificate contents are never logged. The
enrollment server logs hostname, remote address and outcome; `serve`
prints the CA fingerprint (it is public by design — it is what you
pin for `--ca-pin`/`--ca` enrollment). Client certificate material is written only to the
files named above.

## Protocol hardening

- TLS 1.3 minimum, both directions authenticated.
- Handshake under a 5s deadline (a stalled peer cannot hold a
  connection open).
- Frame size capped at 8 MiB (memory-bounded).
- Version handshake fails closed: mixed versions never reach `Apply`.
- Empty command ops are rejected (they once panicked — fixed with a
  regression test).
- Timeout precedence is explicit: per-op timeout > run timeout; a
  runaway command is killed at its deadline.

## Certificate lifetimes and revocation

Enrollment issues agent certificates with 365-day validity. Revocation
is CRL-lite (inventory `revocations` table, serial-based). Interim
guidance for strict environments: keep token TTLs short (minutes),
revoke on any host decommission, and treat `claymod-data/` backups as
key material. Planned hardening (Phase 9+): connection limits,
reconnection with bounded retries, graceful shutdown.

## One-liner bootstrap

`curl -fsSLk https://control:8443/enroll.sh | sudo sh` is a
convenience for bulk enrollment. The `-k` is required: the bootstrap
certificate comes from claymod's internal CA, so a fresh host cannot
verify it against any system trust store. The script takes no pin: the
**one-time enrollment token is the sole credential** (bearer model) —
proof that you know the control server. Its security model and honest
caveats:

**What it guarantees — against a passive observer only.** The token is
single-use, bound to the hostname you pass and short-lived (TTL set at
`claymod host token` time) — and it is **never embedded in a served
script**: it is passed at run time and burned on the hostname you name.
Enrollment itself is authenticated by the token. The served `.sha256`
digest is a corruption guard, nothing more: on this unauthenticated
channel a MITM controls the binary *and* its sidecar, so a swapped
binary passes it — the digest only binds the two files together. The
returned identity material (agent cert/key) is confidential against
someone merely watching the network (TLS still encrypts), not against a
channel-controlling MITM, who can terminate/relay TLS and read it.

**What it cannot guarantee — the honest `curl | sh` caveats.**
- *The pipeline hides curl's failure.* `curl | sh` reports `sh`'s exit
  code: if the fetch fails, `sh` runs on empty input and exits 0. Use
  the fetch-first form below, or at least watch the output.
- *The script runs with root and executes before you read it.* Whatever
  is piped runs; fetch the script first, read it, then run —
  `curl -fsSLk …/enroll.sh -o enroll.sh && less enroll.sh &&
  sudo sh enroll.sh --token … --hostname …` is the cautious form.
- *The transport is not authenticated in this flow.* A MITM who controls
  the channel can steal the token in flight (a bearer credential) and
  burn it on the same hostname before you do — and serve you a modified
  script, though enrollment itself would fail against the real server
  with a stolen-but-consumed token. When the network is untrusted, use
  the pinned manual flow instead: `claymod-agent enroll --ca-pin <CA
  fingerprint>` (chain-verified, hostname waived) or `--ca <bundle>`
  (stock TLS verification). `claymod serve` prints the CA fingerprint
  at startup.
- *The script mutates the host* (binary, systemd unit, WireGuard). Use
  `--no-systemd` and `--skip-wg` to stage only, or the manual enrollment
  path entirely.
- *Not a substitute for review in high-assurance environments* — there
  the manual path (`claymod-agent enroll` + your own config management)
  remains the recommended route.

## Agent binary distribution

The host agent is a **separate small static binary** (`claymod-agent`,
~7 MB) with a light dependency closure (no database, no PKL tooling, no
wgctrl). It can be served by the control server itself
(`GET /agent/{goos}/{goarch}` on the bootstrap channel) for air-gapped
hosts. The binary carries no secrets; integrity comes from SHA-256
digests — logged by `serve` at startup and served as a `.sha256` sidecar
for comparison on the host. A pinned channel (CA bundle / fingerprint,
manual flows) authenticates the download, and there the digest catches a
corrupted or swapped file; in the token-only one-liner the channel is
unauthenticated, so a MITM controls the binary and its sidecar alike —
the digest is only a corruption guard, not an authenticity check.

## Dependency footprint

Four Go dependencies (cobra, yaml.v3, modernc.org/sqlite — pure-Go
driver, no cgo — and wgctrl) plus the `pkl` CLI as a *server-side* tool.
Agents link only the Go dependencies. Fewer dependencies, smaller audit
surface.

## Simulation as regression suite

`simulation/run.sh` exercises the full lifecycle including the negative
cases in this document: anonymous client, rogue certificate, untrusted
server, single-use token. Run it after any change to enrollment, the CA
or the protocol.
