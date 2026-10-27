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
(`--ca`) or a SHA-256 certificate fingerprint (`--ca-pin`, printed by
`claymod serve` at startup). There is no trust-on-first-use mode: an
unpinned enrollment is refused at the CLI.

```sh
openssl s_client -connect control:8443 -servername control </dev/null 2>/dev/null \
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
prints the bootstrap certificate fingerprint (it is public by design —
it is what you pin). Client certificate material is written only to the
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

## Agent binary distribution

The host agent is a **separate small static binary** (`claymod-agent`,
~7 MB) with a light dependency closure (no database, no PKL tooling, no
wgctrl). It can be served by the control server itself
(`GET /agent/{goos}/{goarch}` on the pinned bootstrap channel) for
air-gapped hosts. The binary carries no secrets; integrity comes from
SHA-256 digests — logged by `serve` at startup and served as a `.sha256`
sidecar for comparison on the host. Pinning the channel (CA bundle /
fingerprint) is what authenticates the download; the digest guards
against a corrupted or swapped file.

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
