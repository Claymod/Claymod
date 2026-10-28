# Architecture

Claymod is a push-based IaC tool: a **control server** compiles PKL
playbooks into primitive ops and pushes them to **agents** over a
WireGuard overlay secured with mutual TLS. This document describes the
components, data flow and trust model.

## Binaries

The tool ships as **two binaries**, one per side of the wire:

- **`claymod`** (control server + full CLI) — links everything: sqlite
  inventory, the PKL pipeline, the CA and wgctrl. Runs on the operator's
  side; needs the `pkl` CLI on PATH.
- **`claymod-agent`** (host) — a small static binary linking only the
  light closure: `agent` (apply engine), `proto` (framed mTLS), the
  `enroll` *client* contract, `wgmgr` (keygen + interface bring-up) and
  `config`. No database, no PKL, no wgctrl. ~7 MB vs ~14 MB.

The split is enforced by package layout: heavy control-side code lives
in `internal/inventory`, `internal/playbook`, `internal/modules`,
`internal/enrollserver` and `internal/wgmanager`; the shared light code
is `internal/agent`, `internal/proto`, `internal/enroll`,
`internal/wgmgr`, `internal/agentcli`. `go list -deps ./cmd/claymod-agent`
contains no inventory/playbook/wgctrl packages.

Air-gapped hosts fetch their agent from the control server itself:
`GET /agent/{goos}/{goarch}` (+ `.sha256`) on the pinned HTTPS bootstrap
endpoint serves binaries placed in `--agent-bin-dir`. Integrity is
by checksum — the digest is logged at startup and served alongside the
binary for comparison on the host.

## Components

| Component | Package | Role |
|---|---|---|
| CLI | `internal/cli` | `claymod` command tree (cobra) |
| Control server | `internal/cli/serve.go`, `internal/state` | state, inventory, enrollment, orchestration |
| PKL pipeline | `internal/pkl`, `internal/playbook` | eval → parse → validate → plan |
| Modules | `internal/modules` | resource compilers → primitive ops |
| Runner | `internal/runner` | dial agents, stream ops, collect results |
| Agent | `internal/agent` | apply File/Command/Service ops on the host |
| Protocol | `internal/proto` | framed JSON over mutual TLS 1.3 |
| Enrollment | `internal/enroll`, `internal/inventory` | one-time tokens, identity issuance, revocation |
| WireGuard | `internal/wgmgr` | key generation, peer management |
| CA | `internal/ca` | internal root of trust, certificate issuance |

## Data flow: an apply run

```
playbook.pkl ──pkl eval──▶ JSON document
                             │
              parse + validate (names, deps, cycles)
                             │
              topological plan (per host)
                             │
              compile (per host: templates rendered with host vars)
                             │
                    primitive ops (File / Command / Service)
                             │
        runner: one mTLS connection per host, ops streamed in plan order
                             │
                    agent: apply, stream per-op results
                             │
                    summary report (changed / failed / ok)
```

Key design decisions:

- **Agents never see PKL.** The `pkl` CLI is a *server-side* dependency;
  playbooks compile to three primitive op types (File, Command, Service)
  on the control server. New resource types need a compiler in
  `internal/modules` and no agent change.
- **Rendering is server-side.** Templates (`text/template`, sprig-free
  func map) are rendered per host before ops are sent; the agent writes
  bytes, it never interprets templates.
- **Applies are idempotent** (verified in tests and the simulation): the
  agent reports `changed=false` when a resource already matches.

## Trust model

Three identity relationships, one CA:

1. **Bootstrap (HTTPS)**: the control server presents a certificate
   issued by the internal CA; the enrolling host pins it (`--ca` bundle
   or `--ca-pin` fingerprint) — no TOFU — or, in the `/enroll.sh`
   one-liner, skips server authentication entirely: there the one-time
   token is the sole credential (bearer model).
2. **Framed protocol (mTLS)**: the control server dials agents. Both
   sides present certificates from the internal CA; agents are the TLS
   *servers* on the overlay (they listen), the control side is the
   client. Agent certificates carry the hostname as a DNS SAN (the
   runner dials with `ServerName=hostname`).
3. **WireGuard overlay**: peers are configured by `wgmgr` on the control
   side as hosts enroll; each host generates its own WireGuard key pair
   locally — the private key is never transmitted.

Revocation is CRL-lite: `claymod host revoke` removes the WireGuard
peer, frees the overlay IP and records the certificate serial in the
inventory's `revocations` table.

## State directory

`claymod serve` owns a data directory (`claymod-data/` by default):

```
ca/ca.pem, ca/ca-key.pem   internal root CA
server.pem, server-key.pem  bootstrap HTTPS identity
control.pem, control-key.pem  control's mTLS client identity (runner/exec)
wg-keys.json               control's WireGuard key pair
inventory.db               sqlite: hosts, tokens, IP allocations, revocations
```

Everything is created on first `serve` and reloaded on restart. Client
commands (`exec`, `host facts`, `playbook apply`) *read* this state and
fail loudly if it is missing — they never mint a CA.

## Inventory

SQLite (`internal/inventory`), single-writer with WAL:

- `hosts` — hostname (PK), WG IP (unique), WireGuard public key, issued
  certificate, cached facts, last seen.
- `tokens` — one-time enrollment tokens: bound to a hostname, TTL,
  atomic consume (single-use, enforced in a transaction).
- `ip_allocations` — durable overlay IP assignments (restart-safe IPAM;
  freed IPs are reusable).
- `revocations` — CRL-lite: certificate serials that are no longer
  trusted.

## Failure model

- Per-host isolation: one host's failure never affects another's apply.
- Failure policy: `--max-fail` = fail-fast (0), tolerate N, or run all
  (-1); skipped hosts are reported explicitly.
- Per-op results stream back as they complete; a transport error marks
  the host failed with the reason.
- Check mode (`--check`) computes would-change without mutating.

## Extension points

- **Modules**: `modules.Register(type, compiler)` — a compiler turns one
  resource into primitive ops (e.g. `std.commands.Script` compiles to a
  File op + a Command op). Future: pkg, cron, users.
- **WireGuard backends**: `wgmgr.Backend` interface — `wgctrl` (real,
  needs root) or `fake` (testing/simulation).
- **Template funcs**: minimal, sprig-free set in
  `internal/playbook/render.go` (file, trimSpace, quote, default, lower,
  upper).
