# Claymod enrollment simulation

Verifies the **implemented enrollment flow** end-to-end: one-time token →
HTTPS bootstrap → identity issued by the control CA → agent on the
enrolled identity → TLS probe suite against it. Nothing is
pre-generated: the WireGuard key pair is created on the host by
`claymod enroll`, and the mTLS identity comes from the real
`claymod serve` bootstrap endpoint.

## Topology

```
control   claymod serve (HTTPS :8443, CA + inventory, fake WG backend)
   │      claymod host token → /shared/token
   │
agent     waits for token → claymod enroll (pinned CA) → claymod agent
   │      (asserts the token is single-use)
   │
probes    TLS suite against the ENROLLED identity
```

All three are the same image (`simulation/Dockerfile`).

## What the probes assert

| # | Probe | Expected |
|---|---|---|
| 1 | Control identity connects to the enrolled agent | connect + Ping + Facts + Apply smoke (2nd pass = no-op) |
| 2 | No client certificate (anonymous) | rejected (mTLS mandatory) |
| 3 | Rogue self-signed client certificate | rejected |
| 4 | Probe verifies agent against a wrong CA bundle | rejected |

Plus, in `enroll-entry.sh`: **the enrollment token is single-use** (a
second `claymod enroll` with the same token must fail).

Any probe behaving unexpectedly fails the whole run.

## Run it

Docker mode (default):

```sh
simulation/run.sh
```

Local loopback mode (no Docker, same flow and probes):

```sh
simulation/run.sh --local
```

## Files

- `Dockerfile` — build stage (Go 1.26) + alpine runtime
- `docker-compose.yml` — control → agent → probes services
- `scripts/control-entry.sh` — serve + token issuance + /shared publish
- `scripts/enroll-entry.sh` — enroll (pinned) + single-use assertion + agent
- `scripts/probes.sh` — the four TLS checks
- `run.sh` — orchestrator (docker + local modes)

Artifacts land in the `shared` volume (docker mode) or `.sim-local/`
(local mode); both are disposable and git-ignored.
