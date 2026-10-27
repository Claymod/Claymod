# Protocol specification

The claymod protocol carries control-server → agent traffic: primitive
ops pushed over a framed JSON channel on mutual TLS 1.3, tunneled
through the WireGuard overlay. This document is the wire contract.

## Transport

- **TLS 1.3** (minimum) with mutual certificate authentication. The
  agent is the TLS *server* (it listens on the overlay); the control
  server is the TLS client. Both certificates are issued by the internal
  CA (see [enrollment](enrollment.md)).
- **Framing**: every message is a 4-byte big-endian length prefix
  followed by a JSON payload. The maximum frame payload is **8 MiB**;
  larger frames are rejected. Format details: `internal/proto/frame.go`.
- **One connection, one session**: `proto.Dial`/`proto.Listen` wrap the
  TLS handshake plus a version exchange.

## Handshake

Immediately after TLS, both sides send a JSON `Handshake` frame (raw
frame I/O, under a 5-second deadline so a stalled peer cannot hold the
handshake open):

```json
{ "role": "control", "version": 1 }
{ "role": "agent",   "version": 1 }
```

- `role` — `"control"` or `"agent"`. A role mismatch closes the
  connection.
- `version` — protocol version. A mismatch closes the connection (the
  agent never parses unknown versions).

## Messages

Requests are `Request` frames, responses are `Response` frames. A
response carries the request `id` (string, chosen by the requester) and
either a `result` or an `error`. There is no pipelining requirement:
clients may send one request and read until its final response.

### Request

```json
{ "id": "apply-1", "method": "Apply", "params": { ... } }
```

### Response

```json
{ "id": "apply-1", "result": { ... } }
```
```json
{ "id": "apply-1", "error": { "code": "bad_request", "message": "..." } }
```

Error codes: `bad_request`, `not_found`, `internal`, `unsupported`.

### Methods

| Method | Params | Result | Notes |
|---|---|---|---|
| `Ping` | — | `{agent, version}` | liveness |
| `Facts` | — | `{hostname, os, arch, kernel, extra}` | host self-description |
| `Apply` | `{ops, check, timeout_ms}` | streamed per-op results + final summary | see below |
| `Exec` | `{argv\|shell, cwd, env, timeout_ms}` | `{exit_code, stdout, stderr}` | ad-hoc command |
| `GetFile` | `{path}` | `{path, content, mode}` | read a file |
| `PutFile` | `{path, content, mode}` | — | write a file |

## Apply

`Apply` streams: the agent sends one `Response` per op as it completes,
then a final summary response (`"summary": true`). Clients read until
the summary frame.

### Primitive ops

```json
{ "op_type": "file",
  "file": { "path": "/etc/motd", "content": "...", "mode": "0644",
            "owner": "", "group": "", "ensure": "file",
            "backup": false } }

{ "op_type": "command",
  "command": { "shell": "...", "argv": [], "cwd": "", "env": {},
               "only_if": "", "unless_if": "", "creates": "",
               "removes": "", "timeout_ms": 0 } }

{ "op_type": "service",
  "service": { "unit": "nginx", "state": "started", "enabled": true } }
```

`ensure` is `"file"` (default), `"directory"` or `"absent"`. `state` is
`"started"`, `"stopped"`, `"restarted"` or `"reloaded"`. `enabled` is
`true`, `false` or omitted (leave unchanged). Exactly one of `shell` /
`argv` for a command. Empty commands are rejected (they used to panic —
now a clean failure).

### Per-op result

```json
{ "index": 0, "op_type": "file", "changed": true, "failed": false,
  "message": "wrote /etc/motd", "stdout": "", "stderr": "" }
```

### Summary

```json
{ "summary": true, "ok": 3, "changes": 3, "failures": 0 }
```

`check` mode (`"check": true`) computes and reports `changed` but does
not mutate the host.

## Timeouts

- Handshake deadline: 5s.
- Frame read/write: 60s default.
- Per-op command timeout: `timeout_ms` on the op (takes precedence over
  the run-level timeout). `Exec`'s `timeout_ms` likewise.

## Versioning

`version` is currently `1` (`proto.Version`). Any wire change bumps it;
the handshake rejects mismatches, so mixed-version pairs fail closed at
connection time, never mid-apply.

## Reference implementation

`internal/proto` (codec + conn), `internal/agent` (server side),
`internal/runner` (client side) are the normative implementation; this
document describes their contract. Simulation probes
(`simulation/scripts/probes.sh`) verify the TLS layer of this protocol
end-to-end.
