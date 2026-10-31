# claymod

A push-based IaC tool in the spirit of Puppet and Ansible: a control
server compiles PKL playbooks into primitive ops and pushes them to
enrolled hosts over a WireGuard overlay, secured end-to-end with mutual
TLS. Small dependency footprint, one static binary.

```
                 ┌──────────────┐   HTTPS bootstrap (token → identity)
   operator ───▶ │ control      │ ◀─────────────┐
                 │ (claymod     │               │
                 │  serve)      │   framed mTLS │
                 └──────┬───────┘   over the    │
                        │           WireGuard  │
                 WireGuard overlay   overlay    │
                        │               │       │
                 ┌──────┴───────┐       │  ┌────┴──────┐
                 │ agent (web01)│◀──────┘  │ agent     │
                 └──────────────┘          │ (db01)…   │
                                           └───────────┘
```

- **Playbooks in PKL** (`pkl/claymod/` schema): declarative resources
  (`std.files`, `std.commands`, `std.service`, `std.sysctl`, `std.cron`,
  `std.assert`, `std.users`)
  with per-host vars and
  dependencies; compiled server-side to primitive ops — agents never see
  PKL.
- **Enrollment**: one-time tokens over an HTTPS bootstrap endpoint; the
  host generates its own WireGuard key pair (private key never leaves it)
  and receives its mTLS identity. Revocation is CRL-lite.
- **Transport**: framed JSON over mutual TLS 1.3, tunneled through
  WireGuard. Nothing else is exposed.
- **Dependencies**: cobra, yaml.v3, modernc.org/sqlite, wgctrl, plus the
  `pkl` CLI on the control server (server-side only).

## Install

Two binaries, one per side of the wire:

| Binary | Role | Size | Links |
|---|---|---|---|
| `claymod` | control server + full CLI | ~14 MB | sqlite, pkl, wgctrl |
| `claymod-agent` | host agent (static) | ~7 MB | stdlib + yaml only |

### Dev workstation (lint playbooks, no control server)

```sh
scripts/bootstrap-claymod.sh
```

Installs the `claymod` CLI (+ `pkl` for `playbook validate|plan`) on
Linux or macOS, checksum-verified, **user-local by default**:
`~/.local/bin` on both (no sudo; the script prints the PATH line to add
when the directory isn't on `PATH`). Run as root and it defaults to
`/usr/local/bin` instead — the server setup flow; `PREFIX` overrides
either way. It never sets up or starts a control server — that's a
separate, deliberate step. The PKL std schema itself needs no install:
it is embedded in the binary and materialized into the user cache on
first run. Pin with `CLAYMOD_VERSION=vX.Y.Z`, mirror air-gapped with
`CLAYMOD_RELEASES_BASE` + `CLAYMOD_SHA256` (out-of-band digest),
`SKIP_PKL=1` / `FORCE=1` as needed.

### Control server / hosts

Download from the [latest release](https://github.com/Claymod/Claymod/releases/latest)
and verify against `SHA256SUMS` (linux **and darwin** assets):

```sh
BASE=https://github.com/Claymod/Claymod/releases/latest/download
os=$(uname -s | tr A-Z a-z)   # linux or darwin
# uname prints arm64 on Apple Silicon; assets are named aarch64.
arch=$(uname -m | sed -e s/x86_64/amd64/ -e s/arm64/aarch64/)
curl -fsSL -O $BASE/claymod-$os-$arch -O $BASE/SHA256SUMS
# macOS ships shasum, not sha256sum.
grep "  claymod-$os-$arch\$" SHA256SUMS | (sha256sum -c - 2>/dev/null || shasum -a 256 -c -)
```

Building from source (developers):

```sh
make build          # bin/claymod (control) + bin/claymod-agent (host)
make agents         # cross-compiled agents in bin/agents/ + sha256 sums
go test ./...       # run the test suite (pkl-dependent tests auto-skip
                    # without the pkl CLI; run scripts/bootstrap-pkl.sh
                    # first for full coverage)
```

The control server needs the `pkl` CLI on its PATH
(`scripts/bootstrap-pkl.sh` installs it locally). Hosts need only the
**agent** binary — a small static build (`CGO_ENABLED=0`) that links no
database, no PKL tooling and no wgctrl.

### Air-gapped hosts

`claymod serve` can offer agent binaries for download over its pinned
HTTPS bootstrap endpoint:

```sh
make agents                      # bin/agents/claymod-agent-<os>-<arch>
claymod serve --agent-bin-dir bin/agents ...
```

On the host, with only `curl` and the pinned CA bundle (or the server's
certificate fingerprint) in hand:

```sh
arch=$(uname -m | sed s/x86_64/amd64/)   # aarch64 stays aarch64
curl --cacert ca.pem -o claymod-agent \
  https://control:8443/agent/linux/$arch
curl --cacert ca.pem https://control:8443/agent/linux/$arch.sha256
shasum -a 256 claymod-agent        # compare with the digest above
chmod +x claymod-agent
./claymod-agent enroll --server https://control:8443 --token ... --hostname ...
```

The digest is also printed by `claymod serve` at startup for
out-of-band verification. Nothing else needs to reach the host: the
entire bootstrap path is the one pinned TLS channel.

### One-liner enroll (curl | sh)

`claymod serve` also serves a bootstrap script that does the whole host
setup — download the right agent, verify it, enroll, bring up
WireGuard and install a systemd unit:

```sh
# -k is required: the bootstrap certificate comes from claymod's
# internal CA. The one-time TOKEN is the credential in this flow.
curl -fsSLk https://control:8443/enroll.sh \
  | sudo sh -s -- --token <TOKEN> --hostname web01
```

A bare-IP URL (`https://51.38.34.49:8443`) works — no DNS name or hosts
entry needed. The one-time token is the credential: single-use,
bound to the hostname, short TTL, never embedded in a served script —
whoever holds it decides which host name it is burned on. The transport
in this flow is not pinned; when that matters, use the manual
`claymod-agent enroll` path with `--ca`/`--ca-pin` (pinned, chain-
verified enrollment). Caveats of `curl | sh` (including the pipeline's
silent-failure mode) are spelled out in
[docs/security.md](docs/security.md#one-liner-bootstrap); the manual
enrollment path below is always available.

## Quickstart (loopback, ~2 minutes)

Everything below runs on one machine against loopback — no root, no
WireGuard interface — and exercises the real enrollment flow with the
**agent binary** (the same one served to air-gapped hosts). It is
copy-paste verbatim: every command below has been run exactly as
printed.

```sh
# 1. Write a demo playbook (3 resources under /tmp, no root needed).
mkdir -p demo/files
cat > demo/files/motd.txt <<'EOF'
Managed by claymod — hello from the demo.
EOF
cat > demo/files/conf.tmpl <<'EOF'
host = {{.Host}}
greeting = {{.Vars.greeting}}
port = {{.Vars.port}}
EOF
cat > demo/playbook.pkl <<'EOF'
amends "modulepath:/claymod/base.pkl"
import "modulepath:/claymod/std/files.pkl"
import "modulepath:/claymod/std/commands.pkl"

hosts { "web01" }
vars  { ["greeting"] = "hello" }

resources {
  new files.Copy {
    name = "motd"
    source = "files/motd.txt"
    dest = "/tmp/claymod-demo-motd.txt"
    mode = "0644"
  }
  new files.Template {
    name = "conf"
    source = "files/conf.tmpl"
    dest = "/tmp/claymod-demo-conf.txt"
    vars { ["port"] = "8080" }
  }
  new commands.Shell {
    name = "marker"
    command = "date > /tmp/claymod-demo-marker.txt"
    creates = "/tmp/claymod-demo-marker.txt"
    dependsOn { "conf" }
  }
}
EOF

# 2. Start the control server (creates the CA + identities in ./demo).
#    Loopback demo: the overlay network is 127.0.0.0/8 so the allocated
#    address is 127.0.0.1 — where the agent actually listens.
#    Prefer the config file (examples/server.yaml): flags stay available
#    as explicit overrides, e.g. --data-dir demo --wg-backend fake.
bin/claymod serve --data-dir demo --agent-network 127.0.0.0/8 \
  --bootstrap-listen 127.0.0.1:8443 \
  --server-name localhost --wg-backend fake

# 3. In a second shell: issue a one-time token for host "web01".
bin/claymod host token web01 --data-dir demo --token-file demo/token

# 4. Enroll the host with the agent binary (pinned to the CA the server
#    just created). In an air-gapped setup this binary comes from
#    https://localhost:8443/agent/<os>/<arch> instead of ./bin.
bin/claymod-agent enroll --server https://localhost:8443 \
  --token "$(cat demo/token)" --hostname web01 \
  --ca demo/ca/ca.pem --out-dir demo/host --listen 127.0.0.1:2323 \
  --skip-wg-config

# 5. Start the agent on the enrolled identity.
bin/claymod-agent agent --config demo/host/agent.yaml
```

In a third shell, apply the playbook (the agent listens on
`127.0.0.1:2323`; the demo inventory records that address for web01):

```sh
# 6. Validate and plan, then apply.
bin/claymod playbook validate demo/playbook.pkl
bin/claymod playbook plan demo/playbook.pkl
bin/claymod playbook apply demo/playbook.pkl \
  --data-dir demo --agent-network 127.0.0.0/8 --agent-port 2323
```

The first apply reports `3 ok, 3 changed`; running it again reports
`3 ok, 0 changed` — applies are idempotent. More:

```sh
bin/claymod host facts web01 --data-dir demo --agent-port 2323   # live facts
bin/claymod exec --host web01 --data-dir demo --agent-port 2323 -- uname -a
bin/claymod exec --host web01 --data-dir demo --agent-port 2323 --shell 'echo hi from $(hostname)'
bin/claymod playbook apply demo/playbook.pkl \
  --data-dir demo --agent-network 127.0.0.0/8 --agent-port 2323 --check
```

For a real deployment (WireGuard interface, host tokens over the
network, revocation) see [docs/enrollment.md](docs/enrollment.md).

## Control server configuration

`claymod serve` is configured through a YAML file — the primary source
of parameters, with every CLI flag available as an explicit override:

```sh
cp examples/server.yaml /etc/claymod/server.yaml   # edit to taste
claymod serve --config /etc/claymod/server.yaml
claymod serve --config /etc/claymod/server.yaml --wg-port 51825  # example: one-off override*
```

*flags override only when explicitly given; `host token|list|revoke`
accept the same `--config`.

```yaml
# /etc/claymod/server.yaml (full annotated example: examples/server.yaml)
bootstrap_listen: ":8443"     # HTTPS enrollment endpoint
server_name: claymod          # cert CN/SAN, pinned by agents
data_dir: /var/lib/claymod    # CA, identities, inventory
agent_network: 10.42.0.0/24   # WireGuard overlay CIDR
wg_endpoint: 203.0.113.7:51821
wg_port: 51821                # never the default 51820
wg_backend: wgctrl            # or fake for demos/CI
manage_interface: true
```

## Playbooks

```pkl
amends "modulepath:/claymod/base.pkl"
import "modulepath:/claymod/std/files.pkl"
import "modulepath:/claymod/std/service.pkl"

hosts { "web01" }
vars  { ["domain"] = "example.internal" }

resources {
  new files.Template {
    name = "nginx.conf"
    source = "templates/nginx.conf.tmpl"
    dest = "/etc/nginx/nginx.conf"
  }
  new service.Unit {
    name = "nginx"
    unit = "nginx"
    state = "started"
    enabled = true
    dependsOn { "nginx.conf" }
  }
}
```

The std schema is embedded in the binary: `playbook validate|plan|apply`
work from any working directory (`CLAYMOD_SCHEMA_DIR` pins an on-disk
copy; `--module-path`/`CLAYMOD_MODULE_PATH` add extra lookup dirs).
Shared PKL libraries come from git repos pinned in
`claymod.project.yaml` (managed with `claymod lib list|sync`; see
[docs/playbooks.md](docs/playbooks.md#libraries)). Which libraries
exist, who maintains them and the trust tiers:
[docs/libraries.md](docs/libraries.md).

Start a new playbook from a scaffold with `claymod playbook init <dir>`.

Full authoring guide: [docs/playbooks.md](docs/playbooks.md). Examples
live in [examples/](examples/).

## Verification

The [simulation](simulation/README.md) runs the complete lifecycle in
Docker (or loopback with `--local`): token → HTTPS bootstrap → enrollment
→ agent → TLS probe suite, including negative checks (rogue client
certificate, missing client certificate, untrusted server).

## Documentation

| Document | Contents |
|---|---|
| [docs/architecture.md](docs/architecture.md) | components, data flow, trust model |
| [docs/protocol.md](docs/protocol.md) | framed mTLS protocol spec |
| [docs/playbooks.md](docs/playbooks.md) | playbook authoring guide |
| [docs/enrollment.md](docs/enrollment.md) | enrollment + revocation runbook |
| [docs/security.md](docs/security.md) | threat model and security notes |
| [simulation/README.md](simulation/README.md) | TLS/enrollment verification |

## Status

Phases 0–9 of the plan are implemented and tested (`go test -race ./...`
clean). Phase 9 hardening: CRL-lite enforcement on the dial path, fuzzed
wire codec, tokens hashed at rest, agent session caps + panic isolation,
bounded dial retries, provable graceful shutdown, static systemd unit +
release target + CI (see the hardening checklist in
[docs/security.md](docs/security.md#hardening-checklist)).
