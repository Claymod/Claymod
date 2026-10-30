# Homelab deployment guide

Step-by-step runbook for a **first real environment**: claymod control
server on a VPS, a fresh Debian VM enrolled with the one-liner, and a
playbook that installs nginx. This is the preferred path only —
everything is configured in `server.yaml`, WireGuard is managed by
claymod, and hosts enroll with the served bootstrap script.
Alternatives (manual pinned enrollment, air-gapped downloads,
operator-managed WireGuard) live in
[docs/enrollment.md](enrollment.md); security trade-offs in
[docs/security.md](security.md).

You run every command yourself, over SSH, as **root** on both machines
(WireGuard and systemd need it). The agent executes commands with its
own privileges — by design, see [docs/security.md](security.md).

## Topology

```
        workstation (this Mac)
          │  ssh (setup only)
          ├──────────────────────────────┐
          ▼                              ▼
   ┌─────────────┐   UDP 51821    ┌──────────────┐
   │ VPS         │◄──────────────►│ Debian VM    │
   │ control     │  WireGuard     │ web01        │
   │ TCP 8443    │   overlay      │ agent :2323  │
   │ bootstrap   │  10.42.0.0/24  │ 10.42.0.2    │
   └─────────────┘                └──────────────┘
```

| Thing | Value here | server.yaml key |
|---|---|---|
| Overlay network | `10.42.0.0/24` (server `.1`, VM `.2`) | `agent_network` |
| Control VPS | `VPS_IP` (public address) | `wg_endpoint` |
| Bootstrap HTTPS | TCP `8443` | `bootstrap_listen` |
| WireGuard | UDP `51821`, interface `claymod0` | `wg_interface`, `wg_endpoint`, `wg_port` |
| Agent port | TCP `2323` (tunnel only) | `agent_port` |

Replace `VPS_IP` throughout. Firewall on the VPS: **TCP 8443**
(enrollment) and **UDP 51821** (the overlay) — everything else flows
inside the tunnel. Port 51821 is deliberate: never WireGuard's
standard 51820, so claymod cannot collide with your own tunnels.

## Phase 0 — Get the binaries

Both binaries are published on every release as static linux builds
(plus `SHA256SUMS`), at
`https://github.com/Claymod/Claymod/releases/latest/download/`:

| Binary | Runs on | Asset | Notes |
|---|---|---|---|
| `claymod` | VPS | `claymod-linux-<arch>` | control server + CLI; needs the `pkl` CLI |
| `claymod-agent` | managed hosts | `claymod-agent-linux-<arch>` | static, no dependencies |

`uname -m`: `x86_64` → amd64, `aarch64` → arm64 (Debian on UTM/Apple
Silicon is arm64). No Go toolchain needed anywhere; from a checkout,
`make build` / `make agents` produce the same binaries.

## Phase 1 — Control server on the VPS

### 1.1 Install

```sh
ssh root@VPS_IP
apt update && apt install -y wireguard-tools rsync

# control binary, checksum-verified
BASE=https://github.com/Claymod/Claymod/releases/latest/download
curl -fsSL -O $BASE/claymod-linux-<arch> -O $BASE/SHA256SUMS
grep "claymod-linux-<arch>$" SHA256SUMS | sha256sum -c -
install -m 0755 claymod-linux-<arch> /usr/local/bin/claymod

# agent binaries the one-liner downloads from the server
curl -fsSL -O $BASE/claymod-agent-linux-<arch>
grep "claymod-agent-linux-<arch>$" SHA256SUMS | sha256sum -c -
mkdir -p /root/claymod/agents
install -m 0755 claymod-agent-linux-<arch> /root/claymod/agents/
```

Keep the release file names: `GET /agent/<goos>/<goarch>` serves
`claymod-agent-<goos>-<goarch>` out of `agent_bin_dir` — a file named
just `claymod-agent` is invisible to it
([docs/security.md](security.md#agent-binary-distribution)).
`wireguard-tools` is for `wg` diagnostics only; `serve` manages the
interface itself.

The PKL schema and the `pkl` CLI (server-side only — agents never see
PKL):

```sh
# from your workstation
ssh root@VPS_IP 'mkdir -p /root/claymod/pkl'
rsync -av pkl/ root@VPS_IP:/root/claymod/pkl/
rsync -av scripts/bootstrap-pkl.sh root@VPS_IP:/root/claymod/

# on the VPS
/root/claymod/scripts/bootstrap-pkl.sh    # installs to /usr/local/bin
```

### 1.2 Configure and start

All parameters live in one file:

```yaml
# /etc/claymod/server.yaml
bootstrap_listen: ":8443"
server_name: vps
data_dir: /root/claymod-data
agent_bin_dir: /root/claymod/agents
agent_network: 10.42.0.0/24
agent_port: 2323
wg_interface: claymod0
wg_endpoint: VPS_IP:51821
wg_port: 51821
wg_backend: wgctrl
manage_interface: true
log_level: info
```

Absolute paths on purpose: `data_dir` is not `~`-expanded and a
systemd unit has no shell. Full annotated file:
[examples/server.yaml](../examples/server.yaml).

```sh
claymod serve --config /etc/claymod/server.yaml
```

The first run creates all state under `data_dir` (CA, identities,
inventory, WireGuard keys), prints the **CA fingerprint** (the pin for
the pinned flows in [docs/enrollment.md](enrollment.md)) and the
ready-made one-liner, and brings up `claymod0` itself — peers stay in
sync with the inventory on every start and on enroll/revoke. Verify
with `wg show` (listening on **51821**). The startup log must say
`agent binaries offered for download`; anything else and the
one-liner's agent download 404s (Troubleshooting).

### 1.3 Keep it running

`/etc/systemd/system/claymod-serve.service`:

```ini
[Unit]
Description=claymod control server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/claymod serve --config /etc/claymod/server.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```sh
systemctl daemon-reload
systemctl enable --now claymod-serve
```

Reboots need nothing: on every start `serve` recreates the interface
and re-installs all peers from the inventory (the source of truth).

## Phase 2 — Enroll the Debian VM

### 2.1 Prepare and issue a token

```sh
ssh <vm>
apt update && apt install -y wireguard-tools curl
```

The one-liner's preflight checks for `wg` **before** the token is
consumed: missing tooling aborts with the token still valid (the
script never installs packages in your place). No DNS needed — the
flow works against a bare IP.

On the VPS, issue the token:

```sh
claymod host token web01 --config /etc/claymod/server.yaml \
  --token-file /root/token-web01
```

Single-use, bound to `web01`, valid 15 minutes (`--ttl` to change).

### 2.2 Enroll — the one-liner (on the VM)

`GET /enroll.sh` does the whole host setup: download the right agent,
verify it against its served digest, enroll (the token is the
credential), bring up WireGuard and install `claymod-agent.service`:

```sh
# -k is required: the bootstrap certificate comes from claymod's
# internal CA. The one-time token IS the credential in this flow.
curl -fsSLk https://VPS_IP:8443/enroll.sh \
  | sudo sh -s -- --token <TOKEN> --hostname web01
```

`serve` prints this command at startup. That is everything: agent at
`/usr/local/bin/claymod-agent`, identity in `/etc/claymod/`, tunnel up
on `claymod0`, service enabled and started. `curl | sh` reports `sh`'s
exit code — watch for the `==` progress lines; caveats and the
fetch-first form: [docs/security.md](security.md#one-liner-bootstrap).
Options (`--skip-wg`, `--no-systemd`, …) and the manual pinned flow:
[docs/enrollment.md](enrollment.md).

**Reboot note:** the unit starts the agent only. After a VM reboot the
tunnel is gone — re-create it first with
`sudo claymod-agent wg-setup --out-dir /etc/claymod`, or add a wg-quick
unit (see [docs/enrollment.md](enrollment.md) §5).

### 2.3 Smoke test (on the VPS)

```sh
claymod host facts web01 --data-dir /root/claymod-data
claymod exec --host web01 --data-dir /root/claymod-data -- uname -a
```

`playbook apply`, `exec` and `host facts` locate the state with
`--data-dir` (the same value as `data_dir` above). Both commands dial
`10.42.0.2:2323` through the tunnel with mutual TLS. If they hang:
check `wg show` handshakes on both sides.

## Phase 3 — Playbook: install nginx

### 3.1 Files (on the VPS, in `/root/claymod/homelab/`)

`files/motd`:

```
Managed by claymod.
```

`files/index.html.tmpl`:

```
<html><body><h1>{{.Vars.greeting}} from {{.Host}}</h1></body></html>
```

`files.Copy` ships bytes verbatim; Go templates render only in
`files.Template` ([docs/playbooks.md](playbooks.md#templates)).

`playbook.pkl`:

```pkl
amends "modulepath:/claymod/base.pkl"
import "modulepath:/claymod/std/files.pkl"
import "modulepath:/claymod/std/commands.pkl"
import "modulepath:/claymod/std/service.pkl"

hosts { "web01" }
vars  { ["greeting"] = "hello" }

resources {
  new commands.Shell {
    name = "nginx-install"
    command = "DEBIAN_FRONTEND=noninteractive apt-get install -y nginx"
    unlessIf = "dpkg -s nginx"
  }
  new files.Directory {
    name = "webroot"
    path = "/var/www/html"
    mode = "0755"
  }
  new files.Copy {
    name = "motd"
    source = "files/motd"
    dest = "/etc/motd"
    mode = "0644"
  }
  new files.Template {
    name = "index"
    source = "files/index.html.tmpl"
    dest = "/var/www/html/index.html"
    mode = "0644"
    dependsOn { "webroot" }
  }
  new service.Unit {
    name = "nginx"
    unit = "nginx"
    state = "started"
    enabled = true
    dependsOn { "nginx-install" "index" }
  }
}
```

### 3.2 Validate, plan, apply

```sh
cd /root/claymod
claymod playbook validate homelab/playbook.pkl
claymod playbook plan homelab/playbook.pkl
claymod playbook apply homelab/playbook.pkl \
  --data-dir /root/claymod-data --check          # dry run
claymod playbook apply homelab/playbook.pkl \
  --data-dir /root/claymod-data                  # real run → "ok, N changed"
claymod playbook apply homelab/playbook.pkl \
  --data-dir /root/claymod-data                  # again → "ok, 0 changed"
```

The second real apply reporting **0 changed** is the idempotence proof.

### 3.3 Verify on the VM

```sh
curl -s localhost            # → "hello from web01"
systemctl is-enabled nginx   # → enabled
cat /etc/motd                # → "Managed by claymod."
```

## Proof checklist

- [ ] wrong or expired token → refused before anything is installed
- [ ] token single-use: re-running with the same token fails at enroll
- [ ] `wg show` handshakes on both sides; only UDP 51821 + TCP 8443
      touch the public interface
- [ ] apply #1 → `N changed`; apply #2 → `0 changed`
- [ ] `host facts web01` returns live facts; `exec -- uname -a` works
- [ ] optional: `claymod host revoke web01` → peer removed; re-enroll
      with a fresh token to restore

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| one-liner exits 0 but nothing happened | `curl \| sh` reports sh's exit code — a failed fetch looks like success; watch for the `==` progress lines |
| one-liner: `curl: (22) … 404` on the agent download | serve isn't serving binaries — read the startup log: `directory does not exist` = wrong `agent_bin_dir`; `no claymod-agent-<goos>-<goarch> files` = empty dir or renamed files (keep the release names) |
| `curl: (60) SSL certificate problem` fetching `/enroll.sh` | missing `-k` (the bootstrap certificate is internal-CA-issued) |
| agent dead after a VM reboot | the tunnel is gone — `sudo claymod-agent wg-setup --out-dir /etc/claymod` |
| `wg show` empty on the VPS | `wg_backend: fake` in server.yaml, or watch the serve log for `wireguard configuration written` |
| tunnel up, agent unreachable | the agent listens on the overlay only — `ss -tlnp \| grep 2323` on the VM |
| apply: `x509: certificate ... not found` | the CA rotated, or `--data-dir` points at a different deployment |
| playbook: `modulepath:/claymod/base.pkl` not found | `CLAYMOD_SCHEMA_DIR` points at a wrong/incomplete copy — unset it to use the embedded std ([docs/playbooks.md](playbooks.md#libraries)) |
