# Homelab deployment guide

Step-by-step runbook for a **first real environment**: claymod control
server on a VPS, a fresh Debian VM enrolled over a real WireGuard
overlay, and a playbook that installs a simple system (nginx + motd +
templated index). The goal is to prove the full workflow outside
loopback: real enrollment, tunnel, and idempotent apply.

This guide assumes **you run every command yourself** (SSH from your
workstation); nothing here needs claymod itself for setup.

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

| Thing | Value used here | Change if needed |
|---|---|---|
| Overlay network | `10.42.0.0/24` | `--agent-network` everywhere it appears |
| Control VPS | `VPS_IP` (public), overlay `10.42.0.1` | replace `VPS_IP` throughout |
| Debian VM | `web01`, overlay `10.42.0.2` | any free IP in the CIDR |
| Bootstrap HTTPS | TCP `8443` | `--bootstrap-listen` |
| WireGuard | UDP `51821`, iface `claymod0` | `--wg-interface`, `--wg-endpoint` |
| Agent port | TCP `2323` (tunnel only) | `--agent-port` / `--listen` |

Both server and agent run as **root** in this guide (WireGuard and
systemd need it). The agent executes commands with its own privileges —
that is by design and documented in `docs/security.md`.

Ports to open on the VPS provider firewall (and `ufw`/`firewalld` if
enabled): **TCP 8443** (enrollment, short-lived use) and **UDP 51821**
(the overlay; everything else flows through the tunnel). Nothing else is
exposed: applies, facts and exec dial the agent inside the tunnel.

## Phase 0 — Get the binaries

Claymod is two binaries, both published on every release as static
linux builds (plus `SHA256SUMS`):

| Binary | Where it runs | Release asset | Contains |
|---|---|---|---|
| `claymod` | control server (VPS) | `claymod-linux-<arch>` | serve, playbooks, inventory, exec — needs the `pkl` CLI |
| `claymod-agent` | managed hosts (VM) | `claymod-agent-linux-<arch>` | `agent`, `enroll`, `wg-setup` — static, no deps |

No Go toolchain is needed anywhere: download from
`https://github.com/Claymod/Claymod/releases/latest/download/` and
verify against `SHA256SUMS`. (Debian on UTM on Apple Silicon is
**arm64**; check with `uname -m`: `x86_64` → amd64, `aarch64` → arm64.)

Developing claymod itself? `make build` / `make agents` cross-compile
the same binaries from a checkout instead.

## Phase 1 — Control server on the VPS

### 1.1 Prerequisites

```sh
ssh root@VPS_IP
apt update
apt install -y wireguard-tools rsync
```

- `wireguard-tools` provides `wg`/`wg-quick`. By default `serve`
  **manages the interface itself** (`--manage-interface`, needs
  `CAP_NET_ADMIN` — i.e. root) and drives `ip`/`wg` directly, so the
  tools are only needed for `wg show` diagnostics; with
  `--manage-interface=false` you apply the generated config via
  `wg-quick` yourself (§1.4).
- Reboot behaviour is automatic now — no sqlite3 peer-restore recipes
  (see §1.6).

### 1.2 Install the control binary

On the VPS (replace `<arch>` with `amd64` or `arm64` per `uname -m`):

```sh
BASE=https://github.com/Claymod/Claymod/releases/latest/download
curl -fsSL -O $BASE/claymod-linux-<arch> -O $BASE/SHA256SUMS
grep "claymod-linux-<arch>$" SHA256SUMS | sha256sum -c -
install -m 0755 claymod-linux-<arch> /usr/local/bin/claymod
```

Optionally pre-stage the agent binaries for hosts to download over the
bootstrap channel (the one-liner and air-gap flow need this — the
script fetches its agent from the server):

```sh
curl -fsSL -O $BASE/claymod-agent-linux-<arch>
grep "claymod-agent-linux-<arch>$" SHA256SUMS | sha256sum -c -
mkdir -p ~/claymod/agents
install -m 0755 claymod-agent-linux-<arch> ~/claymod/agents/
```

**How binaries are served.** `serve` offers whatever is in one
directory — `--agent-bin-dir` (default `<data-dir>/agents`) — at
`GET /agent/<goos>/<goarch>` (plus a computed `.sha256` sidecar). The
filename **is** the mapping: `claymod-agent-<goos>-<goarch>`, i.e. the
release asset name dropped into that directory unchanged. Keep the
release names — `claymod-agent-linux-amd64` is what
`/agent/linux/amd64` serves; a file named just `claymod-agent` is
invisible to it. With the staging dir above, §1.3 passes
`--agent-bin-dir ~/claymod/agents`.

`~` is expanded by claymod itself, so `~/claymod/agents` works even in
a systemd unit (whose `ExecStart` has no shell) — but an absolute path
(`$HOME/claymod/agents` written out, e.g. `/root/claymod/agents`) is
the safer habit in units and scripts. At startup the serve log tells
you which case you are in:

```
agent binaries offered for download        dir=…  ← working (plus one
                                                    "agent binary <os>-<arch>
                                                    <sha256>" line per binary)
… no agent binaries to serve: directory
  does not exist …                         dir=…  ← wrong path (watch for a
                                                    literal ~ in old configs)
… no agent binaries to serve: no
  claymod-agent-<goos>-<goarch> files …    dir=…  ← dir exists but is empty /
                                                    wrongly named files
```

Any of the last two lines means every `/agent/…` request (and therefore
the one-liner) 404s.

The repo is still needed for the PKL schema and the pkl bootstrap
script (copy from the workstation, or `git clone` on the VPS):

```sh
ssh root@VPS_IP 'mkdir -p ~/claymod/pkl'
rsync -av pkl/ root@VPS_IP:~/claymod/pkl/          # the PKL schema
rsync -av scripts/bootstrap-pkl.sh root@VPS_IP:~/claymod/
```

The server needs the `pkl` CLI to evaluate playbooks (agents never do):

```sh
ssh root@VPS_IP
~/claymod/scripts/bootstrap-pkl.sh    # installs to /usr/local/bin
```

### 1.3 First `serve` run — creates all state

The first run generates the CA, bootstrap certificate, server WireGuard
key pair and inventory DB, then reloads them on every later start. The
bootstrap certificate bakes `--server-name` into its SANs — a DNS name
becomes a DNS SAN, an IP becomes an IP SAN — and is **re-issued
automatically** whenever `--server-name` changes (the CA, and with it
the fingerprint, stays stable).

```sh
cd ~/claymod
claymod serve \
  --data-dir ~/claymod-data \
  --bootstrap-listen 0.0.0.0:8443 \
  --server-name vps \
  --wg-interface claymod0 \
  --wg-endpoint VPS_IP:51821 \
  --agent-network 10.42.0.0/24 \
  --agent-bin-dir ~/claymod/agents \
  --wg-backend wgctrl
```

`--agent-bin-dir ~/claymod/agents` is what makes the one-liner work:
the bootstrap script downloads the agent from
`GET /agent/<goos>/<goarch>`, which serves files from that directory
(§1.2). Without it, serve looks in `<data-dir>/agents` (empty) and
every agent download 404s.

One fingerprint is printed — the **CA fingerprint**, the single pin of
the deployment:

```
CA fingerprint (the pin for agent enroll --ca-pin/--ca)
  <64 hex chars>
```

Copy it: the manual `enroll --ca-pin` flow (§2.4) verifies the served
`/ca.pem` bundle against exactly this value. The one-liner (§2.3) does
not need it — there the token is the credential. `serve` also prints
the ready-made one-liner command.

The same startup also writes `~/claymod-data/claymod0.conf` and logs
`wireguard configuration written … peers N` — that file is what you
apply with `wg-quick`/`wg syncconf` (§1.4), and it is regenerated on
every enrollment change.

Enrollment via a bare IP (`https://VPS_IP:8443`) works in every flow:
the one-liner and `--ca-pin` waive hostname checks (the token/pin is
the identity), and when `--server-name` is an IP the bootstrap
certificate carries an IP SAN so even `--ca` stock verification
accepts it.

### 1.4 Bring up the WireGuard interface

`serve` does the configuration work for you: it installs peers on
`claymod0` via wgctrl as hosts enroll/revoke, **re-syncs every peer from
the inventory at startup**, and maintains a wg-quick config at
`~/claymod-data/claymod0.conf` (0600 — it contains the server's private
key), regenerated on every enroll/revoke and restart.

Two ways to bring the interface up — pick one:

**claymod-managed (default):** with no extra flags, `serve` creates
the interface if missing, assigns the overlay address, private key and
listen port at startup (needs `CAP_NET_ADMIN`, i.e. root) and keeps
peers in sync via wgctrl. Nothing to run by hand — §1.5's unit is all
you need.

**Operator-managed (opt out; claymod never touches the interface):**

```sh
claymod serve ... --manage-interface=false
# then apply the generated config yourself:
wg-quick up ~/claymod-data/claymod0.conf        # first time
# on later changes (enroll/revoke), apply the update without downtime:
wg syncconf claymod0 <(wg-quick strip ~/claymod-data/claymod0.conf)
```

Either way, verify: `wg show` lists `claymod0` listening on **51821**
(not 51820 — claymod deliberately avoids the standard port so it never
collides with your own tunnels).

### 1.5 Keep it running: systemd unit

One unit is enough — `serve` itself re-syncs all peers from the
inventory at startup and (with `--manage-interface`) recreates the
interface, so a plain restart of the server restores the whole overlay.

`/etc/systemd/system/claymod-serve.service` (default: claymod manages
the interface itself — no wg-quick unit needed):

```ini
[Unit]
Description=claymod control server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/claymod serve --data-dir /root/claymod-data --bootstrap-listen 0.0.0.0:8443 --server-name vps --wg-interface claymod0 --wg-endpoint VPS_IP:51821 --agent-network 10.42.0.0/24 --agent-bin-dir /root/claymod/agents --wg-backend wgctrl
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```sh
systemctl daemon-reload
systemctl enable --now claymod-serve
systemctl status claymod-serve
```

For the operator-managed variant (`--manage-interface=false`), add
`After=wg-quick@claymod0.service` and enable that unit too (§1.6).

### 1.6 Reboot behaviour

No manual peer surgery needed any more: on every start `serve` reads the
inventory (the source of truth) and re-installs all peers on `claymod0`
via wgctrl, then rewrites `claymod0.conf`. Agents initiate the tunnel
with `persistent-keepalive 25`, so as soon as the server is back — and
the interface exists — handshakes resume automatically.

The only boot decision is **who creates the interface**:

- default (claymod-managed): nothing to do; `serve` recreates it at
  startup (`--manage-interface` is on).
- operator-managed (`--manage-interface=false`): `wg-quick@claymod0.service`
  reads `/etc/wireguard/claymod0.conf`, so link the generated file there
  once and enable the unit — after that it always boots current, because
  `serve` keeps the file up to date:
  ```sh
  ln -s ~/claymod-data/claymod0.conf /etc/wireguard/claymod0.conf
  systemctl enable wg-quick@claymod0
  ```

## Phase 2 — Enroll the Debian VM

### 2.1 Prepare the VM

```sh
ssh <vm>
uname -m                          # aarch64 → arm64 agent
apt update && apt install -y wireguard-tools curl
```

(`wireguard-tools` provides `wg`, needed by the tunnel step; the
one-liner's preflight checks for it **before** the token is consumed, so
a missing dependency aborts with the token still valid. The script never
installs packages in your place.)

No DNS setup needed: the one-liner works against a bare IP
(`https://VPS_IP:8443`). If you prefer a name, a hosts entry
(`echo "VPS_IP vps" | sudo tee -a /etc/hosts`) lets you enroll via
`https://vps:8443`, which also satisfies `--ca`'s hostname check.

### 2.2 Issue a token (on the VPS)

```sh
claymod host token web01 --data-dir ~/claymod-data --ttl 15m \
  --token-file ~/token-web01
```

This prints the token and writes it to `~/token-web01` (single-use,
bound to the name `web01`, valid 15 minutes). It also prints the exact
one-liner to run on the host (token-only — the `-k` is included).

### 2.3 Enroll — the one-liner (preferred)

`serve` exposes a bootstrap script at `GET|POST /enroll.sh` that does
the whole host setup: download the right agent, verify the binary
against its served digest, enroll (the **token is the credential**),
bring up WireGuard and install `claymod-agent.service`. One command,
on the VM:

```sh
# -k is required: the bootstrap certificate comes from claymod's
# internal CA (no system trust store). The one-time token IS the
# credential in this flow; the transport itself is not pinned.
curl -fsSLk https://VPS_IP:8443/enroll.sh \
  | sudo sh -s -- --token "$(ssh root@VPS_IP cat ~/token-web01)" \
                  --hostname web01
```

That is everything: binary at `/usr/local/bin/claymod-agent`, identity
in `/etc/claymod/`, tunnel up on `claymod0`, `claymod-agent.service`
enabled and started. Options: `--skip-wg` (no tunnel yet), `--no-systemd`
(binary only), `--server`/`--out-dir`/`--bin-dir` to override.

Three honest caveats (full treatment in
[docs/security.md](security.md#one-liner-bootstrap)):

- `curl | sh` reports **sh's** exit code: if the fetch fails, sh runs on
  empty input and exits 0. Watch the output — it prints `==` progress
  lines — or use the fetch-first form (`curl … -o enroll.sh && less
  enroll.sh && sudo sh enroll.sh …`) from security.md.
- The script runs as root and mutates the host before you read it; the
  token is what limits the blast radius (single-use, hostname-bound,
  short TTL) — for an authenticated transport use the pinned manual
  flow (§2.4).
- The installed unit starts only the **agent**, not the tunnel: after a
  VM reboot the tunnel must be re-created first (see §2.5's note).

Assertions you can make now:
- reuse the token → the second run fails at the enroll step (single-use);
- re-run with a wrong token → the enroll step refuses before anything
  is installed.

### 2.4 Manual enrollment (fallback)

When you don't want `curl | sh`, every step is available by hand —
**2.4a** copy the agent binary, **2.4b** enroll, **2.4c** bring up the
tunnel, then §2.5 to run it.

**2.4a — the binary:**

```sh
# from the GitHub release (same as Phase 0)…
BASE=https://github.com/Claymod/Claymod/releases/latest/download
curl -fsSL -O $BASE/claymod-agent-linux-<arch> -O $BASE/SHA256SUMS
grep "claymod-agent-linux-<arch>$" SHA256SUMS | sha256sum -c -
sudo install -m 0755 claymod-agent-linux-<arch> /usr/local/bin/claymod-agent
# …or download over the pinned bootstrap channel (needs
# --agent-bin-dir and the ca.pem from §1.3; this is the air-gap flow):
curl --cacert ca.pem -o claymod-agent https://vps:8443/agent/linux/<arch>
curl --cacert ca.pem https://vps:8443/agent/linux/<arch>.sha256
sha256sum claymod-agent          # compare with the served digest
sudo install -m 0755 claymod-agent /usr/local/bin/claymod-agent
```

(`ca.pem` here is `~/claymod-data/ca/ca.pem` from the VPS — copy it
first. A bare-IP URL fails `--cacert` hostname verification; enroll via
the `--server-name` DNS name (hosts entry from §2.1) or use
`--connect-to vps:8443:VPS_IP:8443`.)

**2.4b — enroll** (on the VM):

```sh
claymod-agent enroll \
  --server https://vps:8443 \
  --token "$(ssh root@VPS_IP cat ~/token-web01)" \
  --hostname web01 \
  --ca-pin "$CA_FINGERPRINT" \
  --out-dir /etc/claymod
```

Files land in `/etc/claymod/` (`ca.pem`, `agent.pem`, `agent-key.pem`,
`agent.yaml`, `wg-keys.json`, `wg-setup.json`). `--ca-pin` takes the
**CA fingerprint** from §1.3 — one pin for the whole deployment.

**2.4c — the tunnel** (on the VM):

```sh
sudo claymod-agent wg-setup --out-dir /etc/claymod
# → wireguard interface claymod0 is up (10.42.0.2/24)
#   peer <server-public-key> endpoint VPS_IP:51821 allowed-ips 10.42.0.0/24
```

This is the only root step of enrollment. Operator-managed networking
also works: render a wg-quick config from `wg-setup.json` (interface
`claymod0`, `Address = <allocated-ip>/24`, `ListenPort = 51821`, one
`[Peer]` block for the server).

Verify:

```sh
wg show            # latest handshake should populate within seconds
ping -c 3 10.42.0.1
```

On the VPS: `wg show` should now list web01 as a peer.

### 2.5 Run the agent

With the one-liner, `claymod-agent.service` is already enabled and
running — verify with `systemctl status claymod-agent`. For the manual
path, run it in the foreground first (`claymod-agent agent --config
/etc/claymod/agent.yaml`), then install the same unit the script uses
(`Restart=always`, `ExecStart=/usr/local/bin/claymod-agent agent
--config /etc/claymod/agent.yaml`) and `systemctl enable --now
claymod-agent`.

**Reboot note (both paths):** the unit starts only the agent. After a
VM reboot the WireGuard tunnel is gone (`wg-setup` applies it at run
time; nothing re-applies it at boot), so re-run
`sudo claymod-agent wg-setup --out-dir /etc/claymod` first, or add a
`claymod-wg.service` oneshot (`ExecStart=… wg-setup …`,
`Before=claymod-agent`) or a wg-quick unit. Without the tunnel the
agent listens on an address nothing can reach.

The agent listens **only** on the overlay address, TCP 2323, inside the
WireGuard tunnel — the VM needs no inbound ports on its real interface.

### 2.6 Smoke test (on the VPS)

```sh
claymod host facts web01 --data-dir ~/claymod-data
claymod exec --host web01 --data-dir ~/claymod-data -- uname -a
```

Both dial `10.42.0.2:2323` through the tunnel with mutual TLS. If they
hang: check `wg show` handshakes on both sides, and that the VM's
`iptables`/`nftables` isn't filtering the tunnel interface.

## Phase 3 — Playbook: install nginx

### 3.1 Files (on the VPS, in `~/claymod`)

`~/claymod/homelab/files/motd`:

```
Managed by claymod — host {{.Host}}
```

`~/claymod/homelab/files/index.html.tmpl`:

```
<html><body><h1>{{.Vars.greeting}} from {{.Host}}</h1></body></html>
```

`~/claymod/homelab/playbook.pkl`:

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

From `~/claymod` (the directory that contains `pkl/` — that is the
schema dir; override with `CLAYMOD_SCHEMA_DIR` if you run from
elsewhere):

```sh
claymod playbook validate homelab/playbook.pkl
claymod playbook plan homelab/playbook.pkl
claymod playbook apply homelab/playbook.pkl \
  --data-dir ~/claymod-data --check          # dry run
claymod playbook apply homelab/playbook.pkl \
  --data-dir ~/claymod-data                  # real run → "ok, N changed"
claymod playbook apply homelab/playbook.pkl \
  --data-dir ~/claymod-data                  # again → "ok, 0 changed"
```

The second real apply reporting **0 changed** is the idempotence proof.

### 3.3 Verify on the VM

```sh
curl -s localhost                    # → "hello from web01"
systemctl is-enabled nginx           # → enabled
cat /etc/motd
```

Optional on the VPS — prove the apply went through the tunnel, not the
public interface:

```sh
tcpdump -ni any port 2323            # then run an apply in another shell
```

## Phase 4 — Proof checklist

- [ ] one-liner: wrong or expired token → enrollment refused before
      anything is installed
- [ ] token single-use: re-running the one-liner with the same token
      fails at the enroll step
- [ ] `wg show` shows handshakes both sides; only UDP 51821 + TCP 8443
      touch the public interface (optional `tcpdump` check)
- [ ] `systemctl is-active claymod-agent` → active (one-liner installed
      it), `curl -s localhost` on the VM serves nginx (Phase 3)
- [ ] apply #1 → `N changed`; apply #2 → `0 changed` (idempotent over
      real mTLS + WireGuard)
- [ ] `host facts web01` returns live facts
- [ ] `exec --host web01 -- uname -a` propagates the exit code
- [ ] optional: `claymod host revoke web01` → peer removed, apply to it
      now fails; re-enroll with a fresh token to restore

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| enroll: `fingerprint mismatch` (`--ca-pin`) | the pin is the **CA** fingerprint ("CA fingerprint (the pin for agent enroll …)" line), not the TLS leaf's — compute it with `curl -fsSLk https://vps:8443/ca.pem \| openssl x509 -outform DER \| sha256sum` |
| `curl: (60) SSL certificate problem` fetching `/enroll.sh` | missing `-k`: the bootstrap cert is internal-CA-issued (see §2.3) |
| one-liner exits 0 but nothing happened | `curl | sh` reports sh's exit code — a failed fetch looks like success; watch for the `==` progress lines (§2.3) |
| one-liner: `curl: (22) … 404` on the agent download | serve isn't serving binaries — read the startup log (§1.2 "How binaries are served"): `directory does not exist` = wrong path (check for an unexpanded `~` in the unit: `dir=~/…` literally); `no claymod-agent-<goos>-<goarch> files here` = dir exists but the files are missing or misnamed (keep the release asset names) |
| one-liner: could not resolve `vps` | use the bare IP (`https://VPS_IP:8443`) directly, or add a §2.1 hosts entry, or pass `--server https://<name>:8443` |
| enrolled but `wg-setup`/agent install failed (old script) | the token is burned but nothing is lost: install `wireguard-tools`, fetch the agent again (`curl -fsSLk -o claymod-agent https://VPS_IP:8443/agent/linux/<arch>`), run `claymod-agent wg-setup --out-dir /etc/claymod`, install it to `/usr/local/bin` + the systemd unit — or simply `claymod host revoke <name>` and re-run the one-liner with a fresh token (the new script preflights WireGuard tooling first) |
| agent dead after a VM reboot | the tunnel was not re-created — run `sudo claymod-agent wg-setup` (§2.5 reboot note) |
| `wg show` empty on the VPS | no peer installed — check `serve` ran with `--wg-backend wgctrl` (not `fake`) and watch its log for the `wireguard configuration written` line |
| tunnel up, agent unreachable | the agent listens on the overlay IP only; check `ss -tlnp | grep 2323` on the VM and that `agent.yaml` `listen` matches |
| apply: `x509: certificate ... not found` | the CA rotated or `--data-dir` points at a different deployment than the agent enrolled against |
| handshakes never resume after a reboot | the server interface is missing (operator-managed path: `wg-quick@claymod0` not enabled) — `serve` re-syncs peers but the interface must exist |
| playbook: `modulepath:/claymod/base.pkl` not found | run from the directory containing `pkl/`, or set `CLAYMOD_SCHEMA_DIR` |
