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

## Phase 0 — Build binaries on the workstation

No Go toolchain is needed on the VPS or the VM; cross-compile once per
architecture from the repo root on the Mac:

```sh
make build GOOS=linux GOARCH=amd64 BIN=bin/claymod-linux-amd64
make build GOOS=linux GOARCH=arm64 BIN=bin/claymod-linux-arm64
```

(`make build` passes `GOOS`/`GOARCH` through to `go build`. Debian on
UTM on Apple Silicon is **arm64**; check with `uname -m` on each target:
`x86_64` → amd64, `aarch64` → arm64.)

## Phase 1 — Control server on the VPS

### 1.1 Prerequisites

```sh
ssh root@VPS_IP
apt update
apt install -y wireguard-tools rsync
```

- `wireguard-tools` provides `wg`/`wg-quick`: with the default
  operator-managed interface you apply the config `serve` generates
  (§1.4). With `--manage-interface` claymod drives `ip`/`wg` itself and
  doesn't need them, but keeping them installed is useful for `wg show`.
- Reboot behaviour is automatic now — no sqlite3 peer-restore recipes
  (see §1.6).

### 1.2 Upload claymod

From the workstation:

```sh
rsync -av bin/claymod-linux-<arch> root@VPS_IP:/usr/local/bin/claymod
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
bootstrap certificate is issued **once** with `--server-name` baked in
as its only DNS SANs — choose it now (changing it later means deleting
`server.pem`/`server-key.pem`, i.e. re-issuing).

```sh
cd ~/claymod
claymod serve \
  --data-dir ~/claymod-data \
  --bootstrap-listen 0.0.0.0:8443 \
  --server-name vps \
  --wg-interface claymod0 \
  --wg-endpoint VPS_IP:51821 \
  --agent-network 10.42.0.0/24 \
  --wg-backend wgctrl
```

Note the startup line:

```
bootstrap certificate fingerprint (pin with --ca-pin):
  <64 hex chars>
```

Copy that fingerprint — it is what the VM will pin during enrollment.

The same startup also writes `~/claymod-data/claymod0.conf` and logs
`wireguard configuration written … peers N` — that file is what you
apply with `wg-quick`/`wg syncconf` (§1.4), and it is regenerated on
every enrollment change.

Enrollment via a bare IP (`https://VPS_IP:8443`) does **not** work with
`--ca` (the cert has DNS SANs only, no IP SAN — Go's verifier rejects
the hostname). Use `--ca-pin <fingerprint>` on the VM, exactly as in
Phase 2. (`--ca` works if you enroll via a DNS name that equals
`--server-name`.)

### 1.4 Bring up the WireGuard interface

`serve` does the configuration work for you: it installs peers on
`claymod0` via wgctrl as hosts enroll/revoke, **re-syncs every peer from
the inventory at startup**, and maintains a wg-quick config at
`~/claymod-data/claymod0.conf` (0600 — it contains the server's private
key), regenerated on every enroll/revoke and restart.

Two ways to bring the interface up — pick one:

**Operator-managed (default; claymod never touches the interface):**

```sh
wg-quick up ~/claymod-data/claymod0.conf        # first time
# on later changes (enroll/revoke), apply the update without downtime:
wg syncconf claymod0 <(wg-quick strip ~/claymod-data/claymod0.conf)
```

**Let claymod manage the interface (root, one flag):**

```sh
claymod serve ... --manage-interface
```

`--manage-interface` creates the interface if missing, assigns the
overlay address, private key and listen port at startup (needs
`CAP_NET_ADMIN`); peers are still synced via wgctrl.

Either way, verify: `wg show` lists `claymod0` listening on **51821**
(not 51820 — claymod deliberately avoids the standard port so it never
collides with your own tunnels).

### 1.5 Keep it running: systemd unit

One unit is enough — `serve` itself re-syncs all peers from the
inventory at startup and (with `--manage-interface`) recreates the
interface, so a plain restart of the server restores the whole overlay.

`/etc/systemd/system/claymod-serve.service` (operator-managed variant;
add `--manage-interface` if claymod should own the interface):

```ini
[Unit]
Description=claymod control server
After=network-online.target wg-quick@claymod0.service
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/claymod serve --data-dir /root/claymod-data --bootstrap-listen 0.0.0.0:8443 --server-name vps --wg-interface claymod0 --wg-endpoint VPS_IP:51821 --agent-network 10.42.0.0/24 --wg-backend wgctrl
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

With `--manage-interface`, drop the `After=wg-quick@…` line: claymod
brings the interface up itself on every start.

### 1.6 Reboot behaviour

No manual peer surgery needed any more: on every start `serve` reads the
inventory (the source of truth) and re-installs all peers on `claymod0`
via wgctrl, then rewrites `claymod0.conf`. Agents initiate the tunnel
with `persistent-keepalive 25`, so as soon as the server is back — and
the interface exists — handshakes resume automatically.

The only boot decision is **who creates the interface**:

- `--manage-interface`: nothing to do; `serve` recreates it at startup.
- operator-managed: `wg-quick@claymod0.service` reads
  `/etc/wireguard/claymod0.conf`, so link the generated file there once
  and enable the unit — after that it always boots current, because
  `serve` keeps the file up to date:
  ```sh
  ln -s ~/claymod-data/claymod0.conf /etc/wireguard/claymod0.conf
  systemctl enable wg-quick@claymod0
  ```

## Phase 2 — Enroll the Debian VM

### 2.1 Prepare the VM

```sh
ssh <vm>
uname -m                          # aarch64 → use the arm64 binary
apt update && apt install -y wireguard-tools curl
```

Upload the matching binary from the workstation:

```sh
# on the workstation
rsync -av bin/claymod-linux-<arch> <vm>:/usr/local/bin/claymod
```

### 2.2 Issue a token (on the VPS)

```sh
claymod host token web01 --data-dir ~/claymod-data --ttl 15m \
  --token-file ~/token-web01
```

This prints the token and writes it to `~/token-web01` (single-use,
bound to the name `web01`, valid 15 minutes).

### 2.3 Enroll (on the VM)

```sh
claymod enroll \
  --server https://VPS_IP:8443 \
  --token "$(ssh root@VPS_IP cat ~/token-web01)" \
  --hostname web01 \
  --ca-pin <fingerprint-from-serve> \
  --out-dir /etc/claymod
```

Files land in `/etc/claymod/` (`ca.pem`, `agent.pem`, `agent-key.pem`,
`agent.yaml`, `wg-keys.json`, `wg-setup.json`), and the command prints
the one bring-up step with the **allocated overlay IP** — note it.

Assertions you can make now (both must fail):
- reuse the token → refused (single-use);
- enroll with a wrong `--ca-pin` → fingerprint mismatch.

### 2.4 Bring up the tunnel (on the VM)

`enroll` wrote `/etc/claymod/wg-setup.json` with everything needed
(overlay address, the locally generated private key, the server's peer
entry — endpoint `VPS_IP:51821`, keepalive 25). One root command applies
it:

```sh
sudo claymod wg-setup --out-dir /etc/claymod
# → wireguard interface claymod0 is up (10.42.0.2/24)
#   peer <server-public-key> endpoint VPS_IP:51821 allowed-ips 10.42.0.0/24
```

This is the **only** root step of enrollment. If you prefer
operator-managed networking, render a wg-quick config from
`wg-setup.json` yourself (interface `claymod0`, `Address = <allocated-ip>/24`,
`ListenPort = 51821`, one `[Peer]` block for the server) — claymod won't
fight you.

At boot, re-run `wg-setup` (or your own wg-quick unit) before the agent:
the private key and peer live only in the interface, not on disk in
applied form. A `claymod-wg.service` oneshot that runs
`claymod wg-setup --out-dir /etc/claymod` (`Before=claymod-agent`) is
the simplest way.

Verify:

```sh
wg show            # latest handshake should populate within seconds
ping -c 3 10.42.0.1
```

On the VPS: `wg show` should now list web01 as a peer.

### 2.5 Start the agent

`claymod agent --config /etc/claymod/agent.yaml` (foreground first to
see it listen; then `claymod-agent.service`):

```ini
[Unit]
Description=claymod agent
After=network-online.target claymod-wg.service
Wants=network-online.target
Requires=claymod-wg.service

[Service]
ExecStart=/usr/local/bin/claymod agent --config /etc/claymod/agent.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

`claymod-wg.service` is the oneshot from §2.4 that runs
`claymod wg-setup --out-dir /etc/claymod` at boot.

```sh
systemctl daemon-reload
systemctl enable --now claymod-wg claymod-agent
```

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

- [ ] enrollment pinned: wrong `--ca-pin` refused
- [ ] token single-use: second enroll with the same token refused
- [ ] `wg show` shows handshakes both sides; only UDP 51821 + TCP 8443
      touch the public interface (optional `tcpdump` check)
- [ ] apply #1 → `N changed`; apply #2 → `0 changed` (idempotent over
      real mTLS + WireGuard)
- [ ] `host facts web01` returns live facts
- [ ] `exec --host web01 -- uname -a` propagates the exit code
- [ ] optional: `claymod host revoke web01` → peer removed, apply to it
      now fails; re-enroll with a fresh token to restore

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| enroll: `fingerprint mismatch` | you pinned the CA fingerprint instead of the **bootstrap certificate** fingerprint (the one `serve` prints) |
| enroll hangs on a bare IP with `--ca` | the cert has no IP SAN (see §1.3) — use `--ca-pin` or a DNS name equal to `--server-name` |
| `wg show` empty on the VPS | no peer installed — check `serve` ran with `--wg-backend wgctrl` (not `fake`) and watch its log for the `wireguard configuration written` line |
| tunnel up, agent unreachable | the agent listens on the overlay IP only; check `ss -tlnp | grep 2323` on the VM and that `agent.yaml` `listen` matches |
| apply: `x509: certificate ... not found` | the CA rotated or `--data-dir` points at a different deployment than the agent enrolled against |
| handshakes never resume after a reboot | the server interface is missing (operator-managed path: `wg-quick@claymod0` not enabled) — `serve` re-syncs peers but the interface must exist |
| playbook: `modulepath:/claymod/base.pkl` not found | run from the directory containing `pkl/`, or set `CLAYMOD_SCHEMA_DIR` |
