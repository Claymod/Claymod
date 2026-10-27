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
apt install -y wireguard-tools sqlite3 rsync
```

- `wireguard-tools` provides `wg`/`wg-quick` (the interface is created
  with `ip link`, but `wg set` configures peers).
- `sqlite3` is only for the optional peer-restore recipe (§1.6).

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

Enrollment via a bare IP (`https://VPS_IP:8443`) does **not** work with
`--ca` (the cert has DNS SANs only, no IP SAN — Go's verifier rejects
the hostname). Use `--ca-pin <fingerprint>` on the VM, exactly as in
Phase 2. (`--ca` works if you enroll via a DNS name that equals
`--server-name`.)

### 1.4 Bring up the WireGuard interface

`wg(8)` wants the private key as a raw base64 file, but claymod stores
it as JSON — unpack it first (this is the same command `enroll` prints
on agents):

```sh
awk -F'"' '/private/ {print $4}' ~/claymod-data/wg-keys.json \
  | tee /run/claymod-wg.key >/dev/null && chmod 600 /run/claymod-wg.key

ip link add dev claymod0 type wireguard
ip address add 10.42.0.1/24 dev claymod0
wg set claymod0 private-key /run/claymod-wg.key listen-port 51821
ip link set up dev claymod0
rm /run/claymod-wg.key
```

Peers are installed **automatically** by `serve` (wgctrl backend) as
hosts enroll — nothing to do by hand here.

### 1.5 Keep it running: systemd units

`/etc/systemd/system/claymod-wg.service` (recreates the interface after
reboot; runs before the server):

```ini
[Unit]
Description=claymod WireGuard interface
After=network-online.target
Wants=network-online.target
Before=claymod-serve.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'awk -F"\"" "/private/ {print \$4}" /root/claymod-data/wg-keys.json | tee /run/claymod-wg.key >/dev/null && chmod 600 /run/claymod-wg.key && ip link add dev claymod0 type wireguard && ip address add 10.42.0.1/24 dev claymod0 && wg set claymod0 private-key /run/claymod-wg.key listen-port 51821 && ip link set up dev claymod0 && rm /run/claymod-wg.key'

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/claymod-serve.service`:

```ini
[Unit]
Description=claymod control server
After=network-online.target claymod-wg.service
Wants=network-online.target
Requires=claymod-wg.service

[Service]
ExecStart=/usr/local/bin/claymod serve --data-dir /root/claymod-data --bootstrap-listen 0.0.0.0:8443 --server-name vps --wg-interface claymod0 --wg-endpoint VPS_IP:51821 --agent-network 10.42.0.0/24 --wg-backend wgctrl
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```sh
systemctl daemon-reload
systemctl enable --now claymod-wg claymod-serve
systemctl status claymod-serve
```

### 1.6 Known limitation: peers after a reboot of the WG interface

Peers are added to `claymod0` at enrollment time. If the interface is
recreated (e.g. you bring it down/up manually), `serve` does **not**
re-sync peers from the inventory — re-add them manually:

```sh
sqlite3 ~/claymod-data/inventory.db "select hostname, public_key, wg_ip from hosts"
# for each host:
wg set claymod0 peer <public_key> allowed-ips <wg_ip>/32
```

(A full reboot **requires re-adding the peers**: the `claymod-wg`
unit recreates `claymod0` with only the server's private key — no
peers — and `serve` does not re-sync them from the inventory. WireGuard
silently drops handshake initiations from unknown public keys, so the
agents' `persistent-keepalive 25` alone cannot restore the tunnel:
every keepalive is dropped until its public key is known again. After
any reboot, run the `sqlite3` + `wg set` loop above for every enrolled
host.)

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
`agent.yaml`, `wg-keys.json`), and the command prints the WireGuard
setup commands with the **allocated overlay IP** — note it.

Assertions you can make now (both must fail):
- reuse the token → refused (single-use);
- enroll with a wrong `--ca-pin` → fingerprint mismatch.

### 2.4 Bring up the tunnel (on the VM)

```sh
awk -F'"' '/private/ {print $4}' /etc/claymod/wg-keys.json \
  | tee /run/claymod-wg.key >/dev/null && chmod 600 /run/claymod-wg.key

ip link add dev claymod0 type wireguard
ip address add <allocated-ip>/24 dev claymod0        # e.g. 10.42.0.2
wg set claymod0 private-key /run/claymod-wg.key listen-port 51821 \
  peer <server-public-key> endpoint VPS_IP:51821 \
  allowed-ips 10.42.0.0/24 persistent-keepalive 25
ip link set up dev claymod0
rm /run/claymod-wg.key
```

(`<server-public-key>` is printed by `enroll`; it is also the
`Public` field of `~/claymod-data/wg-keys.json` on the VPS.)

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
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/claymod agent --config /etc/claymod/agent.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```sh
systemctl daemon-reload
systemctl enable --now claymod-agent
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
| `wg show` empty on the VPS | peer not yet added — it is added at enrollment; check `serve` ran with `--wg-backend wgctrl` (not `fake`) |
| tunnel up, agent unreachable | the agent listens on the overlay IP only; check `ss -tlnp | grep 2323` on the VM and that `agent.yaml` `listen` matches |
| apply: `x509: certificate ... not found` | the CA rotated or `--data-dir` points at a different deployment than the agent enrolled against |
| `wg set: Bad file` / key rejected | you passed the JSON file instead of the unpacked raw key (see the `awk` line) |
| playbook: `modulepath:/claymod/base.pkl` not found | run from the directory containing `pkl/`, or set `CLAYMOD_SCHEMA_DIR` |
