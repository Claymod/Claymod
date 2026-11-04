# Docker / Compose deployment

The control server ships as a multi-arch container image
(`linux/amd64`, `linux/arm64`): `ghcr.io/claymod/claymod`. It contains
everything `claymod serve` needs on the server side — the server and
CLI, the `pkl` CLI, `ip`/`wg` for the WireGuard interface, `git` for
git-pinned PKL libraries, and the `claymod-agent` binaries the bootstrap
endpoint hands to hosts.

The **agent is never installed in this image**: hosts download it from
`https://<control>:8443/agent/<os>/<arch>` when they enroll. For the
non-container path see [homelab.md](homelab.md) or
[enrollment.md](enrollment.md).

```
host (web01) ── UDP 51821 / WireGuard ──┐
      │                                 │  container: claymod serve
      └── HTTPS 8443 (enroll, agent) ───┘  CA + inventory in
                                          volume claymod-data
```

## Requirements

| Requirement | Why |
|---|---|
| WireGuard in the host kernel (`wireguard` module or 5.6+) | the container shares the kernel; it cannot load modules |
| `CAP_NET_ADMIN` on the container | `serve` runs `ip link add … type wireguard`, `ip address`, `wg set` and wgctrl |
| TCP 8443 reachable | HTTPS enrollment endpoint (agents and operators) |
| UDP 51821 reachable | the WireGuard overlay |
| outbound HTTPS | `pkl` download at **build** time only; git libraries at playbook time |

The image runs as **root on purpose** — those interface operations need
`NET_ADMIN`, which Docker does not grant to a non-root user without extra
setup. Compose hardens it with `no-new-privileges` and only two published
ports.

Published tags (from CI, `.github/workflows/image.yml`):

| Tag | When |
|---|---|
| `latest` | push to the default branch |
| `<branch>` | push to `main` (and any branch, if widened) |
| `1.2.3`, `1.2` | semver tag `v1.2.3` |
| `sha-<full sha>` | every non-PR build |

Packages on GHCR are private by default even for a public repo. For
anonymous `docker pull`, set the package visibility to public under
**GitHub → your profile/org → Packages → claymod → Package settings**.

## Quick start

```sh
export CLAYMOD_WG_ENDPOINT=203.0.113.10:51821   # public IP agents dial

docker compose -f examples/docker-compose.yaml up -d
docker compose -f examples/docker-compose.yaml logs -f claymod
```

The first start creates the CA, the control identity, the inventory and
the WireGuard keys in the `claymod-data` volume, prints the **CA
fingerprint** and the enrollment one-liner, and brings up `claymod0`.
The startup log must contain:

```
msg="wireguard configuration written" ...
msg="wireguard interface ensured" interface=claymod0
msg="agent binaries offered for download" dir=/var/lib/claymod/agents
msg="bootstrap endpoint listening (https)" addr=:8443
```

`CLAYMOD_WG_ENDPOINT` is mandatory: it is the address agents are told to
dial, so `127.0.0.1` only works for a loopback demo. Changing it later
takes effect for hosts enrolled after the change (re-enroll existing
hosts, or point them at the new endpoint).

### Enroll a host

Issue a token inside the container:

```sh
docker compose -f examples/docker-compose.yaml exec claymod claymod \
  host token web01 --config /etc/claymod/server.yaml
```

Then, on the host (the one-liner from the server log):

```sh
curl -fsSLk https://203.0.113.10:8443/enroll.sh \
  | sudo sh -s -- --token <TOKEN> --hostname web01
```

`-k` is required because the bootstrap certificate comes from claymod's
internal CA; the one-time token is the credential in this flow. The
manual, pinned flow and its trade-offs: [enrollment.md](enrollment.md).

### Apply a playbook

The WireGuard overlay lives in the container's network namespace, so the
CLI reaches agents only from inside the container. Mount your playbooks
and run it there:

```yaml
# examples/docker-compose.yaml
    volumes:
      - claymod-data:/var/lib/claymod
      - ./playbooks:/playbooks:ro
```

```sh
docker compose -f examples/docker-compose.yaml exec claymod claymod \
  playbook apply /playbooks/site.pkl --data-dir /var/lib/claymod
```

`--data-dir` locates the control identity and inventory; the overlay
defaults (`10.42.0.0/24`, agent port 2323) match the baked config. The
same pattern runs `host list`, `host facts web01`, `exec --host web01 --`,
`host revoke web01`, `lib sync`, ….

## Configuration

The image is configured the same way as a native install: a YAML file,
the primary source, with CLI flags as explicit overrides.

| Path / variable | Contents |
|---|---|
| `/etc/claymod/server.yaml` | baked default config (container paths, `:8443`, UDP 51821) |
| `/var/lib/claymod` | data dir **and** the volume: CA, identities, `inventory.db`, `claymod0.conf`, `agents/`, caches |
| `/var/lib/claymod/agents` | `claymod-agent-<os>-<arch>` served at `/agent/<os>/<arch>` |
| `HOME`, `XDG_CACHE_HOME`, `CLAYMOD_CACHE_DIR` | all under `/var/lib/claymod`, so schema/library/pkl caches survive recreation |

To use your own config, mount it over the baked one:

```yaml
    volumes:
      - ./server.yaml:/etc/claymod/server.yaml:ro
      - claymod-data:/var/lib/claymod
```

A single flag override works too (explicit flags win over the file):

```sh
docker compose -f examples/docker-compose.yaml run --rm claymod \
  serve --config /etc/claymod/server.yaml --wg-endpoint 198.51.100.7:51821
```

Annotated config reference: [examples/server.yaml](../examples/server.yaml).
Container defaults: [docker/server.yaml](../docker/server.yaml).

### Networking: bridge or host

| Mode | Operator CLI | Notes |
|---|---|---|
| bridge (default) | `docker compose exec claymod claymod …` | overlay isolated in the container; only 8443/tcp + 51821/udp published |
| `network_mode: host` | on the host, with the same `--data-dir`-style flags | Linux only; the interface lands in the host namespace, so `10.42.0.x` is routable from the host. Drop `ports:`; keep `cap_add: NET_ADMIN` |

With bridge networking, `claymod exec` / `playbook apply` run from a
workstation **cannot** reach the overlay — run them in the container.

### Trying it without capabilities

For a UI/loopback demo, skip WireGuard management entirely:

```sh
docker run --rm -p 8443:8443 ghcr.io/claymod/claymod:latest \
  serve --data-dir /tmp/data --wg-backend fake \
  --agent-bin-dir /var/lib/claymod/agents
```

`--wg-backend fake` needs no `NET_ADMIN`; nothing is installed on a real
interface. Enrollment still works over HTTPS, but agents cannot reach
the server through a tunnel.

## Operating

| Task | Command |
|---|---|
| list hosts | `docker compose … exec claymod claymod host list --config /etc/claymod/server.yaml` |
| live facts | `docker compose … exec claymod claymod host facts web01 --data-dir /var/lib/claymod` |
| run a command | `docker compose … exec claymod claymod exec --host web01 --data-dir /var/lib/claymod -- uname -a` |
| revoke a host | `docker compose … exec claymod claymod host revoke web01 --config /etc/claymod/server.yaml` (needs `NET_ADMIN`; runs against the live interface) |
| health | `docker compose … ps` (uses `GET /healthz` with the internal CA — hence `-k`) |
| logs | `docker compose … logs -f claymod` |

`serve` handles `SIGTERM`: `docker stop` logs `shutting down` and exits 0
within the 20 s grace period.

## Upgrades and backup

```sh
docker compose -f examples/docker-compose.yaml pull
docker compose -f examples/docker-compose.yaml up -d
```

The data volume carries over untouched: the CA and control identity are
stable across upgrades, so enrolled hosts keep working.

Back up by stopping the service (a consistent SQLite file) and archiving
the volume:

```sh
docker compose -f examples/docker-compose.yaml stop claymod
docker run --rm -v claymod_claymod-data:/data -v "$PWD":/backup \
  alpine tar czf /backup/claymod-data.tgz -C /data .
```

The volume contains the CA **private key**: treat a backup like the
control server itself. Losing it means re-enrolling every host.

## Building and testing locally

```sh
docker build -t claymod:dev .
docker build -t claymod:dev --build-arg VERSION=v1.2.3 .
docker build -t claymod:dev --build-arg PKL_VERSION=0.32.2 .
```

The same script CI runs, which builds the image and exercises it against
the real kernel (HTTP enrollment surface, served agents + digests,
graceful shutdown, WireGuard interface, `host token`):

```sh
scripts/test-docker-image.sh                  # build + test
scripts/test-docker-image.sh --multiarch      # also build amd64 and arm64
NO_BUILD=1 IMAGE=claymod:step1 scripts/test-docker-image.sh   # reuse an image
scripts/test-docker-image.sh --keep           # keep containers for inspection
```

The multi-arch check builds one platform at a time: two concurrent Go
builds of the sqlite driver exceed a small builder VM (2 GB colima dies
with `cannot allocate memory`). CI's publish job builds both platforms in
one invocation on a larger runner.

The image is ~480 MB on disk: Debian slim plus `git`/perl, the `pkl`
binary (~99 MB), the control binary (~15 MB) and four agent binaries
(~32 MB). The agent binaries and `git` are functional requirements; trim
the former only if you serve agents from elsewhere (`agent_bin_dir`).

## Security notes

- Two exposed ports: TCP 8443 (enrollment) and UDP 51821 (overlay).
  Nothing else leaves the container.
- Everything on the wire after enrollment is framed JSON over mutual
  TLS 1.3 inside WireGuard. Enrollment itself is token-authenticated
  (see [security.md](security.md#one-liner-bootstrap)).
- The container runs as root with `NET_ADMIN` because it manages the
  interface. `no-new-privileges` is set; don't add more capabilities.
- The data volume holds the CA key, the control client key and host WireGuard
  keys: root-only, backed up, never committed.
- `agent_bin_dir` is served over the bootstrap endpoint; keep the baked
  binaries or verify your own.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `serve` exits with `manage-interface: ip: … Operation not permitted` | missing `cap_add: NET_ADMIN` (or the container was started without it) |
| `… Operation not supported` / `Unknown device type` | the host kernel has no WireGuard support — `modprobe wireguard` on the host (outside the container) |
| agents enroll but never connect | `CLAYMOD_WG_ENDPOINT` is not the address agents can reach, or UDP 51821 is firewalled |
| `curl: (60) SSL certificate problem` on `/enroll.sh` or `/healthz` | expected: the bootstrap certificate is internal-CA-issued — use `-k` (or `--cacert` with the CA) |
| one-liner: `curl: (22) … 404` on the agent download | `agent_bin_dir` does not contain `claymod-agent-<os>-<arch>`; the baked default is `/var/lib/claymod/agents` |
| container `unhealthy` | `serve` is not listening on 8443 (check `bootstrap_listen`) or it crashed — read the logs |
| `playbook apply` cannot reach hosts | it is running outside the container (bridge networking); use `docker compose exec` or host networking |
| `pkl: not found` | only if you replaced the image or removed `PATH` entries; pkl is at `/usr/local/bin/pkl` |
| permission denied writing the data dir | the container runs as root; a volume created for another UID needs `chown`, or override `user:` and grant `NET_ADMIN` yourself |
