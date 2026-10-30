# Library index

Playbook libraries are git repos of PKL modules shared across playbook
repos. The mechanics — `claymod.project.yaml`, ref pinning, the cache,
`claymod lib list|sync` — are documented in
[playbooks.md § Libraries](playbooks.md#libraries). This page is the
**discovery point and the trust list**: which libraries exist, who
maintains them, and what each one is allowed to be responsible for.

> There is deliberately no registry service. A library is a git URL and
> an immutable tag; this page is a curated index over that, not a
> package server.

## What belongs in the std vs a library

| | Ships with claymod (`pkl/claymod/std/`) | Library |
|---|---|---|
| Nature | primitive, distro-agnostic | opinionated, distro-aware |
| Change rate | rare, with the binary | independent, semver tags |
| Examples | `files`, `commands`, `service`, `sysctl`, `cron`, `assert`, `users` | `pkg`, `systemd`, `baseline`, app installers |

Rule of thumb: **the std holds what every Unix has** (a file, a process,
a user, a listening port). A library holds what depends on *which*
package manager, *which* init system, *which* upstream release channel
that host runs.

## Trust tiers

| Tier | What it means | Who reviews |
|---|---|---|
| **Official** | Maintained in the Claymod org. Tested in its CI against the docker simulation on every release. Immutable semver tags. | Claymod maintainers |
| **Reviewed** | Community-maintained, reviewed once at listing and on every major tag. Listed status is a snapshot, not a guarantee. | Claymod maintainers, on request |
| **Community** | Listed for discovery only. Use at your own review level. | Nobody |

Promotion is a one-line change to this page: a library that proves
itself and stays boring to maintain moves up. Demotion (or removal for
security) is equally mechanical — pinning means nobody's playbook
breaks when an entry leaves this list.

## Official libraries

Status legend: **planned** = designed here, repo not yet published —
do not pin it yet; **published** = usable now.

### Tier 1 — must have

| Library | Status | Module prefix | Purpose | Why it is not in the std |
|---|---|---|---|---|
| [claymod-libs-pkg](#claymod-libs-pkg) | planned | `pkg` | Package management and repository setup | Emits `dpkg-query`/`rpm`/`apk` — the definition of distro-specific |
| [claymod-libs-systemd](#claymod-libs-systemd) | planned | `systemd` | Unit and timer *files* (`/etc/systemd/system`) | `std.service` manages unit state; unit files are systemd-specific |
| [claymod-libs-baseline](#claymod-libs-baseline) | planned | `baseline` | New-server checklist composites | Composes std resources; opinionated by design |

### Tier 2 — next

| Library | Status | Module prefix | Purpose |
|---|---|---|---|
| `claymod-libs-containers` | planned | `containers` | Engine install + containers-as-units |
| `claymod-libs-gitdeploy` | planned | `gitdeploy` | Deploy a git checkout at a pinned ref |

### App installers (install only, never config)

See [why app *configuration* stays out of the org](#why-the-org-does-not-own-app-configuration).

| Library | Status | Module prefix | Purpose |
|---|---|---|---|
| `claymod-libs-nginx-install` | planned | `nginx` | Package + upstream repo + `nginx.conf` **skeleton only**, unit enabled |
| `claymod-libs-postgres-install` | planned | `postgres` | Package + upstream repo + data dir conventions, service enabled |
| `claymod-libs-docker-engine` | planned | `docker` | Engine install, `docker` group, service, daemon defaults |

## Library details

### claymod-libs-pkg

The installation layer everything else composes on.

```pkl
import "modulepath:/pkg/packages.pkl"

new pkg.Installed {
  name = "nginx"
  packages { "nginx" "curl" }
}
new pkg.Repo {
  name = "nginx-stable"
  url = "https://nginx.org/packages/debian"
  key = "https://nginx.org/keys/nginx_signing.key"
  format = "deb"          // deb | rpm
}
```

Planned resources: `pkg.Installed`, `pkg.Absent`, `pkg.Repo` (third-party
repo + GPG key + pin), `pkg.Updated`. Backends detected at run time:
apt (deb), dnf/yum (rpm), apk (Alpine), pacman (Arch), brew (macOS).
Idempotence via the native query of each backend (`dpkg-query -W`,
`rpm -q`, `apk info -e`) — never by re-running the installer.

### claymod-libs-systemd

Closes the gap between "manage a unit" and "own a unit file".

```pkl
import "modulepath:/systemd/units.pkl"

new systemd.UnitFile {
  name = "myapp.service"
  source = "units/myapp.service.tmpl"   // Template → /etc/systemd/system
  vars { ["binary"] = "/usr/local/bin/myapp" }
}
new systemd.Timer {
  name = "backup.timer"
  source = "units/backup.timer"
  unit = "backup.service"
}
```

`daemon-reload` is emitted once per playbook (guarded by a hash of the
unit files it changed), not once per resource.

### claymod-libs-baseline

A single import that applies the org's opinion of a "finished" server:
hostname, timezone, chrony/NTP client, journald size limits,
unattended-upgrades toggle, a standard `/etc/motd` banner. Every
component is overridable; the library is a starting point, not a policy
engine. Composes `std.files`, `std.sysctl`, `std.cron`, `std.assert`.

## Why the org does not own app configuration

Docker Official Images work because an image is an **immutable
artifact** with the configuration problem externalized (you mount your
own `nginx.conf`). A configuration module cannot freeze: modeling
nginx's or apache's config space turns into a parameter framework (see
`puppetlabs-apache`) with a version matrix of app × distro × claymod,
and a security-response duty on every upstream CVE. In claymod a
playbook *is* the configuration, so an org module competes with a
playbook that always fits the user's needs better.

So the org maintains:

1. **Infrastructure** — `pkg`, `systemd`, `baseline`: stable API, reused
   by nearly every playbook.
2. **The installation layer** of popular apps — repos, keys, pinned
   versions, unit enabled: high churn, distro-specific, no glory.
3. **Trusted examples** — reference compositions (nginx site, reverse
   proxy + TLS, postgres) in `claymod-examples`, meant to be **forked**,
   not depended on. Documentation that executes.

Configuration stays in your playbook:

```pkl
new files.Template { name = "site"; source = "nginx/site.conf.tmpl"; dest = "/etc/nginx/sites-enabled/site.conf" }
new service.Unit    { name = "nginx"; unit = "nginx"; state = "restarted"; enabled = true; dependsOn { "site" } }
new assert.PortListening { name = "nginx-up"; port = 80; dependsOn { "nginx" } }
```

## Community libraries

None listed yet. To list one, see [Submitting a library](#submitting-a-library).

## Using a library

```yaml
# claymod.project.yaml (in your playbook repo; discovered by walking up)
version: 1
libraries:
  - name: pkg                       # import prefix: modulepath:/pkg/…
    git: https://github.com/Claymod/claymod-libs-pkg.git
    ref: v1.2.0                     # pin a tag or commit — always
    path: pkl
```

```sh
claymod lib list       # cache state + resolved commits
claymod lib sync       # clone/refresh
claymod lib sync --offline   # air-gapped: reuse the cache, never network
```

Playbook commands sync automatically on evaluate. Air-gapped flow: sync
on a connected machine, carry `CLAYMOD_CACHE_DIR`, point the target
host at the copy.

Pin a **tag or commit**, never a branch, in anything you expect to
reproduce. Branch refs re-fetch on every sync by design.

## Submitting a library

Open an issue on the main repo with the git URL, the module prefix and
the intended tier. Listing requires:

- **Layout** — modules under `pkl/<prefix>/…`; `path: pkl` in the
  project entry. The prefix must not be `claymod` (reserved for the
  std) and must be unique in the index.
- **Immutable tags** — semver, never moved or force-pushed. Consumers
  pin, so a moved tag is a supply-chain incident, not a bug.
- **Idempotence** — every resource is safe to apply twice and reports
  `changed=false` the second time. Use guards (`onlyIf`/`unlessIf`)
  rather than "it usually works".
- **No secrets in module code** — no tokens, keys or passwords. Pass
  them as playbook `vars` or fetch them per host.
- **Visible commands** — everything the library runs is a normal
  command op, so `claymod playbook apply --verbose` shows it. Nothing
  hidden behind an opaque helper.
- **CI** — validates every module with the pkl CLI and applies a test
  playbook against the docker simulation (`simulation/`) on each
  release.
- **LICENSE** and a README stating the supported claymod versions,
  the distros tested, and each resource's idempotence guarantee.
- **Safety** — destructive resources (anything deleting data, disk or
  accounts) carry a default of "no" and an explicit opt-in field.

## Maintenance and compatibility policy

- **Renames are breaking.** Never rename an imported module path
  (`modulepath:/pkg/…`) or a resource `type` without a major tag. Add
  the new name, keep the old one, deprecate in the README, remove at
  the next major.
- **Additive within a minor.** New optional fields are fine; changing
  a default is a minor bump with a README note, removing a field is a
  major.
- **Security fixes ship as a patch on every supported minor**, and the
  index entry notes the supported range.
- **Abandonment** — an unmaintained official library is marked
  `deprecated` here, then moved to Community or removed. Its tags stay
  up, so existing pins keep working.

## See also

- [playbooks.md](playbooks.md) — authoring guide and the std reference
- [playbooks.md § Libraries](playbooks.md#libraries) — the mechanism
- [`examples/`](../examples/) — std-only reference playbooks
