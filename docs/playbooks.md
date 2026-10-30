# Playbook authoring guide

Playbooks are PKL documents that declare *what* a set of hosts should
look like. They are compiled on the control server to primitive ops and
pushed to agents — you write intent, the pipeline decides the
operations.

## Anatomy

```pkl
amends "modulepath:/claymod/base.pkl"      // the claymod schema
import "modulepath:/claymod/std/files.pkl" // resource families

hosts { "web01" "web02" }                  // targets (exact names)
vars  { ["domain"] = "example.internal" }  // per-host template vars

resources {
  new files.Template {
    name = "app.conf"
    source = "templates/app.conf.tmpl"
    dest = "/etc/app.conf"
    mode = "0640"
    vars { ["port"] = "8080" }             // merged over playbook vars
  }
  new service.Unit {
    name = "app"
    unit = "myapp"
    state = "started"
    enabled = true
    dependsOn { "app.conf" }               // run after the config lands
  }
}
```

Rules learned the hard way (PKL specifics):

- The playbook **amends** `modulepath:/claymod/base.pkl` — one root
  document. The std schema is **embedded in the binary**: validate,
  plan and apply work from any working directory, no checkout needed.
  `CLAYMOD_SCHEMA_DIR` pins an on-disk copy of the schema instead;
  `--module-path` (repeatable) and `CLAYMOD_MODULE_PATH`
  (colon-separated) add extra lookup directories for external
  libraries.
- Amended properties **must not repeat type annotations** and may not
  introduce new non-local properties: `hosts`, `vars`, `resources` and
  `hostName` are declared in `base.pkl`.
- `dependsOn` refers to resource **names**; the planner topologically
  sorts resources (declaration order is only a tie-breaker). Dependency
  cycles are an error and name the cycle: `a -> b -> c -> a`.

## Resource reference

### std.files

| Resource | Purpose | Key fields |
|---|---|---|
| `files.Copy` | copy a static file | `source`, `dest`, `mode`, `owner`, `group`, `backup` |
| `files.Template` | render a Go template server-side | `source`, `dest`, `mode`, `vars`, `backup` |
| `files.Directory` | ensure a directory (or absence) | `path`, `mode`, `ensure` (`directory`/`absent`) |
| `files.Content` | write literal inline text | `content`, `dest`, `mode`, `owner`, `group`, `backup` |
| `files.Line` | ensure one exact line is present/absent | `path`, `line`, `ensure` (`present`/`absent`) |
| `files.Symlink` | ensure a symlink points at `target` | `path`, `target`, `force` |
| `files.Fetch` | download on the control server, ship like Copy | `url`, `dest`, `sha256?`, `mode`, `owner`, `group`, `backup` |

Paths: `source` is relative to the playbook's directory; `dest`/`path`
must be absolute on the host. `backup = true` keeps a `.bak` copy of
overwritten files.

Text-only file content: file bodies travel the wire as JSON strings, so
`Copy`, `Content`, `Template` and `Fetch` are for text files — binaries
would be corrupted by UTF-8 coercion.

`files.Line` matches the **full line** (`grep -x`): `"present"` appends
when missing (creating the file if needed), `"absent"` rewrites the file
without it — in place via `cat >`, so mode and owner survive. The line
must not contain a newline. `files.Symlink` relinks a wrong-target
symlink automatically; a non-symlink occupying `path` fails the apply
unless `force = true`. `files.Fetch` downloads at **compile time** on
the control server (60 s timeout, 64 MiB cap, `sha256` verified
server-side) — agents see only ordinary file ops.

### std.commands

| Resource | Purpose | Key fields |
|---|---|---|
| `commands.Shell` | run a command | `command` **or** `argv` (exactly one), `cwd`, `env`, `timeout` |
| `commands.Script` | write + run a script | `content`, `path`, `mode` (default `0755`) |

Guards (both resources): `onlyIf`, `unlessIf` (shell conditions),
`creates`, `removes` (path existence). A guarded command that should be
skipped reports `changed=false` — re-running a playbook is safe.

> `commands` is the imperative escape hatch: it runs with the agent's
> privileges. Prefer `files` where declarative is possible.

### std.service

| Resource | Purpose | Key fields |
|---|---|---|
| `service.Unit` | systemd unit management | `unit`, `state` (`started`/`stopped`/`restarted`/`reloaded`), `enabled` (nullable) |

`enabled` omitted/null leaves boot enablement unchanged.

### std.sysctl

| Resource | Purpose | Key fields |
|---|---|---|
| `sysctl.Sysctl` | set a runtime kernel sysctl | `key`, `value` |

Idempotent: skipped while `sysctl -n <key>` already reports `value`.
The recipe writes `sysctl 'key'='value'` — the form procps, busybox and
BSD sysctl all parse as a write (verified on macOS, alpine and debian).
**Runtime-only by design**: persistence across reboots is an explicit
`files.Content` write to `/etc/sysctl.d/<name>.conf`, which you compose
with `dependsOn`.

### std.cron

| Resource | Purpose | Key fields |
|---|---|---|
| `cron.Entry` | manage one crontab entry | `schedule`, `command`, `ensure` (`present`/`absent`) |

Installs into the **invoking user's** crontab (the agent's user,
typically root) via `crontab(1)` — deliberately not `/etc/cron.d`,
whose syntax and availability vary across distros. Each entry is
tagged with a trailing `# claymod:<name>` marker; the guard matches the
exact marked line, so updates replace and `ensure = "absent"` removes
exactly that resource's entries (foreign crontab lines are untouched).
`schedule` is a crontab(5) line (five fields or an `@daily`-style
shortcut); `schedule`, `command` and the resource name must be single
lines without `#` in the name. A missing crontab binary fails the op
with a clear stderr instead of silently succeeding.

## Templates

`files.Template` and `commands.Script` content render server-side with
Go `text/template` (`missingkey=error` — a typo fails the apply, never
produces a half-rendered file):

```
# {{.Host}}
listen_port = {{.Vars.port}}
```

- `.Host` — the target hostname (or `--host` override on apply).
- `.Vars` — playbook `vars` merged with the resource's own `vars`
  (resource wins).
- Functions: `file` (read a file relative to the playbook dir),
  `trimSpace`, `quote`, `default`, `lower`, `upper`. Deliberately
  minimal — no sprig.

## Workflow

```sh
claymod playbook validate playbook.pkl   # schema, names, deps, cycles
claymod playbook plan playbook.pkl       # dependency-ordered task list
claymod playbook apply playbook.pkl      # push to the targeted hosts
claymod playbook apply playbook.pkl --check   # dry run
```

Useful flags on all three commands: `--module-path <dir>` (repeatable;
extra lookup directories for external libraries — `CLAYMOD_MODULE_PATH`
adds colon-separated ones). Useful `apply` flags: `--limit web01,web02`
(subset), `--verbose` (per-op detail), `--check` (would-change only),
`--parallel N`, `--max-fail N` (failure policy).

Applies are **idempotent**: unchanged resources report `changed=false`,
so a re-run is cheap and safe. Per-host rendering means `{{.Host}}` and
per-host vars resolve per target — one playbook, many hosts.

## Examples

- [`examples/basic-setup/`](../examples/basic-setup/) — Copy + Template
  + Directory.
- [`examples/nginx/`](../examples/nginx/) — Template + service.Unit with
  a dependency.

Validate any of them right away:

```sh
claymod playbook validate examples/nginx/playbook.pkl
```
