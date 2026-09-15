# Coulson

Coulson is a local development gateway that gives every project its own domain — `myapp.coulson.local` instead of `localhost:3000`. Apps start automatically on the first request and stop when idle, so you never hunt for a free port or kill a stray process again.

It's built for how people actually develop now: many projects running at once, and AI assistants driving them. When you tell Cursor, Claude Code, or Windsurf "restart myapp", it runs one deterministic command — `coulson restart myapp` — with no port to guess, no process to find, and no orphaned file watchers or bundlers left hogging ports. One tool covers local, LAN, and public access: `.local` domains let phones and nearby devices connect directly, and a single command exposes a public URL over Cloudflare Tunnel.

It replaces the `localhost:port` mess — and the stack of `puma-dev` / `pow` / `ngrok` / `Caddy` configs you'd otherwise stitch together — with one zero-config gateway for Python (ASGI), Node.js, Docker Compose, and static sites.

## Why Not Just `localhost:port`?

Every project on `localhost` shares the same origin. This causes real problems:

- **Cookies collide** — session tokens, JWTs, and auth cookies from one project leak into another, causing mysterious login loops and 403 errors
- **Saved passwords mix up** — the browser autofills credentials from project A into project B because they're both `localhost`
- **Browser history is useless** — `localhost:3000`, `localhost:3001`, `localhost:8080`... which project was which?
- **localStorage/IndexedDB overlap** — data from different projects stomps on each other when they use the same keys
- **Port conflicts** — "address already in use" when two projects default to the same port; you waste time hunting which process to kill
- **Remembering ports** — was it `:3000` or `:3001`? You end up grepping configs or checking `lsof`
- **AI coding gets confused too** — when you tell Cursor or Claude Code "restart my server", the AI has to figure out which port, which process, which command — and often gets it wrong

Coulson gives every project its own domain (`myapp.coulson.local`). Cookies, storage, passwords, and history are isolated by the browser automatically — the way they were designed to work. And when you tell your AI assistant "restart myapp", it just runs `coulson restart myapp` — no ports to remember, no processes to hunt down. The entire process group is killed cleanly (SIGTERM → SIGKILL), so child processes like file watchers, worker threads, and bundlers don't linger as orphans hogging ports.

## Features

- **Zero-config routing** — directory/file name becomes the domain (`myapp` → `myapp.coulson.local`)
- **Auto-managed Python ASGI** — starts on first request, stops after idle timeout
- **Auto-managed Node.js** — detects package manager and start script, starts on first request
- **Auto-managed Docker Compose** — `docker compose up` on first request, `down` on idle
- **Static directory hosting** — just drop a `public` directory
- **Multi-route** — path-prefix routing to different backends under one domain
- **`.coulson.toml`** — per-app configuration for routes, env, hooks, and proxy options
- **Lifecycle hooks** — run scripts or fire webhooks on app start/stop/ready events
- **mDNS** — `.local` domains work out of the box, LAN and mobile devices connect directly
- **Cloudflare Tunnel** — one command generates a public URL for sharing
- **Web Dashboard + Menu bar app** — visual management

![Request Inspector](https://coulson.hola.ac/assets/screenshot-inspector.png)

## Try It in 30 Seconds

Point Coulson at a project and open its domain — that's the whole loop:

```bash
ln -s ~/Projects/myapp ~/.coulson/myapp   # any Python ASGI / Node.js / Docker Compose / static project
open http://myapp.coulson.local           # first request auto-starts it; idle apps stop themselves
```

No port to pick, no server to start by hand, no config file required. Tell your AI assistant "restart myapp" and it runs `coulson restart myapp`.

## How It Compares

Coulson folds the jobs of a local reverse proxy, a process manager, and a tunnel into one zero-config tool. The closest alternatives each solve only part of it:

| | Coulson | puma-dev / pow | Laravel Valet | ngrok / cloudflared |
|---|---|---|---|---|
| Per-project local domain | ✅ | ✅ | ✅ | — |
| Languages | Python, Node.js, Docker, static | Rack / Ruby only | PHP only | any (proxy only) |
| Auto start on request | ✅ | ✅ | always-on | — |
| Idle stop | ✅ | ✅ | — | — |
| LAN / mobile access (mDNS) | ✅ | — | — | — |
| Public URL (Tunnel) | ✅ built-in | — | — | ✅ (this is all it does) |
| AI-assistant control | ✅ `coulson restart <app>` | — | — | — |

It's the only one of these built around language-agnostic apps and first-class AI-assistant control.

## How It Works

Coulson runs as a single unprivileged daemon that combines a reverse proxy, a process supervisor, and a name-resolution layer. The design goal: nothing surprising and nothing privileged happens at request time.

**Routing.** Each entry in your apps directory (`~/.coulson/<name>`, a directory or symlink) becomes the host `<name>.<suffix>` (default suffix `coulson.local`). Coulson advertises `.local` names over mDNS so your OS resolves them with no `/etc/hosts` edits; by default they point at loopback. The proxy matches a request's `Host` header to an app.

**Lazy lifecycle.** Apps aren't running until needed. On the first request, Coulson detects the app's type (Python ASGI, Node.js, Docker Compose, Procfile, or static), cold-starts it, and holds the request behind a loading page until the process is ready — then proxies through. After `idle_timeout` (default 15 minutes) with no traffic, the process is stopped; the next request starts it again. This is why "restart myapp" is simply "stop the process" — the next visit recreates it.

**No root at request time.** TLS uses a CA generated locally on your machine, not a public one. Privileged ports (80/443) are never bound by the daemon itself — on macOS a tiny socket-activated forwarder holds them, on Linux a capability or sysctl lets the daemon bind them directly. The proxy, your apps, and tunnels all run as your normal user. See [Security & Permissions](#security--permissions) for the full model.

Built on [Pingora](https://github.com/cloudflare/pingora), Cloudflare's production Rust proxy framework.

## Install

> **Platform:** Coulson's core — proxy, process management, routing, mDNS, and Tunnel — is cross-platform Rust. The packaged app and one-click setup below ship for macOS today; on other platforms, run the `coulson` daemon directly.

Download [Coulson.app](https://github.com/ratazzi/coulson/releases) and open it. The daemon starts automatically.

Click **Install Command Line Tool...** in the menu bar to use the `coulson` command in the terminal.

### Trust Certificate (optional)

Generate a local CA certificate and add it to the system keychain for HTTPS support:

```bash
sudo coulson trust
```

### Port Forwarding (optional)

Take over ports 80/443 so you can omit port numbers when accessing:

```bash
sudo coulson trust --forward
```

## Security & Permissions

The privileged and security-sensitive parts are deliberately small, auditable, and reversible.

**TLS certificates — generated locally, never uploaded.** Coulson generates its own CA and per-domain certificates on your machine, with no external CA and no network call. The CA private key is written under `~/.config/coulson/certs` with owner-only permissions and never leaves your machine. `sudo coulson trust` adds only the *public* CA certificate to the system keychain so the browser trusts `https://*.coulson.local`.

**Port 80/443 takeover — a separate, forward-only process; no root at runtime.** `coulson trust --forward` does *not* make the daemon run as root or bind privileged ports. It installs a launchd daemon that holds 80/443 via **socket activation**: launchd binds the ports and hands the already-open sockets to a tiny `coulson forward` process that does nothing but forward bytes to Coulson's high ports (`18080`/`18443`). The forwarder never calls `bind()` on a privileged port and holds no privileges while running. The main daemon stays an unprivileged user process.

**Where `sudo` is actually required — one-time setup only.** Exactly two commands need root, both one-time:
- `sudo coulson trust` — add the CA to the system keychain
- `sudo coulson trust --forward` — install the launchd forwarding daemon (writes `/Library/LaunchDaemons/com.coulson.forward.plist`)

Every other command — `serve`, `add`, `start`, `restart`, `tunnel`, … — runs as your normal user. If a command needs root and you forgot `sudo`, it exits with a clear message naming the exact command to run; it never silently escalates.

**Uninstall / cleanup.**
- Forwarding daemon: `sudo launchctl bootout system /Library/LaunchDaemons/com.coulson.forward.plist && sudo rm /Library/LaunchDaemons/com.coulson.forward.plist`
- Trusted CA: remove the "Coulson" certificate in Keychain Access.
- State and config live under `~/.local/state/coulson` (db, control socket) and `~/.config/coulson` (certs, `config.toml`) — delete to reset.

> **Platform note:** the one-command privileged setup above (launchd, keychain) is macOS-specific. On Linux you don't need the separate forwarder at all — point Coulson directly at the privileged ports (`COULSON_LISTEN_HTTP=0.0.0.0:80`, `COULSON_LISTEN_HTTPS=0.0.0.0:443`) and let the unprivileged daemon bind them via any standard mechanism: `AmbientCapabilities=CAP_NET_BIND_SERVICE` in the systemd unit, `setcap 'cap_net_bind_service=+ep' coulson`, or the `net.ipv4.ip_unprivileged_port_start=0` sysctl. This is configuration, not a missing feature — the macOS forwarder exists only because launchd is macOS's clean way to hand an unprivileged process a pre-bound socket. A turnkey `coulson trust --forward` equivalent for Linux (a generated systemd unit) isn't shipped yet; the steps above are manual. See the Platform note under [Install](#install).

## Quick Start

Listens on `127.0.0.1:18080` (HTTP) and `127.0.0.1:18443` (HTTPS) by default.

### Port Proxy

Map an existing service to a local domain:

```bash
echo 3000 > ~/.coulson/myapp
```

```bash
curl -i http://myapp.coulson.local:18080/
```

### Python ASGI App

Example project structure:

```
~/Projects/hello/
  app.py              # async def app(scope, receive, send): ...
  pyproject.toml
  .venv/bin/uvicorn
```

Symlink to Coulson directory:

```bash
ln -s ~/Projects/hello ~/.coulson/hello
```

```bash
curl -i http://hello.coulson.local:18080/
```

First request auto-starts uvicorn. Reaped after 15 minutes idle.

### Node.js App

Example project structure:

```
~/Projects/myapi/
  index.js            # const http = require("http"); ...
  package.json        # scripts: { "dev": "bun run index.js" }
  bun.lock
```

Symlink to Coulson directory:

```bash
ln -s ~/Projects/myapi ~/.coulson/myapi
```

```bash
curl -i http://myapi.coulson.local:18080/
```

First request auto-detects the package manager (bun/pnpm/yarn/npm), allocates a free port via the `PORT` environment variable, and runs the `dev` or `start` script. Reaped after 15 minutes idle.

### Procfile App

Projects with a `Procfile` (or `Procfile.dev`) containing a `web:` process are auto-managed:

```
~/Projects/myapp/
  Procfile            # web: bundle exec rails server -p $PORT
```

```bash
ln -s ~/Projects/myapp ~/.coulson/myapp
```

```bash
curl -i http://myapp.coulson.local:18080/
```

First request allocates a free port via `$PORT`, runs the `web` command, and proxies traffic. `Procfile.dev` takes priority over `Procfile` when both exist.

To start companion processes (workers, etc.) alongside the web process, add to `.coulsonrc`:

```
COULSON_MANAGED_SERVICES=web,worker
```

All listed process types from the Procfile are started together and share the same lifecycle — idle timeout reaps the entire group.

### Docker Compose App

Projects with a `compose.yml` (or `docker-compose.yml`) are auto-managed:

```
~/Projects/myapp/
  compose.yml         # services: web: ...
```

```bash
ln -s ~/Projects/myapp ~/.coulson/myapp
```

```bash
curl -i http://myapp.coulson.local:18080/
```

First request runs `docker compose up -d --build`. Idle containers are stopped via `docker compose down` after the idle timeout. Port discovery uses compose port mappings or `$PORT` env var.

### Static Directory

Projects with a `public` subdirectory are automatically served as static files:

```
~/Projects/docs/
  public/
    index.html
    style.css
```

```bash
ln -s ~/Projects/docs ~/.coulson/docs
```

```bash
curl -i http://docs.coulson.local:18080/
```

Changes are picked up automatically within 2 seconds.

### `.coulsonrc` — Per-App Environment

Add a `.coulsonrc` file to any managed app directory to set environment variables:

```
# ~/Projects/myapp/.coulsonrc
PORT=4000
DATABASE_URL=postgres://localhost/myapp_dev
```

When `PORT` is set, the app always starts on that fixed port instead of auto-allocating one. Standard dotenv format (parsed by `dotenvy`): `KEY=VALUE`, `#` comments, quoting, `export` prefix, and `${VAR}` interpolation (escape a literal `$` as `\$` or single-quote it).

`${VAR}` interpolation resolves against earlier same-file entries **and the daemon's own environment** — and a matching process-env var takes precedence over a same-file definition. In practice this only matters in development: run the daemon under a service manager (launchd/systemd) and it executes in a clean, minimal environment, so interpolation only sees infrastructure vars. When you start the daemon from an interactive shell, any variable you `export`ed there is visible to `${VAR}` and can shadow a same-file value.

`.coulsonrc` is the **manual, local override** file and has the **highest precedence** — it wins over `.coulson.toml [env]` and `env_url`. The intended split: `.coulson.toml` holds programmatic/provisioned config (committed), while `.coulsonrc` holds hand-edited local overrides (typically gitignored).

**Environment precedence** (lowest → highest):

```
provider defaults  <  .coulson.toml [env]  <  env_url  <  .coulsonrc
```

Rationale: committed `[env]` provides defaults/placeholders; `env_url` delivers authoritative remote secrets that override those defaults; `.coulsonrc` is the hand-edited local override that wins over everything (handy for pointing at a local DB while debugging). Below the provider defaults sit the user login-shell rc and the daemon's own environment.

`coulson env` reports the winning effective value from these layers together with its source and scope. `app` settings are injected into managed app processes; `coulson` settings such as `COULSON_MANAGED_SERVICES` are consumed by Coulson itself and are not injected into those processes. Companion selection happens before `env_url` is fetched, so `COULSON_MANAGED_SERVICES` is only supported in `.coulson.toml [env]` and `.coulsonrc`; an `env_url` value is ignored. `--bare` prints both scopes as `KEY=value` lines.

### `.coulson.toml` — Per-App Configuration

For full control, add a `.coulson.toml` in the app directory:

```toml
name = "myapp"
domain = "myapp"            # prefix only, suffix appended at runtime
kind = "asgi"               # asgi, node, procfile, docker

# Process
module = "mymodule:app"     # ASGI module
server = "uvicorn"          # ASGI server

# Proxy options
port = 5006
timeout = 5000
cors = false
spa = false
trusted_forwarded_hosts = ["*.example.com", "app.example.net"]

# Remote env injection (fetched before each cold start)
env_url = "https://vault.example.com/env/myapp"
env_url_headers = { Authorization = "Bearer xxx" }

# Environment variables
[env]
DATABASE_URL = "postgres://localhost/myapp_dev"

# Multi-route
[[routes]]
path = "/api"
target = "127.0.0.1:3000"
timeout = 30000

# Lifecycle hooks
[hooks]
[hooks.app_ready]
run = "mise run db:migrate"
webhook = "https://hooks.slack.com/xxx"
```

### Global Hooks

Coulson fires hooks on app lifecycle events. Global hooks are executable scripts in `~/.coulson/hooks/`:

```
~/.coulson/hooks/
  app_ready             # runs when any app becomes ready
  app_stop              # runs when any app stops
  scan_complete         # runs after directory scan
```

Per-app hooks are configured via `[hooks]` in `.coulson.toml` (see above). Each hook receives `COULSON_APP_NAME`, `COULSON_APP_URL`, `COULSON_APP_DOMAIN`, and other context as environment variables.

Per-app events: `app_add`, `app_remove`, `app_start`, `app_ready`, `app_stop`, `app_idle`, `tunnel_start`, `tunnel_stop`. Global-only events: `scan_complete`.

## Cloudflare Tunnel

Start/stop tunnels via CLI:

```bash
coulson tunnel start myapp
coulson tunnel stop myapp
```

Also available via the Web Dashboard or the menu bar app.

### Quick Tunnel

No configuration needed — assigns a random `*.trycloudflare.com` URL, great for ad-hoc sharing. Requires `cloudflared`:

```bash
brew install cloudflared
```

### Named Tunnel (recommended)

Configure wildcard DNS for your own domain (e.g. `*.example.com`) pointing to a Cloudflare Tunnel. Coulson automatically routes subdomains to local projects:

- `myapp.example.com` → local `myapp`
- `hello.example.com` → local `hello`

All projects share one Tunnel connection — no per-app setup needed, new projects are instantly accessible from the public internet.

### Trusted Forwarded Host

When a tunnel sits behind an ingress worker that supplies the visitor's
original `X-Forwarded-Host`, configure the allowlist on that app in its
`.coulson.toml`:

```toml
trusted_forwarded_hosts = ["*.example.com", "app.example.net"]
```

The default empty list ignores incoming `X-Forwarded-Host` values. Each app
has its own list, so a host trusted by one app is not trusted by another.
Exact patterns match one host; `*.example.com` matches exactly one leading DNS
label. Coulson reads this value directly from the app's `.coulson.toml` rather
than storing a copy in SQLite; edits are picked up on subsequent tunnel
requests, including after every app restart.

This option is not intended for Quick Tunnels (`*.trycloudflare.com`), which
have no fronting ingress worker.

## Management

- **Web Dashboard**: `http://coulson.local:18080`
- **CLI**: `coulson ls`, `coulson add`, `coulson restart`, `coulson open`
- **Menu bar app**: Coulson.app menu bar icon

## Configuration

Supports TOML config file (`~/.config/coulson/config.toml`) and environment variables. See [example](config.example.toml).

Priority: defaults < config file < environment variables.

## Command Reference

`coulson` has no global flags — all configuration comes from environment variables and `~/.config/coulson/config.toml` (see [Configuration](#configuration)). Run `coulson <command> --help` for the authoritative flag list. Most app commands take an optional `[name]` (app name or domain); omit it to match the current working directory.

**Apps**

| Command | What it does |
|---|---|
| `coulson serve` | Start the daemon (proxy + control + scanner) |
| `coulson scan` | One-shot scan of the apps directory |
| `coulson ls [--managed\|--manual] [--domain <d>]` | List registered apps |
| `coulson add [name] [target] [--link <path>] [--tunnel]` | Add an app (alias: `recruit`) |
| `coulson rm [name]` | Remove an app (alias: `dismiss`; prompts to confirm) |
| `coulson warnings` | Show scan warnings |
| `coulson doctor [--pf]` | Check system health |

**Process**

| Command | What it does |
|---|---|
| `coulson start\|stop\|restart [name]` | Start / stop / restart a managed process |
| `coulson ps` | Show running managed processes |
| `coulson status [name] [--json]` | Show daemon-reported application lifecycle status; omit name to list all apps |
| `coulson wait [name] [--timeout 30s] [--json]` | Wait for one app to become ready without starting it; omit name to match CWD |
| `coulson keep-awake [name] [--for 1h\|--until-cleared\|--clear] [--json]` | Temporarily suspend idle sleep for a managed app; starts it if needed |
| `coulson logs [name] [-f] [-n <lines>] [--path]` | Show logs (`--path` prints the log file path) |
| `coulson env [name] [--bare\|--json] [--preview] [--no-remote]` | Show effective app and Coulson environment configuration with source and scope |
| `coulson open [name]` | Open the app URL in the default browser |
| `coulson attach [name]` | Attach to the process's tmux session |

**Sharing & TLS**

| Command | What it does |
|---|---|
| `coulson trust [--forward] [--force]` | Trust the local CA, optionally install forwarding — needs `sudo` |
| `coulson share <name> [--expires <dur>]` | Generate a sharing URL (default expiry `24h`) |
| `coulson unshare <name>` | Disable share auth for an app |

**Tunnel**

| Command | What it does |
|---|---|
| `coulson tunnel status` | Show tunnel status |
| `coulson tunnel start [name] [--mode quick\|global\|named]` | Activate a tunnel for an app |
| `coulson tunnel stop [name]` | Deactivate a tunnel (keeps config) |
| `coulson tunnel setup --domain <d> [--tunnel-name <n>] [--api-token <t>] [--account-id <id>]` | Create a global named tunnel via the Cloudflare API |
| `coulson tunnel teardown [--api-token <t>]` | Delete the global named tunnel |
| `coulson tunnel connect [--token <t>] [--domain <d>]` / `disconnect` | Connect / disconnect the global named tunnel |
| `coulson tunnel app-setup <name> --domain <d> [--token <t>]` / `app-teardown <name>` | Per-app named tunnel |
| `coulson tunnel login <token>` / `logout` | Save / remove a Cloudflare API token in the keychain |

## Behavior & Failure Modes

Written for scripting and AI agents that need predictable commands and failure paths.

**Exit codes.** Commands return `0` on success and `1` for operational failures. `coulson wait` additionally returns `124` when its deadline expires. Invalid CLI arguments exit `2`. Errors are printed to **stderr**; `wait --json` instead includes its wait outcome and error in the JSON response on stdout.

**Non-interactive / CI / agents.** Only one command prompts: `coulson rm` asks `Remove <app>? [y/N]`. With no TTY (piped/CI/agent), the read hits EOF, defaults to **No**, prints `Cancelled.`, and exits `0` — it never hangs and never deletes. There is no `--yes` bypass, so **`rm` is effectively a safe no-op in non-interactive contexts.** Every other command is non-interactive and never requires a TTY.

**First-request auto-start (HTTP).** A cold app returns predictable statuses:
- Browser (`Accept: text/html`): **503** loading page with `Retry-After: 1` while starting.
- Non-browser client: polls up to **30s**, then **504** "Gateway Timeout" if still not ready.
- App can't be resolved/started, or its process exited: **502** "Bad Gateway".

The underlying error (e.g. `uvicorn not found`) is written to the app's log file, not the HTTP body — read it with `coulson logs <app>`.

**Runtime detection — and what makes it fail.**

| Runtime | Detected when | Start fails if |
|---|---|---|
| Python ASGI | `app.py`/`main.py` + `pyproject.toml`/`requirements.txt` | `uvicorn` not in `.venv/bin`, `venv/bin`, or `PATH` |
| Node.js | `package.json` with a `dev` or `start` script | package manager / `node` not in `node_modules/.bin` or `PATH` |
| Docker Compose | a `docker-compose.yml`/`compose.yml` (a bare `Dockerfile` is **not** enough) | `docker` not in `PATH`, or `docker compose up` exits non-zero |
| Procfile | a `web:` line in `Procfile` | no `web:` process type |
| Rack (`config.ru`) | detected, but **not yet implemented** | always — every start reports `Rack provider is not yet implemented` |

**Gotcha — silent static fallback.** If *nothing* above is detected for a directory, Coulson does **not** error; it serves the directory as static files. A misconfigured app (e.g. a missing `pyproject.toml`) can therefore quietly become a static site instead of failing. Run `coulson warnings` and `coulson doctor` to catch this.

**Application status.** `coulson status` lists all apps; pass a name or stored domain to select one. `--json` returns the same `{ "apps": [...] }` response as the `app.status` control method. Each entry contains `app_id`, `name`, `domain`, `state`, Unix-second timestamps (`since`, `started_at`, `ready_at`, nullable when unavailable), and `last_error` (code, safe diagnostic message, timestamp, and an exit code when the backend provides it). A successful query exits 0 even when an app is failed; a missing app or unavailable daemon exits 1. Querying status never starts an app or resets its idle timer.

The macOS menu and native dashboard display the same daemon states:
- `sleeping`: enabled managed app awaiting its next start.
- `starting`: startup is in progress; the backend has not passed readiness yet.
- `ready`: the managed backend accepted a TCP/Unix-socket connection during startup, or an enabled static directory is available.
- `failed`: startup failed, timed out, or the primary process unexpectedly exited. A live companion worker does not make the app ready.
- `disabled`: the app is administratively disabled, regardless of any retained process state.
- `unknown`: external TCP/Unix-socket backends have no managed lifecycle. The macOS app also shows unknown when status is unavailable, including with older daemons.

Startup readiness timeout is **120s for Docker, 30s otherwise**. The daemon observes tracked processes approximately once per second; slow process operations can delay observation. Readiness is a startup check, not ongoing application-level health monitoring. Failure details remain in memory until the daemon restarts, the app is deliberately stopped, or its identity changes; retries can retain the last error alongside the new state. The next request can retry a failed app. There is no automatic retry backoff in this version. Raw environment values and subprocess output are not included in status responses.

**Waiting for readiness.** `coulson wait myapp --timeout 30s` observes `app.status` every 250ms. It waits through `sleeping` and `starting`, succeeds on `ready`, and fails immediately on `failed`, `disabled`, or `unknown`. An unreachable daemon, missing/replaced app, or invalid response is an error. The default timeout is 30 seconds; positive integer values support `ms`, `s`, `m`, and `h`, with bare numbers interpreted as seconds. The deadline covers connecting, sending, receiving (including a stalled daemon), and polling delays. Waiting does not start or restart an app, send it traffic, or reset its idle timer.

```bash
coulson start myapp && coulson wait myapp --timeout 30s
coulson wait myapp --timeout 2m --json
```

`wait --json` emits one final object: `ready` (boolean), `app` (the last observed status, or null), and `error` (null on success, otherwise `{ "code": "...", "message": "..." }`). Error codes include `timeout`, `app_failed`, `app_disabled`, `status_unknown`, `query_failed`, `invalid_response`, and `app_replaced`. A ready app succeeds even if its status retains a historical `last_error`. A sleeping app with no concurrent start will remain sleeping until the wait times out.

**Keep awake during development.** Choose **Keep Awake → For 1 Hour** or **Until Turned Off** in the macOS app's application submenu. The menu and native app details show the remaining time; **Resume Automatic Sleep** clears the override. CLI equivalents:

```bash
coulson keep-awake myapp --for 1h
coulson keep-awake myapp --until-cleared
coulson keep-awake myapp --clear
coulson status myapp --json
```

The default duration is one hour. Custom CLI durations use the same units as `wait`, rounded up to whole seconds. Only enabled managed apps support keep awake. Setting it schedules startup if the app is sleeping; the command acknowledges the setting, and `status`/`wait` report startup success or failure. It does not automatically restart crashed apps or prevent computer sleep. Ordinary app restarts preserve the setting; explicit process stop, app disable/delete, and daemon restart clear it. Overrides are in memory for the current daemon session, including the until-cleared mode.

Expiry or clearing restores the original idle rule without resetting the last-activity time: an already-idle app can be reaped on the next idle sweep (normally every 30 seconds). `app.status` includes `keep_awake: null` when inactive, `{ "expires_at": <Unix seconds> }` for a timed override, or `{ "expires_at": null }` until cleared. The `app.keep_awake` RPC accepts `app_id` and a mode of `for` (with positive `seconds`), `until_cleared`, or `off`, and returns `{ "app": <status> }`.

## Name Resolution & Troubleshooting

**How `.local` names resolve.** Coulson advertises each app's `.local` domain over mDNS (plus the bare suffix and `dashboard.<suffix>`). By default a name resolves to **loopback** (`127.0.0.1`), so it works on the machine running Coulson with zero configuration.

**LAN / mobile access is per-app and opt-in.** To let phones and other devices reach an app, enable LAN access for that app — it then advertises your real LAN IP instead of loopback. This also requires the proxy to listen on `0.0.0.0` (the default), not loopback; `coulson doctor` reports which. Boundaries worth knowing:

- **Only `.local` names are advertised.** If you set a custom non-`.local` `COULSON_DOMAIN_SUFFIX`, Coulson does no mDNS — you must provide DNS or `/etc/hosts` entries yourself.
- **VPNs and virtual interfaces are skipped.** LAN-IP detection ignores tunnel/VPN/container interfaces (`utun`, `tun`, `ppp`, `wg`, `docker`, `bridge`, …), so an active VPN can leave LAN access without a usable address.
- **The network must pass mDNS multicast.** Many corporate/guest WiFi networks block multicast; other devices then can't resolve `.local` even though the local machine still can.
- **The other device must speak mDNS.** macOS/iOS do natively; Linux needs `avahi-daemon` + `nss-mdns`; Windows needs Bonjour.

**First stop for any problem: `coulson doctor`.** It checks, in order: apps directory, database, daemon reachability, proxy port, `.local` resolution (mDNS health), Cloudflare token, scan warnings, LAN-access listen address, and TLS certificates (add `--pf` to also verify port forwarding). Each line is a pass/fail with the specific path or value, so a red line points straight at the broken piece.

| Symptom | Likely cause / fix |
|---|---|
| `.local` name doesn't resolve at all | mDNS unhealthy — run `coulson doctor`; confirm the daemon is running (`coulson serve`) |
| Resolves on your machine but not on a phone | per-app LAN access not enabled, on a VPN, or WiFi blocks multicast |
| Browser shows a TLS warning | CA not trusted — run `sudo coulson trust` |
| App serves files instead of running | nothing was detected — see the static-fallback gotcha above; run `coulson warnings` |
| 502 / 503 / 504 on first visit | see [Behavior & Failure Modes](#behavior--failure-modes); read `coulson logs <app>` |
| Port 80/443 access fails | forwarding not installed — `sudo coulson trust --forward` (macOS); on Linux see the Platform note under Install |

## Built With

- [Rust](https://www.rust-lang.org/) + [Pingora](https://github.com/cloudflare/pingora) (reverse proxy)
- [Swift](https://www.swift.org/) (macOS menu bar app)
- [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/) (public sharing)

## Disclaimer

This project is not affiliated with Cloudflare. It uses official Cloudflare APIs and respects all rate limits and account restrictions. Users are responsible for complying with [Cloudflare's Terms of Service](https://www.cloudflare.com/terms/).

## License

See [LICENSE](LICENSE) for details.
