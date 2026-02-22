# Coulson

A macOS local development gateway. Say goodbye to `localhost:port` — each project gets its own domain, ready to use on first visit with automatic startup.

One solution covering local, LAN, and public access — `.local` domains let phones and nearby devices connect directly, and a single command generates a public URL via Tunnel. Works great with AI IDEs like Cursor and Windsurf.

## Features

- **Zero-config routing** — directory/file name becomes the domain (`myapp` → `myapp.coulson.local`)
- **Auto-managed Python ASGI** — starts on first request, stops after idle timeout
- **Auto-managed Node.js** — detects package manager and start script, starts on first request
- **Static directory hosting** — just drop a `public` directory
- **Multi-route** — path-prefix routing to different backends under one domain
- **mDNS** — `.local` domains work out of the box, LAN and mobile devices connect directly
- **Cloudflare Tunnel** — one command generates a public URL for sharing
- **Web Dashboard + Menu bar app** — visual management

## Install

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
sudo coulson trust --pf
```

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

## Management

- **Web Dashboard**: `http://coulson.local:18080`
- **CLI**: `coulson ls`, `coulson add`, `coulson restart`
- **Menu bar app**: Coulson.app menu bar icon

## Configuration

Supports TOML config file (`~/.config/coulson/config.toml`) and environment variables. See [example](config.example.toml).

Priority: defaults < config file < environment variables.

## Built With

- [Rust](https://www.rust-lang.org/) + [Pingora](https://github.com/cloudflare/pingora) (reverse proxy)
- [Swift](https://www.swift.org/) (macOS menu bar app)
- [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/) (public sharing)

## Disclaimer

This project is not affiliated with Cloudflare. It uses official Cloudflare APIs and respects all rate limits and account restrictions. Users are responsible for complying with [Cloudflare's Terms of Service](https://www.cloudflare.com/terms/).

## License

See [LICENSE](LICENSE) for details.
