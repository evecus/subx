<div align="center">
<br>
<img width="200" src="https://raw.githubusercontent.com/cc63/ICON/main/Sub-Store.png" alt="SubX">
<br>
<br>
<h2 align="center">Subx</h2>
</div>

A lightweight Sub-Store rewrite in Go (backend) + Vue 3 / Element Plus (web
frontend). Supports subscription management, node parsing/conversion, combined
subscriptions, and token-based sharing, with account/password login.

## Features

- **Subscription management**: add/edit/delete subscriptions (remote URL or
  local content), set custom User-Agent, define per-sub operators.
- **Combined subscriptions**: aggregate multiple subscriptions into one.
- **Node conversion**: parse SS / SSR / VMess / VLESS / Trojan / Hysteria /
  Hysteria2 / TUIC / WireGuard / AnyTLS / SOCKS / HTTP / Surge / Quantumult X /
  Clash / SSD / Base64 subs, and produce JSON, URI, Clash/Mihomo YAML, Surge,
  SurgeMac, Loon, Shadowrocket, Stash, Surfboard, Quantumult X, sing-box,
  V2Ray, Egern output.
- **Operators**: Useless/Region/Regex/Type/Conditional filters and
  Sort/Regex Sort/Regex Rename/Regex Delete/Handle Duplicate/Flag/Quick
  Setting/Resolve Domain operators.
- **Sharing**: generate time-limited or usage-count-limited tokens and share
  `sub` / `col` via public URLs.
- **Auth**: JWT login with bcrypt password hashing. The admin account is fixed
  by environment variables (default `admin`/`admin`); public registration and
  in-app password changes are disabled.
- **Security hardening**: per-IP rate limiting on login and on the public
  download/share endpoints, a constant-effort login path that doesn't leak
  whether a username exists, and baseline security response headers.

## Security

- **Login rate limiting**: `POST /api/login` is limited to 10 attempts per
  client IP per 15 minutes. Exceeding the limit returns `429 Too Many
  Requests` with a `Retry-After` header. A successful login resets the
  counter for that IP.
- **Download/share rate limiting**: `/download/:name`, `/share/sub/:name`,
  and `/share/col/:name` are limited to 120 requests per client IP per
  minute, to blunt share-token guessing and upstream-fetch abuse. (Share
  tokens themselves are 128-bit random values from `crypto/rand`, so this is
  a defense-in-depth measure, not the primary protection.)
- **Timing-safe-ish login**: an unknown username still runs a bcrypt
  comparison against a dummy hash, so response time doesn't reveal whether
  the account exists.
- **Security headers**: every response sets `X-Content-Type-Options:
  nosniff`, `X-Frame-Options: DENY`, and `Referrer-Policy: no-referrer`.
- **Startup warning**: if `password` is left at the default `admin`, the
  server logs a warning on startup. Change it before exposing the server to
  any network you don't fully trust.
- Rate limiting is in-memory and per-process: it resets on restart and isn't
  shared across multiple replicas. That's fine for the single-process,
  single-admin deployment this project targets; if you run multiple
  replicas behind a load balancer, put a rate limiter in front (e.g. at the
  reverse proxy) instead of relying on this one.

## Build

Backend (requires Go 1.23+). The frontend is embedded into the binary via
`go:embed`, so build the frontend first:

```sh
cd web
npm install
npm run build
cd ..
go build -o substore ./cmd
```

The resulting `substore` binary is self-contained (backend + web UI). The
frontend must be built before `go build`, since it's baked into the binary
via `go:embed`.

## Run

The admin account is fixed by environment variables. Defaults to
`admin` / `admin` when unset; set the env vars to override. The admin password
is reset from the env var on every start, so changing credentials is done by
restarting with new values. Public registration and in-app password change are
not supported.

```sh
user=admin \
password=secret \
./substore
```

The server listens on `http://0.0.0.0:3000` and serves the frontend at `/`.

To hide the panel behind a secret URL prefix, set `base_path`. Everything
(API, downloads, shares, static assets) then lives under the prefix, and any
request outside it — including the bare root — returns 404:

```sh
user=admin \
password=secret \
base_path=/mypanel \
./substore
# panel:    http://host:port/mypanel/
# root URL: http://host:port/            -> 404
```

### Environment variables

| Variable | Default | Description |
| --- | --- | --- |
| `host` | `0.0.0.0` | Listen host |
| `port` | `3000` | HTTP listen port |
| `base_path` | *(empty)* | Secret URL prefix for the web panel, e.g. `base_path=/mypanel` serves everything under `http://host:port/mypanel/` and the bare root path returns 404. Leave unset to serve from `/`. Named `base_path` instead of `path` because `path` collides with `PATH` on Windows (environment variables are case-insensitive there). |
| `data_dir` | `./data` | Data directory (SQLite + JWT secret) |
| `jwt_secret` | *(auto-generated)* | JWT signing secret. When unset a random one is generated once and persisted to `$data_dir/jwt_secret` |
| `token_ttl_hours` | `168` | JWT validity in hours |
| `user` | `admin` | Admin username. Overrides the default `admin`. |
| `password` | `admin` | Admin password. Overrides the default `admin`; re-applied on every start. |

## API

Auth (`Bearer <jwt>` required):

- `POST /api/login` `{username,password}` -> `{token,username}`
- `GET  /api/subs` / `POST /api/subs`
- `GET  /api/sub/:name` / `PATCH /api/sub/:name` / `DELETE /api/sub/:name`
- `GET  /api/collections` / `POST /api/collections`
- `GET  /api/col/:name` / `PATCH /api/col/:name` / `DELETE /api/col/:name`
- `GET  /api/node-info/:name` (node preview)
- `GET  /api/tokens` / `POST /api/token` / `DELETE /api/token/:token`
- `GET  /api/settings` / `PATCH /api/settings`

Public:

- `GET /download/:name?target=mihomo` (requires Bearer token or `?token=`)
- `GET /share/sub/:name?token=...&target=...`
- `GET /share/col/:name?token=...&target=...`

Targets: `mihomo`, `clash`, `stash`, `surge`, `surge-mac`, `surfboard`,
`loon`, `shadowrocket`, `qx`, `sing-box`, `v2ray`, `egern`, `json`, `uri`.

## Docker

```sh
docker build -t substore .
docker run -p 3000:3000 \
  -e user=admin \
  -e password=secret \
  -e base_path=/mypanel \
  -v substore-data:/app/data \
  substore
# panel: http://host:3000/mypanel/
```
