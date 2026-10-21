# zaun 
* for the most part ai generated * 

A sidecar that controls network egress for AI agents in a podman pod. It is based on Squid
in a Debian container and comes with a web UI for managing rules live.

- **Proxy allow rules** (L7): `test.host.io`, `*.host.io`, `http://test.io`, `https://api.x.io/v1/*`, `42.42.42.42`, `host.io:8443`
- **Target groups**: proxy allow and deny rules accept comma-separated URLs/hosts, for example `https://test.host.io, *.host2.io, https://host3.io/api`. Each group shares one name, ON/OFF switch and Allow WebSockets setting. Each member retains its own scheme, port and path restrictions. Firewall rules still accept one target. Commas delimit targets; encode literal commas in URL paths as `%2C`. Existing single-target configs remain compatible.
- **WebSockets**: denied by default. Enable **Allow WebSockets** when adding or editing a proxy allow rule to additionally permit WS/WSS handshakes within that rule’s host, scheme, port and path. Use `https://testing.io` for WSS only or `testing.io` for WS and WSS. Deny rules still win. Existing configs default to off; JSON uses `"allow_websockets": true`. After a successful upgrade, Squid tunnels messages without inspecting them.
- **Deny rules**: `http://test.io/*`, `*.host.io/admin/*`. These are checked before every allow rule and always win.
- **Firewall rules** (L3/L4, non-HTTP): `42.42.42.42` tcp `3306`, `10.0.0.0/24` tcp `5432`, `db.internal` tcp `5432,6379`
- **Default deny**: always on and cannot be changed
- **Live apply**: every add, edit, toggle or delete is validated and applied immediately (squid reconfigure + one atomic nftables transaction). If validation fails, nothing changes.
- **Log tab**: live stream of every access from both layers, with date, verdict, rule name, method, host, path, status and client
- **CA tab**: shows the interception CA so you can copy it, download it, or use the install snippets
- **Config tab**: switch settings live (upstream proxy and TLS verification), export/import the config as JSON (replace or merge) and view the generated squid/nft config

## How it works

```
 ┌──────────────────────────── pod (shared network namespace) ─────────────────────────┐
 │  agent ──HTTP(S)_PROXY──▶ squid :3128 ──(ssl-bump, ACLs)──────────────▶ internet      │
 │    │                         ▲                                                       │
 │    └──direct TCP/UDP──▶ nftables output chain (policy drop) ──allowed only──▶ target  │
 │                              │                                                       │
 │                        web UI :8080 (FastAPI) ── writes squid policy + nft ruleset   │
 └─────────────────────────────────────────────────────────────────────────────────────┘
```

- All containers in a pod share one network namespace. The sidecar (with `CAP_NET_ADMIN`)
  loads an nftables `output` chain with `policy drop`. The traffic it lets out is:
  loopback (so agents can reach the proxy), established flows, the proxy container's own
  sockets, and your firewall rules. Everything else gets a TCP reset or ICMP reject, so agents
  fail fast. That includes agent DNS: agents don't need it, because squid resolves names.
- The proxy container's traffic is exempted by **cgroup** (`socket cgroupv2`), not by uid.
  An agent can't move itself into another container's cgroup, even as root with
  `--privileged`. On hosts without cgroup v2 it falls back to squid's uid (31280), which an
  agent with `CAP_SETUID` could impersonate.
- Squid bumps (decrypts) all HTTPS with the CA from `/data/ca`. This is what makes method/path
  logging and path rules work for HTTPS. Each rule becomes a `url_regex` ACL plus an
  `annotate_transaction` ACL, so the log knows exactly which rule matched.
- `ulogd2` writes the nftables log entries (`log group 1`) as JSON. The UI tails both logs
  and merges them into one stream.

## Quick start

```bash
podman build -t zaun-agent-proxy:latest -f Containerfile .
UI_PASSWORD=change-me ./examples/run-pod.sh docker.io/library/debian:trixie-slim sleep infinity
# open http://127.0.0.1:8080 (user: admin)
```

Or use `podman kube play examples/pod.yaml`.

Manually:

```bash
podman pod create --name agents -p 127.0.0.1:8080:8080
podman run -d --pod agents --name agents-proxy --cap-add NET_ADMIN \
  -e UI_PASSWORD=change-me -v zaun-agent-proxy-data:/data zaun-agent-proxy:latest
# wait for http://127.0.0.1:8080/healthz, then start agents:
podman run -d --pod agents --cap-drop NET_ADMIN --cap-drop NET_RAW \
  -e HTTPS_PROXY=http://127.0.0.1:3128 -e HTTP_PROXY=http://127.0.0.1:3128 my-agent
```

### Agent setup

1. Set the proxy env vars: `HTTP_PROXY`/`HTTPS_PROXY`, plus lowercase variants for tools that only read those, and `NO_PROXY=localhost,127.0.0.1`.
2. Trust the CA. Inside the pod it is served without auth at `http://127.0.0.1:8080/ca.crt`:
   ```bash
   curl -fsSo /usr/local/share/ca-certificates/zaun-agent-proxy.crt http://127.0.0.1:8080/ca.crt && update-ca-certificates
   ```
   Node needs `NODE_EXTRA_CA_CERTS`. Python `requests` needs `REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt`.
3. Start agents only after the proxy's `/healthz` answers. The firewall is loaded before the UI
   comes up, so before that point the pod's egress isn't locked down yet.

## Rule syntax

| Kind | Target | Meaning |
|---|---|---|
| allow/deny | `test.host.io` | host, http + https, default ports (80/443), any path |
| allow/deny | `*.host.io` | any subdomain (not `host.io` itself) |
| allow/deny | `http://test.io` | only plain http |
| allow/deny | `https://x.io/api/*` | path prefix (`*` = anything); no `*` means exact path (query allowed) |
| allow/deny | `42.42.42.42`, `host.io:8443` | IP literal / non-default port |
| tcp | `42.42.42.42`, `10.0.0.0/8`, `db.host` + ports `3306`, `80,443`, `8000-8100` | direct L4 access, tcp or udp; hostnames re-resolved every `DNS_REFRESH_SECONDS` |

Evaluation order: built-in denies (non-allowed client, proxy → localhost), then deny rules, then allow rules, then `default-deny`.
Deny-rule paths match case-insensitively.

Rule names may be reused. Each rule has a separate ID; log labels use `<id>_<name>` to distinguish rules with the same name.

## Configuration (env)

| Variable | Default | |
|---|---|---|
| `UI_PASSWORD` | generated, printed once, stored in `/data/ui-password` | web UI basic auth password |
| `UI_USER` | `admin` | |
| `UI_PORT` / `UI_LISTEN` | `8080` / `0.0.0.0` | |
| `FIREWALL_ENFORCE` | `1` | `0` = squid only, no nftables (no `NET_ADMIN` needed, no L4 enforcement) |
| `UPSTREAM_PROXY` | empty (direct) | Upstream HTTP or HTTPS proxy URL, e.g. `http://proxy.example:3128` or `http://user:pass@proxy.example:3128`. A nonempty URL enables proxy chaining. Percent-encode special characters in URL credentials. Initial value only; saved UI settings win over the env. |
| `UPSTREAM_PROXY_USER` | empty | Optional Basic authentication username (when credentials are not included in the URL). |
| `UPSTREAM_PROXY_PASSWORD` | empty | Optional Basic authentication password. |
| `VERIFY_UPSTREAM_TLS` | `1` | `0` = accept invalid upstream certificates (self-signed, expired, wrong name); agents still see a cert signed by the proxy CA. Mimicked certs of origins without an Authority Key Identifier (typically self-signed) also lack one, which Python ≥ 3.13 `ssl.create_default_context()` rejects (`VERIFY_X509_STRICT`). Initial value only: it can be switched live in the Config tab, and the value stored in `config.json` (`settings`) wins over the env |
| `ALLOWED_CLIENTS` | private ranges + loopback | source networks squid accepts |
| `DNS_REFRESH_SECONDS` | `300` | re-resolve hostname firewall targets |
| `CA_CN` | `Agent Proxy CA` | subject of a newly generated CA |
| `LOG_MAX_BYTES` | 50 MB | rotate access/firewall logs at this size |

The `/data` volume holds `config.json` (the rules), `ca/ca.pem` + `ca/ca.key` and
`ui-password`. To use your own CA, put `ca.pem` and `ca.key` there before the first start.

## API

All endpoints require basic auth except `/ca.pem`, `/ca.crt` and `/healthz`.

`GET /api/state` · `POST /api/rules` · `PUT|DELETE /api/rules/{id}` · `POST /api/reapply` ·
`GET /api/export` · `POST /api/import?mode=replace|merge` · `GET /api/generated` · `GET /api/ca` ·
`GET /api/logs?limit=N` · `GET /api/logs/stream` (SSE)

```bash
curl -u admin:change-me -H 'Content-Type: application/json' http://127.0.0.1:8080/api/rules \
  -d '{"kind":"tcp","target":"42.42.42.42","ports":"3306","name":"mysql"}'
```

### Helper script

`scripts/manage-targets.py` (Python stdlib only) lists, adds, imports, removes and
disables rules through the API. It asks for the username and password when they aren't
given with `-u`/`-p` (or `AGENT_PROXY_USER`/`AGENT_PROXY_PASSWORD`).

```bash
scripts/manage-targets.py list                          # table with rule IDs; --kind tcp, --json
scripts/manage-targets.py add allow api.example.com
scripts/manage-targets.py add tcp 10.0.0.5 --ports 5432 --name postgres
scripts/manage-targets.py import rules.json             # export format; merges, skips duplicates
scripts/manage-targets.py import rules.json --replace   # replaces all rules (asks first, -y to skip)
scripts/manage-targets.py disable r1a2b3c4d             # keep the rule but stop applying it
scripts/manage-targets.py enable r1a2b3c4d
scripts/manage-targets.py remove r1a2b3c4d r5e6f7a8b    # several IDs at once
```

The API URL is set with `--url` (before or after the subcommand) or `AGENT_PROXY_URL`, and
defaults to `http://127.0.0.1:8080`. It may include a path prefix (e.g. behind a reverse
proxy); without a scheme `http://` is assumed. On import, the file's
`settings` are only applied with `--with-settings`.

## Security notes

- Never give agent containers `NET_ADMIN` or `--privileged`. With those they could rewrite the pod's nftables rules.
- The UI listens inside the pod, so agents can reach `127.0.0.1:8080`. They still need the
  password, and squid refuses proxy requests to localhost.
- Removing a firewall rule blocks new connections right away. Connections that are already
  established stay open until they close.
- Deny rules match the URL as the agent sent it. Percent-encoded variants of a path
  (`/%61dmin`) are not normalized, so for sensitive paths prefer allow-listing narrow
  prefixes over deny-listing.
- Query strings are stripped from the access log (`strip_query_terms on`) so tokens don't leak into it.

## Development

```bash
python3 -m unittest discover -s tests     # pattern → regex / config generation tests
```

### Upstream proxy

Set `UPSTREAM_PROXY=http://proxy.example:3128` to forward allowed HTTP and HTTPS
requests through a parent proxy. HTTPS destinations use the parent's CONNECT support;
agent-proxy still enforces its normal allow/deny policy and TLS inspection.
HTTP and HTTPS parent URLs are supported (no SOCKS). HTTPS parents use system trusted
CAs. An unavailable parent causes requests to fail; there is no direct fallback.
Raw TCP/UDP firewall rules continue to connect directly.

In **Config → Upstream proxy**, set the URL, optional username/password, and enabled
checkbox, then click **save upstream**. Changes apply without restarting the container;
existing connections may finish. Disable it to restore direct HTTP(S) connections
while retaining the saved URL and credentials. Leave the password blank to keep it,
or select **clear saved password** to remove it. URL credentials override separate fields.
Settings persist in `/data/config.json` and override environment defaults on restart.
The settings API uses `upstream_proxy_enabled`, `upstream_proxy_url`,
`upstream_proxy_username`, and `upstream_proxy_password`; omit the password to keep it,
or send an empty string to clear it. State responses omit the password and generated
config responses redact it. Config exports include credentials so imports can restore
the complete configuration; store exports securely.
