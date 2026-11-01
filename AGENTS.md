# Repository Guidelines

## Project Structure & Module Organization

- `app/agentproxy/`: Python backend. `main.py` serves FastAPI; `rules.py` generates policies; `apply.py` validates/applies them; `firewall.py` defines deployment settings.
- `app/static/`: plain JavaScript, HTML and CSS for the web UI; no frontend build step.
- `rootfs/`: Squid, Supervisor and ulogd configuration plus the startup entrypoint.
- `scripts/`: installation, configuration rendering and API management helpers.
- `examples/container-mode/` and `examples/gateway-mode/`: deployment templates and instructions.
- `tests/`: Python unittest suites covering policies, upstream settings and native deployment. Deployment instructions live in the example READMEs.

## Build, Test, and Development Commands

Run from the repository root:

```bash
python3 -m unittest discover -s tests
podman build -t zaun-agent-proxy:latest -f Containerfile .
podman kube play examples/container-mode/zaun-pod.yaml
node --check app/static/app.js
bash -n scripts/*.sh rootfs/usr/local/bin/entrypoint.sh
```

These run unit tests, build/start the container example, and check JavaScript/shell syntax. Configure the pod template before starting it. Native gateway installation requires root and changes system files; follow its example README rather than using it as a routine development command.

## Coding Style & Naming Conventions

Use four-space indentation for Python and two spaces for frontend code. Follow existing conventions: `snake_case` functions/modules, `PascalCase` classes and `UPPER_CASE` constants. Keep policy generation separate from subprocess execution and API handling. Use Python type hints where consistent with neighboring code. No formatter or linter configuration is currently provided; avoid unrelated formatting changes. Introduce external libraries to this project only if they add real value.

## Testing Guidelines

Use standard-library `unittest`, with `tests/test_*.py` files and `test_*` methods. Add regression tests for policy changes, validation failures and deployment compatibility. No numeric coverage threshold is configured.

For isolated nftables kernel checks:

```bash
ZAUN_TEST_NFT=1 python3 -m unittest discover -s tests -p test_gateway_kernel.py
```

This requires `nft`, `unshare` and namespace permissions. Report skipped checks and distinguish unit validation from live routing/TLS/reboot testing.

## Commit & Pull Request Guidelines

History uses short imperative subjects, such as “Implement gateway mode” and “Simplify README”; follow that style. PRs should explain the behavior change, affected deployment modes and validation performed. Link relevant issues and include screenshots for UI changes.

## Security & Configuration

Preserve default-deny behavior and both deployment modes. Gateway rules must stay scoped to Zaun's table and agent forwarding; never flush unrelated host rules. Keep credentials and CA private keys out of commits. Boot-guard generation prints rules only; installation is explicit.

## Policy Semantics

Preserve these behaviors when changing parsers, generated policies or the UI:

- Evaluation order is built-in client/localhost restrictions, deny rules, allow rules, then default deny. Deny paths match case-insensitively; percent-encoded paths are not normalized.
- Bare hosts permit HTTP/HTTPS on default ports; `*.example.com` excludes the apex. Schemes and explicit ports restrict access. URL paths are exact unless suffixed with `*`; query strings may accompany an exact path.
- Proxy target groups use comma-separated members sharing a name, toggle and WebSocket setting. Keep each member's scheme/port/path restrictions. Encode literal path commas as `%2C`. Direct firewall rules accept one IP, CIDR or hostname and TCP/UDP ports such as `5432,8000-8100`.
- WebSockets default off, including older saved configurations. `allow_websockets: true` permits matching handshakes only; deny rules still win. HTTPS targets permit WSS; bare hosts can permit WS/WSS. Squid tunnels messages after upgrade without inspecting them.
- Names need not be unique. Preserve separate IDs and `<id>_<name>` log labels. Keep old single-target configurations compatible.
- Validate before applying mutations. Failed validation must preserve existing rules and settings. Hostname firewall targets are periodically re-resolved; unresolved names must not broaden access.

## Runtime & Agent Connectivity

Container mode uses nftables OUTPUT with default drop, permitting loopback, established flows, proxy sockets and explicit direct rules. Proxy exemptions prefer `socket cgroupv2`; fallback UID 31280 is weaker because an agent with `CAP_SETUID` could impersonate it. Never grant agents privileged capabilities to work around connectivity errors.

Squid intercepts HTTPS using the persistent CA and generates URL ACLs and transaction annotations. ulogd2 emits NFLOG group 1 JSON; the UI merges firewall and Squid events into one stream. Preserve client, verdict and rule attribution.

Workload agents need uppercase/lowercase HTTP(S) proxy variables, `NO_PROXY=localhost,127.0.0.1`, and trust in the interception CA. In a pod, retrieve it from `http://127.0.0.1:8080/ca.crt`; gateway clients use the LAN proxy address and a securely distributed CA. Node needs `NODE_EXTRA_CA_CERTS`; Python Requests may need `REQUESTS_CA_BUNDLE`. Start workloads after `/healthz` responds; the pod is not protected before initial firewall bootstrap.

## API & Management Helpers

Basic authentication protects endpoints except `/ca.pem`, `/ca.crt` and `/healthz`. Preserve these API routes:

- `GET /api/state`, `POST /api/rules`, `PUT|DELETE /api/rules/{id}`, `POST /api/reapply`.
- `GET /api/export`, `POST /api/import?mode=replace|merge`, `GET /api/generated`, `GET /api/ca`.
- `GET /api/logs?limit=N`, `GET /api/logs/stream` (SSE), `GET /api/logs/download` (authenticated JSON attachment).

Log downloads include recent server-buffered access events, newest first, independently of UI filters/clear. They preserve every event field and original JSON value type, including URL, detail, ID and epoch, without download-time filtering or redaction, and set no-store/nosniff headers. Export every retained buffer entry without separate record, byte or field-length limits; normal log-buffer retention still applies. Keep the download unavailable when UI credentials are unset; never accept a user-provided filesystem path or attachment filename. Event paths and client addresses can still be sensitive.

`scripts/manage-targets.py` uses only Python's standard library. It supports `list`, `add`, `import`, `disable`, `enable` and `remove`:

```bash
scripts/manage-targets.py add allow api.example.com
scripts/manage-targets.py add tcp 10.0.0.5 --ports 5432 --name postgres
scripts/manage-targets.py import rules.json
```

Imports merge and skip duplicates by default; `--replace` replaces rules and prompts unless `-y` is given. Imported settings require `--with-settings`. `--url` or `AGENT_PROXY_URL` selects the API (default `http://127.0.0.1:8080`), supports path prefixes, and assumes HTTP when the scheme is omitted. Credentials come from prompts, `-u`/`-p`, or `AGENT_PROXY_USER`/`AGENT_PROXY_PASSWORD`.

## Upstream Settings & Certificates

HTTP/HTTPS parent proxies are supported; SOCKS is not. An unavailable enabled parent must fail without falling back to direct access. Raw TCP/UDP rules remain direct. HTTPS parents use system-trusted CAs. Percent-encode URL credentials; URL credentials override separate fields.

Persisted settings override environment defaults and apply live. Preserve `upstream_proxy_enabled`, `upstream_proxy_url`, `upstream_proxy_username`, `upstream_proxy_password` and `verify_upstream_tls`. Omitting a password retains it; an empty string clears it. Disabling chaining retains saved credentials. State responses omit passwords, generated configuration redacts them, and exports retain them for restoration.

State lives under `/data` in containers or `/var/lib/zaun` in the native gateway: `config.json`, `ui-password`, and `ca/ca.pem` plus `ca/ca.key`. Custom CA files must be installed before first startup. With origins lacking an Authority Key Identifier, mimicked certificates may fail Python 3.13+ `VERIFY_X509_STRICT` even when upstream TLS verification is disabled.
