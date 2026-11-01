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

Zaun also runs directly on a Debian 13 **network gateway**, controlling remote agents'
forwarded traffic. It remains one root-run application; no privileged helper service
is required. Container mode remains the default and uses the existing pod setup.

## Gateway installation (Debian 13)

Use a dedicated agent LAN/VLAN and a separate uplink, for example:

```
agents 10.20.0.0/24 --> enp2s0 [Debian gateway / Zaun] enp1s0 --> upstream
                        10.20.0.1
```

Agents must route external traffic through this server, with no alternative internet
gateway or IPv6 route. Set `HTTP_PROXY` and `HTTPS_PROXY` (and lowercase variants)
to `http://10.20.0.1:3128`, and install Zaun's CA on each agent. This is an explicit
HTTP(S) proxy, not transparent interception. Raw TCP/UDP allowances are routed by the
gateway. Direct HTTP(S) is blocked unless you deliberately add a firewall allowance.

Gateway mode manages only `table inet agentproxy`: a FORWARD hook scoped to the
dedicated agent interface, plus optional IPv4 masquerading. The server's INPUT and
OUTPUT policies and other nftables tables are untouched. Use your host firewall to
allow proxy port 3128 only from agents and protect other host services; requests
addressed to the gateway itself do not pass through FORWARD. UI credentials do not
authenticate proxy clients. Existing host FORWARD rules can still deny connections
that Zaun allows. Do not use forwarding flow offload for managed agent traffic.

On a dedicated Debian 13 server, from this checkout:

```bash
sudo bash scripts/install-gateway.sh
sudo systemctl disable --now squid.service supervisor.service ulogd.service
sudoedit /etc/zaun/zaun.env
```

The installer installs Debian packages and application files, retaining an existing
`/etc/zaun/zaun.env`. It replaces `/etc/squid/squid.conf`; use a dedicated installation,
not a server already running a separate Squid deployment. Package installation may
start distro services, which the next command stops. Zaun's own supervisor manages
Squid, ulogd and the UI together under one root-run systemd service.
Native child-process logs are rotated in `/var/log/agent-proxy/` as `squid.log`,
`cachelog.log`, `ulogd.log` and `webui.log` (10 MB each, three backups).
Supervisor lifecycle messages remain in `journalctl -u zaun.service`. Container
deployments continue logging child output to stdout.

Configure the actual interface names, agent CIDRs and optional NAT in the env file:

```ini
FIREWALL_MODE=gateway
FIREWALL_ENFORCE=1
GATEWAY_AGENT_INTERFACE=enp2s0
GATEWAY_UPLINK_INTERFACE=enp1s0
GATEWAY_AGENT_NETWORKS="10.20.0.0/24 fd20::/64"
GATEWAY_MASQUERADE=1
UI_LISTEN=127.0.0.1
UI_USER=admin
# UI_PASSWORD=your-long-random-password
VERIFY_UPSTREAM_TLS=1
DATA_DIR=/var/lib/zaun
PYTHONPATH=/opt/agent-proxy
PYTHONUNBUFFERED=1
```

For IPv4-only agents, omit the IPv6 CIDR. Forwarded IPv6 traffic on the agent
interface is then rejected even if host IPv6 forwarding is enabled. IPv6 agent
networks require routed return paths; NAT is IPv4-only. With NAT disabled, upstream
routers also need routes back to IPv4 agent networks. Agent and uplink interfaces
must differ. This mode does not support single-interface/hairpin routing.

`ALLOWED_CLIENTS` defaults to the configured agent CIDRs in gateway mode. If explicitly
set, use a space-separated list. Quote values containing spaces: the env file is also
read as a root-owned shell configuration by the boot-guard preparation command.

**Install the boot guard before enabling forwarding or routing agents through Zaun.**
Keep forwarding disabled during initial setup. Print the default-deny policy:

```bash
sudo zaun-prepare-gateway
```

This command only prints nftables rules to stdout. It does not create files or load
the firewall. Review the output, then install it yourself, for example:

```bash
sudo zaun-prepare-gateway > zaun-boot.nft
sudo nft --check --file zaun-boot.nft
sudo install -d -m 755 /etc/nftables.d
sudo install -m 644 zaun-boot.nft /etc/nftables.d/zaun-boot.nft
```

Add this line at the **end** of `/etc/nftables.conf`, after any `flush ruleset`:

```nft
include "/etc/nftables.d/zaun-boot.nft"
```

Review the rest of that file: Debian's nftables service loads it at boot, and a
`flush ruleset` there replaces existing firewall rules. Preserve your host firewall
configuration. Then validate and start the firewall and application:

```bash
sudo nft --check --file /etc/nftables.conf
sudo systemctl enable --now nftables.service
sudo nft --file /etc/nftables.d/zaun-boot.nft
sudo systemctl enable --now zaun.service
curl --fail http://127.0.0.1:8080/healthz
sudo journalctl -u zaun.service -n 100 --no-pager
```

The boot guard denies new forwarded agent connections before the app is available.
Startup atomically replaces that guard with the saved live policy. If Zaun fails to
start, the guard remains. Stopping/restarting Zaun leaves the last loaded rules in
place. Do not stop or reload nftables while agents are using the gateway: stopping
the distro firewall service can flush rules, and reloading restores the boot guard.
After an intentional firewall reload, restart Zaun to reapply the live policy.
Regenerate, review and manually reinstall the guard whenever gateway
interfaces/subnets/NAT settings change.

Only after the firewall and application are running, enable the required forwarding
families. For example, create `/etc/sysctl.d/90-zaun-gateway.conf`:

```ini
net.ipv4.ip_forward=1
# Include only when routing IPv6 agents:
# net.ipv6.conf.all.forwarding=1
```

Apply with `sudo sysctl -p /etc/sysctl.d/90-zaun-gateway.conf`, then configure the
agent machines' routes. If the uplink obtains its IPv6 default route through router
advertisements, configure `accept_ra=2` for that uplink when enabling IPv6 forwarding.
Zaun does not change interfaces, routes, IP forwarding or DNS settings automatically.
Use a numeric proxy address; direct agent DNS requires an explicit UDP/TCP port 53
firewall rule. Squid and the application resolve hostname targets using server DNS.

Access the admin UI from your workstation:

```bash
ssh -L 8080:127.0.0.1:8080 your-user@your-gateway
```

Open `http://127.0.0.1:8080`. If no password was supplied, retrieve the generated one
with `sudo cat /var/lib/zaun/ui-password`. Add proxy and direct firewall rules in the
UI and download the CA for remote agents. The UI/API show the active firewall mode.
Back up `/var/lib/zaun` securely, including the interception CA private key and rules.
The CA tab's localhost proxy snippets are for pod mode; remote agents must use the
gateway's LAN address and receive the certificate through a trusted channel.

Verify from an agent: an allowed proxy URL works with CA verification enabled, a
non-allowed URL returns a denial, an allowed direct TCP/UDP service works, and a
non-allowed direct connection is rejected. Check both IPv4 and IPv6, unrelated host
administration, and that the boot guard is loaded after reboot before production use.
Existing connections remain permitted after rule removal until they close, as in
container mode. Proxy rules apply to all accepted proxy clients; direct rules apply
to all configured agent subnets, not individual agents.

To update, rerun the installer and restart `zaun.service`. Configuration and CA state
are retained. Gateway mode can also run in a rootful container with `--network=host`
and `--cap-add=NET_ADMIN`, but it then manages the host firewall; do not use port
publishing, and install the same host boot guard. Native installation above is the
recommended gateway deployment. Never run **container mode** with host networking:
its OUTPUT policy would restrict the host's own traffic.

## How container mode works

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
| `FIREWALL_MODE` | `container` | `container` = pod OUTPUT enforcement; `gateway` = routed agent FORWARD enforcement (requires enforcement enabled) |
| `GATEWAY_AGENT_INTERFACE` / `GATEWAY_UPLINK_INTERFACE` | unset | Required, distinct interfaces in gateway mode |
| `GATEWAY_AGENT_NETWORKS` | unset | Required space-separated IPv4/IPv6 CIDRs in gateway mode; also the default allowed proxy clients |
| `GATEWAY_MASQUERADE` | `0` | `1` = IPv4 agent source NAT through the configured uplink; gateway mode only |
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

Optional kernel validation loads container and IPv4/IPv6 gateway policies in a
disposable network namespace, verifies other tables survive, and checks that a
failed transaction preserves the previous policy:

```bash
ZAUN_TEST_NFT=1 python3 -m unittest discover -s tests -p test_gateway_kernel.py
```

This requires `nft` and `unshare`, plus permission to create network namespaces
(root or enabled unprivileged user namespaces). It never modifies the host firewall.
End-to-end routing, proxy TLS and reboot checks still require a gateway test host.

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
