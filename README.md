# Zaun

Zaun controls which network destinations AI agents can reach, with a web UI for managing access rules and viewing traffic. Run it alongside agents in a Podman pod or on a Debian gateway serving agents elsewhere on your network.

This project is mainly vibe coded. 

![Zaun Proxy Tab](zaun.png)

## Features

- Allow or deny HTTP/HTTPS destinations by host, URL path and port.
- Allow direct TCP/UDP connections to specific hosts or networks.
- Block unmatched traffic by default; deny rules take priority.
- Apply rule changes live, view proxy and firewall logs together, and download active and rotated raw logs as a compressed archive.
- Enable WebSockets per rule, chain an upstream proxy, and import/export configuration.

## Modes

| Mode | Use it when | Setup |
|---|---|---|
| **Gateway** | Agents run on other machines and route through a dedicated Debian 13 server. | [Gateway guide](examples/gateway-mode/README.md) |
| **Container** | Agents and the proxy share a Podman pod's network namespace. | [Container guide](examples/container-mode/README.md) |

Both modes use an explicit HTTP/HTTPS proxy. Agents must trust Zaun's CA so it can inspect HTTPS paths. Gateway mode also requires routing agents through the server; setting proxy variables alone does not enforce their network access.

## Technology

- **Squid** handles HTTP/HTTPS filtering and TLS interception. It checks deny rules before allow rules and labels requests for the access log.
- **nftables** controls direct connections: container mode filters the pod's outbound traffic; gateway mode filters forwarded agent traffic and optionally provides IPv4 NAT. Gateway mode leaves the server's own input/output policy to its host firewall.
- **FastAPI** serves the UI and REST API. Rule changes are validated before applying them; nftables updates use an atomic transaction. Squid and ulogd2 logs feed the live log view.
- **Supervisor** runs Squid, logging and the UI together. Gateway mode runs the app as root; container mode gives the proxy `NET_ADMIN`. Container mode exempts proxy traffic using cgroups where available, with a weaker UID fallback.

Contributor commands, policy details and API notes are in [AGENTS.md](AGENTS.md).

## Configuration (env)

The example guides provide ready-to-edit configuration. These are the application defaults; example deployments may override them.

| Variable | Default | Purpose |
|---|---|---|
| `UI_USER` | `admin` | UI/API username. |
| `UI_PASSWORD` | Generated | UI/API password; saved as `ui-password` in the state directory. |
| `UI_LISTEN` / `UI_PORT` | `0.0.0.0` / `8080` | Admin interface address and port. |
| `FIREWALL_MODE` | `container` | `container` or `gateway`. |
| `FIREWALL_ENFORCE` | `1` | `0` disables firewall enforcement; unavailable in gateway mode. |
| `GATEWAY_AGENT_INTERFACE` / `GATEWAY_UPLINK_INTERFACE` | Unset | Required, distinct agent and uplink interfaces in gateway mode. |
| `GATEWAY_AGENT_NETWORKS` | Unset | Required agent CIDRs, separated by spaces. |
| `GATEWAY_MASQUERADE` | `0` | `1` enables IPv4 NAT in gateway mode. |
| `ALLOWED_CLIENTS` | Private ranges and loopback | Accepted proxy client networks; defaults to agent CIDRs in gateway mode. |
| `UPSTREAM_PROXY` | Unset | Optional HTTP/HTTPS parent proxy URL. |
| `UPSTREAM_PROXY_USER` / `UPSTREAM_PROXY_PASSWORD` | Unset | Optional parent proxy credentials. |
| `VERIFY_UPSTREAM_TLS` | `1` | Verify origin TLS certificates. |
| `DNS_REFRESH_SECONDS` | `300` | Refresh hostname-based firewall targets. |
| `CA_CN` | `Agent Proxy CA` | Name used when generating the interception CA. |
| `LOG_MAX_BYTES` | 50 MB | Access/firewall log rotation size. |
| `LOG_BACKUPS` | 20 in gateway mode, 1 otherwise | Number of access/firewall log rotations retained. |
| `DATA_DIR` | `/data` | Persistent rules, CA and generated password. The native gateway uses `/var/lib/zaun`. |

Upstream proxy and TLS verification settings can also be changed in the UI. Saved settings override their environment defaults on restart. Back up the state directory to retain your rules and CA.

## Security notes

- Keep the admin UI on a trusted interface or access it through an SSH tunnel. Proxy clients are restricted by source network; the UI password does not authenticate proxy requests.
- Never give agent containers `NET_ADMIN`, `--privileged` or the host's container-management socket. Start agents only after the proxy is ready. Never use container mode with host networking.
- Gateway agents need a controlled route through Zaun without an alternative internet path. Protect services on the gateway separately; its forwarding rules do not cover traffic addressed to the server itself.
- HTTPS inspection decrypts agent traffic. Protect the CA private key, state backups and configuration exports; exports may include upstream credentials. Keep upstream TLS verification enabled.
- Prefer narrow allow rules for sensitive paths. Deny rules do not normalize percent-encoded paths, so an encoded URL may evade a path deny.
- Deny targets can use `*/admin*` to block paths starting with `/admin` on any host, or `*/*admin*` to match `admin` anywhere in the path. Matching is case-insensitive and deny rules win over allows. A deny target without a scheme or port matches HTTP and HTTPS on every proxy destination port. A scheme alone selects its default port. An explicit port selects only that port. This also applies to existing deny rules when reapplied. To keep a default-port-only deny for a host, use a group such as `http://example.com, https://example.com`.
- Removing a firewall rule blocks new connections; established connections remain open until they close. Query strings are stripped from proxy logs, but URL paths can still contain sensitive information.
