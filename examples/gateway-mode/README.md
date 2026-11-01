# Gateway Deployment

Run Zaun directly on a dedicated Debian 13 server. One root-run app manages Squid,
the web UI and nftables for remote agents.

```text
agents 10.20.0.0/24 --> enp2s0 [Zaun gateway] enp1s0 --> upstream
                        10.20.0.1
```

Use separate agent and uplink interfaces. Agents must route through this server
without an alternative internet route. Keep IP forwarding disabled until step 4.
The installer replaces `/etc/squid/squid.conf`; use a dedicated Squid installation.

## Usage

Run server commands from the repository root.

### 1. Install and configure

```bash
sudo bash scripts/install-gateway.sh
sudo systemctl disable --now squid.service supervisor.service ulogd.service
sudoedit /etc/zaun/zaun.env
```

The installer copies [gateway.env](gateway.env) and [zaun.service](zaun.service).
Keep the template's other settings and change these values for your network:

```ini
GATEWAY_AGENT_INTERFACE=enp2s0
GATEWAY_UPLINK_INTERFACE=enp1s0
GATEWAY_AGENT_NETWORKS="10.20.0.0/24"
GATEWAY_MASQUERADE=1
# UI_PASSWORD=your-long-random-password
```

The standalone distro services must stay stopped: Zaun runs its own Squid,
Supervisor and ulogd. An existing `/etc/zaun/zaun.env` is preserved on reinstall.

### 2. Install the boot firewall

Generate and review the default-deny guard. The command only prints rules; you
install them yourself:

```bash
sudo bash scripts/prepare-gateway.sh > zaun-boot.nft
cat zaun-boot.nft
sudo nft --check --file zaun-boot.nft
sudo install -d -m 755 /etc/nftables.d
sudo install -m 644 zaun-boot.nft /etc/nftables.d/zaun-boot.nft
```

Add this line at the end of `/etc/nftables.conf`, after any `flush ruleset`:

```nft
include "/etc/nftables.d/zaun-boot.nft"
```

Preserve your host firewall rules: the nftables service loads that entire file.
Zaun manages only `table inet agentproxy`, filtering traffic forwarded through
the agent interface. Configure your host firewall separately to allow TCP 3128
from agent addresses and protect other services on the gateway.

### 3. Start Zaun

```bash
sudo nft --check --file /etc/nftables.conf
sudo systemctl enable --now nftables.service
sudo nft --file /etc/nftables.d/zaun-boot.nft
sudo systemctl enable --now zaun.service
curl --fail http://127.0.0.1:8080/healthz
```

From your workstation, open an SSH tunnel:

```bash
ssh -L 8080:127.0.0.1:8080 your-user@your-gateway
```

Open http://127.0.0.1:8080 and log in as `admin`. If you omitted `UI_PASSWORD`,
retrieve it with `sudo cat /var/lib/zaun/ui-password`. Add allowed proxy destinations
and direct TCP/UDP rules, then download the CA for your agents.

### 4. Enable routing and connect agents

Create `/etc/sysctl.d/90-zaun-gateway.conf` on the server:

```ini
net.ipv4.ip_forward=1
```

Apply it with `sudo sysctl -p /etc/sysctl.d/90-zaun-gateway.conf`. Configure agents
to use `10.20.0.1` as their gateway and set:

```bash
export HTTP_PROXY=http://10.20.0.1:3128 HTTPS_PROXY=http://10.20.0.1:3128
export http_proxy="$HTTP_PROXY" https_proxy="$HTTPS_PROXY"
export NO_PROXY=localhost,127.0.0.1 no_proxy=localhost,127.0.0.1
```

Install the downloaded CA in each agent's trust store. Node needs
`NODE_EXTRA_CA_CERTS`; Python Requests may need `REQUESTS_CA_BUNDLE`. The UI's
localhost proxy snippets apply to container mode; remote agents use the gateway IP.
Direct agent DNS requires explicit UDP/TCP port 53 rules; Squid uses server DNS.

Verify allowed and denied proxy requests and direct connections from an agent.
Check IPv4/IPv6 behavior and reboot persistence before using the gateway in production.

## Configurable Parameters

- `FIREWALL_MODE=gateway` and `FIREWALL_ENFORCE=1`: required for this deployment.
- `GATEWAY_AGENT_INTERFACE` / `GATEWAY_UPLINK_INTERFACE`: distinct LAN and uplink names; single-interface routing is unsupported.
- `GATEWAY_AGENT_NETWORKS`: space-separated CIDRs; quote multiple values. Also defaults the proxy's `ALLOWED_CLIENTS`.
- `GATEWAY_MASQUERADE`: `1` enables IPv4 NAT; `0` requires upstream routes back to the agents.
- `UI_LISTEN=127.0.0.1`: keeps administration accessible through SSH.
- `VERIFY_UPSTREAM_TLS=1`: verifies origin TLS certificates.

For IPv6, add an agent CIDR such as `fd20::/64`, enable
`net.ipv6.conf.all.forwarding=1`, and provide an upstream return route. There is no
NAT66. An uplink using router advertisements may need `accept_ra=2` on that interface.
Without configured IPv6 agent networks, forwarded IPv6 on the agent interface is rejected.

## Operation

- **Logs:** `sudo journalctl -u zaun.service` for Supervisor; `/var/log/agent-proxy/{squid,cachelog,ulogd,webui}.log` for child processes (10 MB each, three backups).
- **Backups:** securely back up `/var/lib/zaun`, including rules, credentials and the CA private key.
- **Updates:** rerun the installer and restart `zaun.service`; configuration and CA state are retained.
- **Boot guard:** blocks new agent forwarding until Zaun applies the saved policy. Regenerate, review and reinstall it after changing interfaces, subnets or NAT settings.
- **Firewall reloads:** stopping nftables can flush rules; reloading restores the boot guard. Restart Zaun after an intentional reload. Stopping Zaun leaves its last rules loaded.

Rules apply to all configured agents. Existing connections remain open after rule
removal until they close. Host traffic and same-LAN traffic do not pass through
Zaun's FORWARD policy; other host firewall rules may also deny allowed forwarding.
Do not enable forwarding flow offload for agent traffic. Zaun does not configure
interfaces, routes or DNS automatically.

See the [main README](../../README.md) for rule syntax, API and other settings.
