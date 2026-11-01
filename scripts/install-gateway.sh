#!/usr/bin/env bash
# Install the single root-run application on a dedicated Debian 13 gateway.
# Package installation may start distro services. The Zaun service is not started;
# routes, forwarding sysctls and the live nftables policy are not changed here.
set -euo pipefail
umask 022
if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: sudo bash scripts/install-gateway.sh" >&2
  exit 1
fi
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  squid-openssl nftables ulogd2 ulogd2-json openssl ca-certificates \
  supervisor util-linux procps python3 python3-fastapi python3-uvicorn
if ! getent passwd agentproxy >/dev/null; then
  groupadd -g 31280 agentproxy
  useradd -M -u 31280 -g agentproxy -d /var/spool/squid -s /usr/sbin/nologin agentproxy
fi
if [ "$(id -u agentproxy)" != 31280 ] || [ "$(id -g agentproxy)" != 31280 ]; then
  echo "agentproxy must have uid/gid 31280; resolve the account conflict first" >&2
  exit 1
fi
install -d /opt/agent-proxy /etc/agent-proxy /etc/zaun /etc/nftables.d
install -d -m 700 /var/lib/zaun
cp -R "$repo/app/." /opt/agent-proxy/
find /opt/agent-proxy -type d -exec chmod 0755 {} +
find /opt/agent-proxy -type f -exec chmod 0644 {} +
install -m 644 "$repo/rootfs/etc/agent-proxy/ulogd.conf" /etc/agent-proxy/ulogd.conf
python3 "$repo/scripts/render-native-supervisor.py" \
  "$repo/rootfs/etc/agent-proxy/supervisord.conf" > /etc/agent-proxy/supervisord.conf
# The native installation uses a conventional persistent state directory.
sed 's|/data/ca/|/var/lib/zaun/ca/|g' \
  "$repo/rootfs/etc/squid/squid.conf" > /etc/squid/squid.conf
install -m 644 "$repo/rootfs/usr/share/squid-langpack/templates/ERR_AGENT_DENIED" \
  /usr/share/squid-langpack/templates/ERR_AGENT_DENIED
install -m 755 "$repo/rootfs/usr/local/bin/entrypoint.sh" /usr/local/bin/zaun-entrypoint
install -m 755 "$repo/scripts/prepare-gateway.sh" /usr/local/bin/zaun-prepare-gateway
if [ ! -e /etc/zaun/zaun.env ]; then
  install -m 600 "$repo/examples/gateway.env" /etc/zaun/zaun.env
fi
install -m 644 "$repo/examples/zaun.service" /etc/systemd/system/zaun.service
systemctl daemon-reload
echo "Installed. Follow README gateway setup before starting zaun.service."
echo "The distro squid/supervisor/ulogd services must not run alongside Zaun's supervisor."
