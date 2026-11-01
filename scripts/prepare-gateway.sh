#!/usr/bin/env bash
# The root-owned env file must use shell-compatible KEY=value assignments;
# quote values containing spaces. Prints rules to stdout; does not install or load them.
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root" >&2
  exit 1
fi
set -a
source /etc/zaun/zaun.env
set +a
exec python3 -m agentproxy.gateway_boot
