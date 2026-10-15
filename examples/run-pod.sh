#!/usr/bin/env bash
# Start a pod with the zaun-agent-proxy sidecar and one agent container.
# Usage: UI_PASSWORD=... ./examples/run-pod.sh [agent-image] [agent-command...]
set -euo pipefail

POD=${POD:-agents}
IMAGE=${IMAGE:-localhost/zaun-agent-proxy:latest}
AGENT_IMAGE=${1:-docker.io/library/debian:trixie-slim}
shift || true
[ $# -gt 0 ] || set -- sleep infinity
UI_BIND=${UI_BIND:-127.0.0.1:8080}   # web UI, only on the host's loopback

podman pod create --name "$POD" -p "$UI_BIND:8080"

# 1. the sidecar: owns the pod's network namespace firewall
podman run -d --pod "$POD" --name "$POD-proxy" \
  --cap-add NET_ADMIN \
  -e UI_PASSWORD="${UI_PASSWORD:?set UI_PASSWORD}" \
  -v "$POD-proxy-data:/data" \
  "$IMAGE"

# 2. wait until rules + firewall are loaded before any agent starts
for _ in $(seq 60); do
  podman exec "$POD-proxy" python3 -c 'import urllib.request;urllib.request.urlopen("http://127.0.0.1:8080/healthz")' 2>/dev/null && break
  sleep 1
done

# 3. the agent: proxy env + CA; never give it NET_ADMIN / --privileged
podman run -d --pod "$POD" --name "$POD-agent" \
  --cap-drop=NET_ADMIN --cap-drop=NET_RAW --security-opt no-new-privileges \
  -e HTTP_PROXY=http://127.0.0.1:3128 -e HTTPS_PROXY=http://127.0.0.1:3128 \
  -e http_proxy=http://127.0.0.1:3128 -e https_proxy=http://127.0.0.1:3128 \
  -e NO_PROXY=localhost,127.0.0.1 -e no_proxy=localhost,127.0.0.1 \
  -e AGENT_PROXY_CA_URL=http://127.0.0.1:8080/ca.crt \
  "$AGENT_IMAGE" "$@"

echo "web UI: http://$UI_BIND  (user: admin)"
