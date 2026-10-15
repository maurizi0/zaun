#!/bin/bash
set -euo pipefail

: "${DATA_DIR:=/data}"
: "${SQUID_UID:=31280}"
: "${UI_LISTEN:=0.0.0.0}"
: "${UI_PORT:=8080}"
: "${UI_USER:=admin}"
: "${FIREWALL_ENFORCE:=1}"
: "${VERIFY_UPSTREAM_TLS:=1}"
: "${CA_CN:=Agent Proxy CA}"
export DATA_DIR UI_LISTEN UI_PORT UI_USER FIREWALL_ENFORCE VERIFY_UPSTREAM_TLS

mkdir -p "$DATA_DIR/ca" /run/agent-proxy /var/log/agent-proxy /var/spool/squid /var/lib/agent-proxy
chown agentproxy:agentproxy /var/log/agent-proxy /var/spool/squid /var/lib/agent-proxy
chmod 0700 "$DATA_DIR/ca"

# --- CA used for TLS interception (bring your own by mounting ca.pem + ca.key)
if [ ! -s "$DATA_DIR/ca/ca.pem" ] || [ ! -s "$DATA_DIR/ca/ca.key" ]; then
  echo "entrypoint: generating new CA '$CA_CN'"
  openssl req -x509 -new -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -sha256 -days 3650 -subj "/CN=$CA_CN/O=agent-proxy" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" \
    -keyout "$DATA_DIR/ca/ca.key" -out "$DATA_DIR/ca/ca.pem" 2>/dev/null
fi
chown agentproxy:agentproxy "$DATA_DIR/ca/ca.key" "$DATA_DIR/ca/ca.pem" "$DATA_DIR/ca"
chmod 0600 "$DATA_DIR/ca/ca.key"; chmod 0644 "$DATA_DIR/ca/ca.pem"

# --- generated host-certificate cache (derived from the CA, rebuilt every start)
rm -rf /var/lib/agent-proxy/ssl_db
setpriv --reuid=agentproxy --regid=agentproxy --clear-groups \
  /usr/lib/squid/security_file_certgen -c -s /var/lib/agent-proxy/ssl_db -M 16MB >/dev/null

# --- web UI credentials
if [ -z "${UI_PASSWORD:-}" ]; then
  if [ ! -s "$DATA_DIR/ui-password" ]; then
    (umask 077; openssl rand -base64 18 > "$DATA_DIR/ui-password")
    echo "entrypoint: generated web UI password (user '$UI_USER'): $(cat "$DATA_DIR/ui-password")"
    echo "entrypoint: it is stored in $DATA_DIR/ui-password; set UI_PASSWORD to choose your own"
  fi
fi

# --- firewall / log plumbing
if [ "$FIREWALL_ENFORCE" = "1" ] || [ "$FIREWALL_ENFORCE" = "true" ]; then
  if ! nft list tables >/dev/null 2>&1; then
    echo "entrypoint: FATAL: cannot manage nftables. Run with --cap-add=NET_ADMIN" >&2
    echo "entrypoint:        (or FIREWALL_ENFORCE=0 to run squid-only, without L4 enforcement)" >&2
    exit 1
  fi
  export ULOGD_AUTOSTART=true
else
  echo "entrypoint: WARNING: FIREWALL_ENFORCE=0 - egress is NOT locked down, firewall rules are ignored" >&2
  export ULOGD_AUTOSTART=false
fi
case "$VERIFY_UPSTREAM_TLS" in 0|false|no)
  echo "entrypoint: WARNING: VERIFY_UPSTREAM_TLS=0 - upstream TLS certificates are NOT verified" >&2 ;;
esac
touch /var/log/agent-proxy/access.log /var/log/agent-proxy/firewall.json /var/log/agent-proxy/cache.log
chown agentproxy:agentproxy /var/log/agent-proxy/access.log /var/log/agent-proxy/cache.log

# --- render squid policy + load nftables before anything can talk
python3 -m agentproxy.bootstrap

exec /usr/bin/supervisord -c /etc/agent-proxy/supervisord.conf
