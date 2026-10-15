FROM docker.io/library/debian:trixie-slim

ARG SQUID_UID=31280

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      squid-openssl nftables ulogd2 ulogd2-json openssl ca-certificates \
      supervisor util-linux procps \
      python3 python3-fastapi python3-uvicorn \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g ${SQUID_UID} agentproxy \
 && useradd -M -u ${SQUID_UID} -g agentproxy -d /var/spool/squid -s /usr/sbin/nologin agentproxy

COPY rootfs/ /
COPY app/ /opt/agent-proxy/

ENV PYTHONPATH=/opt/agent-proxy \
    PYTHONUNBUFFERED=1 \
    SQUID_UID=${SQUID_UID} \
    DATA_DIR=/data

RUN chmod 0755 /usr/local/bin/entrypoint.sh

VOLUME ["/data"]
# 3128: proxy for agents, 8080: web UI
EXPOSE 3128 8080

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
