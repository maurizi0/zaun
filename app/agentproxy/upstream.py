"""Validation and Squid parent-proxy configuration."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import quote, unquote, urlsplit

from .rules import RuleError


def parse_url(value: str):
    # Reject control characters before urlsplit silently strips some of them.
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value):
        raise RuleError("upstream proxy URL must not contain whitespace or control characters")
    try:
        url = urlsplit(value)
        host = url.hostname or ""
        port = url.port or (443 if url.scheme == "https" else 80)
        if url.scheme not in ("http", "https") or not host or "%" in host or url.path not in ("", "/") or url.query or url.fragment:
            raise ValueError
        if url.port == 0:
            raise ValueError
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not re.fullmatch(r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9.])?", host):
                raise ValueError
    except ValueError:
        raise RuleError("upstream proxy URL must be http://host[:port] or https://host[:port]") from None
    return url, host, port


def normalize(settings: dict) -> dict:
    value = settings.get("upstream_proxy_url", "")
    if value:
        url, host, port = parse_url(value)
        if url.username is not None:
            settings["upstream_proxy_username"] = unquote(url.username)
            settings["upstream_proxy_password"] = unquote(url.password or "")
        authority = f"[{host}]" if ":" in host else host
        settings["upstream_proxy_url"] = f"{url.scheme}://{authority}:{port}"
    elif settings.get("upstream_proxy_enabled"):
        raise RuleError("an upstream proxy URL is required when enabled")
    user = settings.get("upstream_proxy_username", "")
    password = settings.get("upstream_proxy_password", "")
    if ":" in user or any(ord(c) < 32 or ord(c) == 127 for c in user + password):
        raise RuleError("upstream credentials must not contain control characters or a colon in the username")
    if user.startswith(("*", "NEGOTIATE")):
        raise RuleError("upstream proxy username must not start with '*' or 'NEGOTIATE' (reserved by Squid)")
    if password and not user:
        raise RuleError("an upstream proxy username is required with a password")
    return settings


def squid_conf(settings: dict) -> str:
    if not settings.get("upstream_proxy_enabled"):
        return ""
    url, host, port = parse_url(settings["upstream_proxy_url"])
    host = f"[{host}]" if ":" in host else host
    peer = f"cache_peer {host} parent {port} 0 no-query default name=ap_upstream"
    if url.scheme == "https":
        peer += " tls tls-default-ca=on"
    user = settings.get("upstream_proxy_username", "")
    if user:
        # Squid decodes URL escapes after reading the configuration token.
        password = settings.get("upstream_proxy_password", "")
        peer += f" login={quote(user, safe='')}:{quote(password, safe='')}"
    return peer + "\nnever_direct allow all\n"


def redact(text: str) -> str:
    return re.sub(r"login=\S+", "login=[redacted]", text)
