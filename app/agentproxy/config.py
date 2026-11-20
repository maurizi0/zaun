"""Paths, environment settings and the persistent rule store."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from .rules import Rule, RuleError, validate_rule
from . import upstream
from .firewall import deployment

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
RUN_DIR = Path(os.environ.get("RUN_DIR", "/run/agent-proxy"))
LOG_DIR = Path(os.environ.get("LOG_DIR", "/var/log/agent-proxy"))

CONFIG_FILE = DATA_DIR / "config.json"
CA_CERT = DATA_DIR / "ca" / "ca.pem"
SQUID_CONF = Path("/etc/squid/squid.conf")
SQUID_RULES = RUN_DIR / "squid-rules.conf"
SQUID_PID = RUN_DIR / "squid.pid"
NFT_FILE = RUN_DIR / "ruleset.nft"
SQUID_LOG = LOG_DIR / "access.log"
NFLOG_LOG = LOG_DIR / "firewall.json"

SQUID_UID = int(os.environ.get("SQUID_UID", "31280"))
FIREWALL_ENFORCE = os.environ.get("FIREWALL_ENFORCE", "1") not in ("0", "false", "no")
FIREWALL_MODE, GATEWAY = deployment(os.environ)
VERIFY_UPSTREAM_TLS = os.environ.get("VERIFY_UPSTREAM_TLS", "1") not in ("0", "false", "no")
DNS_REFRESH_SECONDS = int(os.environ.get("DNS_REFRESH_SECONDS", "300"))
ALLOWED_CLIENTS = os.environ.get(
    "ALLOWED_CLIENTS",
    "127.0.0.0/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 fc00::/7",
).split()
if GATEWAY and "ALLOWED_CLIENTS" not in os.environ:
    ALLOWED_CLIENTS = list(GATEWAY.networks)
LOG_BUFFER = int(os.environ.get("LOG_BUFFER", "5000"))
LOG_MAX_BYTES = int(os.environ.get("LOG_MAX_BYTES", str(50 * 1024 * 1024)))
LOG_BACKUPS = int(os.environ.get("LOG_BACKUPS", "20" if GATEWAY else "1"))

CONFIG_VERSION = 1
# runtime settings; the env values are the defaults for configs that don't set them
DEFAULT_SETTINGS = {
    "verify_upstream_tls": VERIFY_UPSTREAM_TLS,
    "upstream_proxy_enabled": bool(os.environ.get("UPSTREAM_PROXY", "")),
    "upstream_proxy_url": os.environ.get("UPSTREAM_PROXY", ""),
    "upstream_proxy_username": os.environ.get("UPSTREAM_PROXY_USER", ""),
    "upstream_proxy_password": os.environ.get("UPSTREAM_PROXY_PASSWORD", ""),
}


def atomic_write(path: Path, text: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def rules_from_export(doc: dict) -> list[Rule]:
    """Validate an exported/imported config document. Raises RuleError."""
    if not isinstance(doc, dict) or not isinstance(doc.get("rules"), list):
        raise RuleError("config must be an object with a 'rules' list")
    rules: list[Rule] = []
    seen_ids = set()
    for i, raw in enumerate(doc["rules"]):
        if not isinstance(raw, dict):
            raise RuleError(f"rule #{i + 1} is not an object")
        rid = raw.get("id")
        if not isinstance(rid, str) or not rid.isascii() or not rid.isalnum() or rid in seen_ids:
            rid = None
        try:
            rule = validate_rule(raw, rules, rule_id=rid)
        except RuleError as e:
            raise RuleError(f"rule #{i + 1} ({raw.get('name') or raw.get('target')}): {e}") from None
        if isinstance(raw.get("created"), (int, float)):
            rule.created = raw["created"]
        seen_ids.add(rule.id)
        rules.append(rule)
    return rules


def settings_from_doc(doc: dict, base: dict | None = None) -> dict:
    """Validate the 'settings' object of a config document on top of `base`. Raises RuleError."""
    settings = dict(base or DEFAULT_SETTINGS)
    raw = doc.get("settings", {})
    if not isinstance(raw, dict):
        raise RuleError("'settings' must be an object")
    for key, value in raw.items():
        if key not in DEFAULT_SETTINGS:
            raise RuleError(f"unknown setting '{key}'")
        expected = type(DEFAULT_SETTINGS[key])
        if not isinstance(value, expected):
            label = "true or false" if expected is bool else "a string"
            raise RuleError(f"setting '{key}' must be {label}")
        settings[key] = value
    return upstream.normalize(settings)


def load_settings() -> dict:
    if not CONFIG_FILE.exists():
        return settings_from_doc({})
    return settings_from_doc(json.loads(CONFIG_FILE.read_text()))


def load_rules() -> list[Rule]:
    if not CONFIG_FILE.exists():
        return []
    return rules_from_export(json.loads(CONFIG_FILE.read_text()))


def export_doc(rules: list[Rule], settings: dict) -> dict:
    return {
        "version": CONFIG_VERSION,
        "default": "deny",
        "settings": settings,
        "rules": [r.to_dict() for r in rules],
    }


def save_config(rules: list[Rule], settings: dict) -> None:
    atomic_write(CONFIG_FILE, json.dumps(export_doc(rules, settings), indent=2) + "\n", 0o600)
