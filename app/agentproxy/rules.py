"""Rule model, validation and translation into squid / nftables config.

Rule kinds:
  allow - HTTP(S) target the agents may reach through squid
  deny  - HTTP(S) target that is always refused, evaluated before every allow rule
  tcp   - non-HTTP L4 target (ip/cidr/hostname + ports) enforced with nftables

Everything not matched by an allow/tcp rule hits the implicit default deny.
"""
from __future__ import annotations

import ipaddress
import re
import secrets
import time
from dataclasses import asdict, dataclass, field
from .firewall import Gateway

KINDS = ("allow", "deny", "tcp")
PROTOS = ("tcp", "udp")
DEFAULT_RULE = "default-deny"
DENY_PAGE = "ERR_AGENT_DENIED"  # /usr/share/squid-langpack/templates/ERR_AGENT_DENIED

NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,48}$")
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?\.)*[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?\.?$")
PATTERN_RE = re.compile(
    r"^(?:(?P<scheme>[A-Za-z]+)://)?"
    r"(?P<host>\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9*._-]+)"
    r"(?::(?P<port>[0-9]{1,5}))?"
    r"(?P<path>/[^\s\"']*)?$"
)
DEFAULT_PORTS = {"http": 80, "https": 443}


class RuleError(ValueError):
    pass


# --------------------------------------------------------------------------- model

@dataclass
class Rule:
    id: str
    kind: str
    name: str
    target: str
    ports: str = ""          # tcp only, e.g. "3306" or "5432,8000-8100"
    proto: str = "tcp"       # tcp only
    enabled: bool = True
    comment: str = ""
    created: float = field(default_factory=time.time)
    allow_websockets: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def new_id() -> str:
    return "r" + secrets.token_hex(4)


def sanitize_name(raw: str) -> str:
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", raw.strip())
    name = re.sub(r"[_.-]*_[_.-]*", "_", name).strip("_.-")
    return name[:48] or "rule"


def validate_rule(data: dict, existing: list[Rule], rule_id: str | None = None) -> Rule:
    """Build a validated Rule from user input. Raises RuleError."""
    kind = str(data.get("kind", "")).strip()
    if kind not in KINDS:
        raise RuleError(f"kind must be one of {', '.join(KINDS)}")
    target = str(data.get("target", "")).strip()
    if not target:
        raise RuleError("target is required")

    allow_websockets = data.get("allow_websockets", False)
    if not isinstance(allow_websockets, bool):
        raise RuleError("allow_websockets must be true or false")
    if allow_websockets and kind != "allow":
        raise RuleError("allow_websockets is only supported on proxy allow rules")

    ports, proto = "", "tcp"
    if kind == "tcp":
        parse_tcp_target(target)
        proto = str(data.get("proto") or "tcp").lower()
        if proto not in PROTOS:
            raise RuleError("proto must be tcp or udp")
        ports = normalize_ports(str(data.get("ports", "")))
    else:
        target = ", ".join(parse_proxy_targets(target))

    name = str(data.get("name") or "").strip()
    if not name:
        name = sanitize_name(f"{kind}_{target}")
    if not NAME_RE.match(name):
        raise RuleError("name may only contain letters, digits, '.', '_' and '-' (max 48)")
    if name == DEFAULT_RULE:
        raise RuleError(f"'{DEFAULT_RULE}' is reserved")

    return Rule(
        id=rule_id or new_id(),
        kind=kind,
        name=name,
        target=target,
        ports=ports,
        proto=proto,
        enabled=bool(data.get("enabled", True)),
        allow_websockets=allow_websockets,
        comment=str(data.get("comment", ""))[:200],
    )


# --------------------------------------------------------------------------- HTTP patterns

def ere_escape(s: str) -> str:
    """Escape for POSIX extended regex (what squid uses)."""
    return "".join("\\" + c if c in ".^$|()[]{}*+?\\" else c for c in s)


def glob_to_ere(s: str, star: str) -> str:
    return star.join(ere_escape(p) for p in s.split("*"))


@dataclass
class HttpPattern:
    scheme: str | None   # None = http and https
    host: str            # lowercase, may contain '*'
    port: int | None     # None = implicit port scope
    path: str | None     # None = any path

    @property
    def schemes(self) -> list[str]:
        return [self.scheme] if self.scheme else ["http", "https"]

    def url_regex(self, *, all_ports: bool = False) -> str:
        """Regex matched against squid's absolute request URL (scheme://host[:port]/path?query)."""
        host_re = glob_to_ere(self.host, "[^][/:@?#]*")
        if self.host == "*":
            # A whole-host wildcard includes bracketed IPv6 literals. Keep
            # brackets/colons out of the DNS branch so ports cannot be swallowed.
            host_re = r"(\[[0-9A-Fa-f:.]+\]|[^][/:@?#]+)"
        origins = []
        for scheme in self.schemes:
            port = self.port or DEFAULT_PORTS[scheme]
            # Squid may omit a default port, but only for this scheme.
            port_re = f"(:{port})?" if port == DEFAULT_PORTS[scheme] else f":{port}"
            if all_ports:
                port_re = "(:[0-9]+)?"
            origins.append(f"{scheme}://{host_re}{port_re}")
        origin_re = "(" + "|".join(origins) + ")"
        if self.path is None:
            path_re = "([/?].*)?$"
        else:
            path_re = glob_to_ere(self.path, ".*")
            if not self.path.endswith("*"):
                path_re += "([?].*)?"
            path_re += "$"
        return f"^{origin_re}{path_re}"

    def connect_host_regex(self) -> str:
        host = self.host.strip("[]")
        return "^" + glob_to_ere(host, "[^/:@]*") + "$"

    @property
    def connect_port(self) -> int:
        return self.port or 443

    def applies_to_connect(self, for_deny: bool) -> bool:
        """Should this pattern produce a CONNECT (TLS tunnel) ACL?

        allow: any https-capable pattern, so the bumped requests inside can be checked.
        deny:  only whole-host patterns; path denies are enforced on the decrypted requests.
        """
        if self.scheme not in (None, "https"):
            return False
        return not for_deny or self.path is None


def parse_proxy_targets(target: str) -> list[str]:
    """Split a proxy group, validating every member before applying any of it."""
    targets = [part.strip() for part in target.split(",")]
    if any(not part for part in targets):
        raise RuleError("target groups must contain non-empty targets separated by commas")
    for part in targets:
        parse_pattern(part)
    return targets


def parse_pattern(target: str) -> HttpPattern:
    m = PATTERN_RE.match(target.strip())
    if not m:
        raise RuleError("target must look like host, *.host, scheme://host[:port][/path*] or an IP")
    scheme = (m.group("scheme") or "").lower() or None
    if scheme and scheme not in DEFAULT_PORTS:
        raise RuleError("scheme must be http or https")
    host = m.group("host").lower()
    if host.startswith("["):
        try:
            ipaddress.IPv6Address(host[1:-1])
        except ValueError:
            raise RuleError(f"invalid IPv6 address {host}") from None
    elif "*" in host:
        if not HOSTNAME_RE.match(host.replace("*", "x")):
            raise RuleError(f"invalid host pattern {host}")
    elif not HOSTNAME_RE.match(host):
        raise RuleError(f"invalid host {host}")
    port = int(m.group("port")) if m.group("port") else None
    if port is not None and not 0 < port < 65536:
        raise RuleError("port out of range")
    path = m.group("path")
    if path in ("/*", "*"):
        path = None
    return HttpPattern(scheme, host, port, path)


# --------------------------------------------------------------------------- L4 targets

def parse_tcp_target(target: str) -> ipaddress._BaseNetwork | str:
    """Returns an ip_network or a hostname (resolved at apply time)."""
    t = target.strip()
    try:
        return ipaddress.ip_network(t, strict=False)
    except ValueError:
        pass
    if "*" in t or not HOSTNAME_RE.match(t) or t.replace(".", "").isdigit():
        raise RuleError("tcp target must be an IP, a CIDR or a hostname")
    return t.lower().rstrip(".")


def normalize_ports(raw: str) -> str:
    raw = raw.replace(" ", "")
    if not raw:
        raise RuleError("ports are required for firewall rules (e.g. 3306 or 8000-8100)")
    out = []
    for part in raw.split(","):
        m = re.fullmatch(r"(\d{1,5})(?:-(\d{1,5}))?", part)
        if not m:
            raise RuleError(f"invalid port spec '{part}'")
        lo, hi = int(m.group(1)), int(m.group(2) or m.group(1))
        if not (0 < lo <= hi < 65536):
            raise RuleError(f"invalid port range '{part}'")
        out.append(str(lo) if lo == hi else f"{lo}-{hi}")
    return ",".join(out)


# --------------------------------------------------------------------------- squid

def squid_rules_conf(rules: list[Rule], allowed_clients: list[str],
                     verify_upstream_tls: bool = True) -> str:
    """The policy part of squid.conf (included by the static base config)."""
    lines = [
        "# Generated by agent-proxy - do not edit, changes are overwritten.",
    ]
    if not verify_upstream_tls:
        # keep verifying (so the error ACLs are set) but ignore the errors, and sign the
        # bumped cert with the trusted CA, fixing dates and name, so agents accept it too
        lines += [
            "# VERIFY_UPSTREAM_TLS=0: upstream certificate errors are ignored",
            "sslproxy_cert_error allow all",
            "sslproxy_cert_sign signTrusted all",
            "sslproxy_cert_adapt setValidAfter ssl::certHasExpired",
            "sslproxy_cert_adapt setValidBefore ssl::certNotYetValid",
            "sslproxy_cert_adapt setCommonName ssl::certDomainMismatch",
            "",
        ]
    lines += [
        f"acl ap_clients src {' '.join(allowed_clients)}",
        f"acl ap_mark_default annotate_transaction rule={DEFAULT_RULE}",
        "acl ap_mark_builtin annotate_transaction rule=builtin-deny-localhost",
        "acl ap_mark_clients annotate_transaction rule=builtin-deny-client",
        "acl ap_upgrade req_header Upgrade .",
        "acl ap_websocket req_header Upgrade -i ^[[:space:]]*websocket[[:space:]]*$",
        "acl ap_mark_bumped annotate_client ap_bumped=true",
        "acl ap_bumped note ap_bumped true",
        "acl ap_http proto HTTP",
        "acl ap_https proto HTTPS",
        "",
        "http_access deny !ap_clients ap_mark_clients",
        "http_access deny to_localhost ap_mark_builtin",
        "http_access deny CONNECT ap_bumped ap_mark_default",
    ]
    # squid picks the error page from the last ACL on the denying line
    deny_marks = ["ap_mark_clients", "ap_mark_builtin", "ap_mark_default"]
    active = [r for r in rules if r.enabled and r.kind in ("allow", "deny")]
    acls, access, upgrades, websocket_access, bindings = [], [], [], [], []
    # deny rules first: they win over every allow rule
    for r in sorted(active, key=lambda r: r.kind != "deny"):
        targets = parse_proxy_targets(r.target)
        acls.append(f"# {r.kind} {r.name}: {r.target}")
        acls.append(f"acl {r.id}_mark annotate_transaction rule={r.id}_{r.name}")
        if r.kind == "deny":
            deny_marks.append(f"{r.id}_mark")
        for index, target in enumerate(targets):
            # Keep single-target ACL names compatible; group members need
            # separate host/port bindings to avoid cross-matching targets.
            aid = r.id if len(targets) == 1 else f"{r.id}_t{index + 1}"
            p = parse_pattern(target)
            all_ports = r.kind == "deny" and p.scheme is None and p.port is None
            verb = "deny" if r.kind == "deny" else "allow"
            flags = "-i " if r.kind == "deny" else ""
            acls.append(f"acl {aid}_url url_regex {flags}{p.url_regex(all_ports=all_ports)}")
            if r.kind == "allow" and r.allow_websockets:
                # At SslBump1, dstdom/port still identify the original CONNECT.
                # Evaluate every binding, including overlapping rules. A false
                # host/port match skips annotation; a true match annotates the
                # connection, not just the CONNECT transaction.
                if p.applies_to_connect(for_deny=False):
                    acls += [
                        f"acl {aid}_ws_mark annotate_client ap_ws_{aid}=true",
                        f"acl {aid}_ws_bound note ap_ws_{aid} true",
                        f"acl {aid}_ws_name ssl::server_name_regex --client-requested -i {p.connect_host_regex()}",
                    ]
                    bindings.append(aid)
                guards = []
                if "http" in p.schemes:
                    guards.append("ap_http !ap_bumped")
                if "https" in p.schemes:
                    guards.append(f"ap_https ap_bumped {aid}_ws_bound {aid}_ws_name")
                for guard in guards:
                    match = f"{aid}_url {guard}"
                    upgrades.append(f"http_upgrade_request_protocols websocket allow {match}")
                    websocket_access.append(f"http_access allow !CONNECT ap_websocket {match} {r.id}_mark")
            upgrade_guard = "!ap_upgrade " if r.kind == "allow" else ""
            access.append(f"http_access {verb} !CONNECT {upgrade_guard}{aid}_url {r.id}_mark")
            if p.applies_to_connect(for_deny=r.kind == "deny"):
                acls.append(f"acl {aid}_chost dstdom_regex -n -i {p.connect_host_regex()}")
                ports = "1-65535" if all_ports else str(p.connect_port)
                acls.append(f"acl {aid}_cport port {ports}")
                bump_guard = "!ap_bumped " if r.kind == "allow" else ""
                access.append(f"http_access {verb} CONNECT {bump_guard}{aid}_chost {aid}_cport {r.id}_mark")
    # any-of short-circuits before the side effect when the CONNECT does not
    # match. Each conditional ACL always returns true, so all-of visits every
    # rule. This runs only at SslBump1, never on the rewritten CONNECT at step 2.
    for rid in bindings:
        acls.append(f"acl {rid}_ws_bind any-of !{rid}_chost !{rid}_cport {rid}_ws_mark")
    binding_acls = " ".join(f"{rid}_ws_bind" for rid in bindings) or "all"
    acls.append(f"acl ap_ws_bind all-of {binding_acls}")
    # Denies always win. Upgrade attempts must match an opted-in rule before
    # any ordinary allow can accept them (including overlapping allow rules).
    deny_access = [line for line in access if line.startswith("http_access deny ")]
    allow_access = [line for line in access if line.startswith("http_access allow ")]
    lines += [""] + acls + [""] + upgrades + [
        "http_upgrade_request_protocols websocket deny all",
        "http_upgrade_request_protocols OTHER deny all",
        "",
    ] + deny_access + websocket_access + [
        "http_access deny !CONNECT ap_upgrade ap_mark_default",
    ] + allow_access
    lines += ["", "# default rule: always deny", "http_access deny all ap_mark_default", ""]
    lines += [f"deny_info {DENY_PAGE} {m}" for m in deny_marks] + [""]
    return "\n".join(lines)


# --------------------------------------------------------------------------- nftables

NFT_TABLE = "agentproxy"
NFLOG_GROUP = 1


def nft_ruleset(rules: list[Rule], resolved: dict[str, list[str]], proxy_matches: list[str],
                *, gateway: Gateway | None = None) -> str:
    """Complete, atomically loadable script for container output or gateway forwarding.

    `resolved` maps hostname targets to their current addresses.
    `proxy_matches` are nft match expressions identifying the proxy's own sockets
    (which are exempt: squid has to reach the internet).
    """
    if gateway:
        return gateway_ruleset(rules, resolved, gateway)
    out = [
        f"destroy table inet {NFT_TABLE}",
        f"table inet {NFT_TABLE} {{",
        "  chain output {",
        "    type filter hook output priority filter; policy drop;",
        '    oifname "lo" accept',
        "    ct state established,related accept",
    ]
    out += [f'    {m} accept comment "proxy egress"' for m in proxy_matches]
    out += _nft_allow_rules(rules, resolved)
    out += _nft_reject_rules() + ["  }", "}", ""]
    return "\n".join(out)


def _nft_allow_rules(rules: list[Rule], resolved: dict[str, list[str]]) -> list[str]:
    out = []
    for r in rules:
        if not r.enabled or r.kind != "tcp":
            continue
        target = parse_tcp_target(r.target)
        addrs = [str(target)] if not isinstance(target, str) else resolved.get(target, [])
        v4 = [a for a in addrs if ":" not in a]
        v6 = [a for a in addrs if ":" in a]
        ports = r.ports.replace(",", ", ")
        prefix = f"ALLOW|{r.id}_{r.name}"
        out.append(f"    # {r.name}: {r.target} {r.proto}/{r.ports}")
        if not addrs:
            out.append("    # (unresolved - no addresses)")
        for fam, lst in (("ip", v4), ("ip6", v6)):
            if lst:
                out.append(
                    f"    {fam} daddr {{ {', '.join(lst)} }} {r.proto} dport {{ {ports} }} "
                    f'ct state new log group {NFLOG_GROUP} prefix "{prefix}" accept'
                )
    return out


def _nft_reject_rules() -> list[str]:
    return [
        f'    ct state new limit rate 50/second burst 100 packets log group {NFLOG_GROUP} prefix "DENY|{DEFAULT_RULE}"',
        "    meta l4proto tcp reject with tcp reset",
        "    reject",
    ]


def gateway_ruleset(rules: list[Rule], resolved: dict[str, list[str]], gateway: Gateway) -> str:
    """Guard both directions on a dedicated agent interface, including IPv6.

    Source checks precede conntrack. Other host tables and INPUT/OUTPUT are untouched.
    """
    lan, wan = gateway.agent_interface, gateway.uplink_interface
    networks = {v: [n for n in gateway.networks if ipaddress.ip_network(n).version == v]
                for v in (4, 6)}
    out = [f"destroy table inet {NFT_TABLE}", f"table inet {NFT_TABLE} {{",
           "  chain forward {", "    type filter hook forward priority filter; policy accept;",
           f'    iifname "{lan}" jump from_agents',
           f'    oifname "{lan}" jump to_agents', "  }", "  chain from_agents {"]
    for version, family in ((4, "ip"), (6, "ip6")):
        if networks[version]:
            out.append(f'    oifname "{wan}" {family} saddr {{ {", ".join(networks[version])} }} jump agent_egress')
    out += _nft_reject_rules() + ["  }", "  chain agent_egress {",
                                "    ct state invalid drop",
                                "    ct state established,related accept"]
    out += _nft_allow_rules(rules, resolved) + _nft_reject_rules()
    out += ["  }", "  chain to_agents {"]
    for version, family in ((4, "ip"), (6, "ip6")):
        if networks[version]:
            out.append(f'    iifname "{wan}" {family} daddr {{ {", ".join(networks[version])} }} ct state established,related accept')
    out += _nft_reject_rules() + ["  }"]
    if gateway.masquerade:
        out += ["  chain postrouting {",
                "    type nat hook postrouting priority srcnat; policy accept;",
                f'    iifname "{lan}" oifname "{wan}" ip saddr {{ {", ".join(networks[4])} }} masquerade',
                "  }"]
    return "\n".join(out + ["}", ""])
