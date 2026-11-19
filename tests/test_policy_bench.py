"""Security contract tests; handwritten expectations in policy_bench/README.md."""
import copy
import ipaddress
from pathlib import Path
import re
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))
from agentproxy.firewall import Gateway
from agentproxy.rules import RuleError, nft_ruleset, squid_rules_conf, validate_rule


def rule(kind, target, rid="r1", **kwargs):
    return validate_rule(dict(kind=kind, target=target, name="shared", **kwargs), [], rule_id=rid)


class HttpAccess:
    """Evaluate only ordinary HTTP/HTTPS access, with explicit built-in facts.

    This consumes generated ACLs, never production pattern-parsing helpers.
    Unsupported ACL types raise rather than silently approximating Squid.
    """
    def __init__(self, text):
        self.acls = {}
        self.access = []
        for line in text.splitlines():
            if line.startswith("acl "):
                _, name, kind, *args = line.split()
                self.acls[name] = kind, args
            elif line.startswith("http_access "):
                _, verdict, *conditions = line.split()
                self.access.append((verdict, conditions))

    def decide(self, url, client="10.20.0.2", localhost=False, upgrade=False):
        label = None

        def match(token):
            nonlocal label
            if token.startswith("!"):
                return not match(token[1:])
            if token in ("all", "CONNECT", "to_localhost"):
                return {"all": True, "CONNECT": False, "to_localhost": localhost}[token]
            kind, args = self.acls[token]
            if kind == "src":
                return any(ipaddress.ip_address(client) in ipaddress.ip_network(n) for n in args)
            if kind == "annotate_transaction":
                label = args[0].removeprefix("rule=")
                return True
            if kind == "url_regex":
                insensitive = args[0] == "-i"
                return re.search(args[-1], url, re.I if insensitive else 0) is not None
            if kind == "req_header" and args == ["Upgrade", "."]:
                return upgrade
            raise AssertionError(f"Unsupported ACL: {token} {kind} {args}")

        for verdict, conditions in self.access:
            if all(match(condition) for condition in conditions):
                return verdict, label
        raise AssertionError("No explicit terminal verdict")


def policy(rules):
    return HttpAccess(squid_rules_conf(rules, ["10.20.0.0/24", "fd20::/64"]))


class SquidContractTest(unittest.TestCase):
    def test_request_matrix(self):
        # Each row supplies an independent expected verdict, not a generated regex.
        cases = [
            ("example.com", "http://example.com/", True),
            ("example.com", "https://example.com:443/x", True),
            ("example.com", "http://example.com:80/x", True),
            ("example.com", "https://example.com:8443/", False),
            ("example.com", "https://example.com.evil/", False),
            ("example.com", "https://evilexample.com/", False),
            ("*.example.com", "https://a.b.example.com/", True),
            ("*.example.com", "https://example.com/", False),
            ("https://example.com/api", "http://example.com/api", False),
            ("https://example.com/api", "https://example.com/api?x=1", True),
            ("https://example.com/api", "https://example.com/api/", False),
            ("https://example.com/api", "https://example.com/API", False),
            ("https://example.com/api*", "https://example.com/apix", True),
            ("https://example.com/a.b+(c)", "https://example.com/a.b+(c)", True),
            ("https://example.com/a.b+(c)", "https://example.com/axbcc", False),
            ("https://example.com/a%2Cb", "https://example.com/a%2Cb", True),
            ("https://example.com/a%2Cb", "https://example.com/a,b", False),
            ("[2001:db8::1]", "https://[2001:db8::1]/", True),
            ("https://example.com:8443/api", "https://example.com/api", False),
            ("https://example.com:8443/api", "https://example.com:8443/api", True),
        ]
        for target, url, allowed in cases:
            with self.subTest(target=target, url=url):
                self.assertEqual(policy([rule("allow", target)]).decide(url),
                                 ("allow", "r1_shared") if allowed else ("deny", "default-deny"))

    def test_builtin_and_default_denies(self):
        p = policy([rule("allow", "example.com")])
        for kwargs, label in [({"client": "192.0.2.1"}, "builtin-deny-client"),
                              ({"localhost": True}, "builtin-deny-localhost"),
                              ({"upgrade": True}, "default-deny")]:
            with self.subTest(kwargs=kwargs):
                self.assertEqual(p.decide("https://example.com/", **kwargs), ("deny", label))
        self.assertEqual(policy([]).decide("https://example.com/"), ("deny", "default-deny"))
        self.assertEqual(p.decide("https://example.com/", client="fd20::1"), ("allow", "r1_shared"))

    def test_denies_win_in_both_input_orders(self):
        allow = rule("allow", "example.com", "ra")
        deny = rule("deny", "*/admin*", "rd")
        for rules in ([allow, deny], [deny, allow]):
            p = policy(rules)
            for path, verdict, label in [("/ADMIN/users", "deny", "rd_shared"),
                                         ("/public", "allow", "ra_shared"),
                                         ("/%61dmin", "allow", "ra_shared"),
                                         ("/nested/admin", "allow", "ra_shared")]:
                with self.subTest(order=[r.id for r in rules], path=path):
                    self.assertEqual(p.decide("https://example.com" + path), (verdict, label))

    def test_group_cross_product_cannot_grant_access(self):
        p = policy([rule("allow", "http://one.example:8080/a, https://two.example:8443/b")])
        for scheme in ("http", "https"):
            for host in ("one.example", "two.example"):
                for port in (8080, 8443):
                    for path in ("a", "b"):
                        url = f"{scheme}://{host}:{port}/{path}"
                        allowed = url in ("http://one.example:8080/a", "https://two.example:8443/b")
                        with self.subTest(url=url):
                            self.assertEqual(p.decide(url)[0], "allow" if allowed else "deny")

    def test_disabled_rules_and_distinct_labels(self):
        rules = [rule("allow", "one.example", "ra"), rule("allow", "two.example", "rb"),
                 rule("deny", "one.example", "rd", enabled=False),
                 rule("allow", "off.example", "rc", enabled=False)]
        p = policy(rules)
        for host, expected in [("one", ("allow", "ra_shared")), ("two", ("allow", "rb_shared")),
                               ("off", ("deny", "default-deny"))]:
            self.assertEqual(p.decide(f"https://{host}.example/"), expected)

    def test_connect_bindings_and_order(self):
        conf = squid_rules_conf([rule("allow", "https://one.example:8443/a, http://two.example/b", "ra"),
                                 rule("deny", "https://one.example:8443/admin", "rd"),
                                 rule("deny", "blocked.example", "rb")], ["10.20.0.0/24"])
        self.assertEqual([line for line in conf.splitlines() if line.startswith("http_access ") and
                          " CONNECT " in line], [
            "http_access deny CONNECT ap_bumped ap_mark_default",
            "http_access deny CONNECT rb_chost rb_cport rb_mark",
            "http_access allow CONNECT !ap_bumped ra_t1_chost ra_t1_cport ra_mark",
        ])
        self.assertIn("acl ra_t1_chost dstdom_regex -n -i ^one\\.example$", conf)
        self.assertIn("acl ra_t1_cport port 8443", conf)
        self.assertIn("acl rb_cport port 443", conf)

    # Regressions from policy_bench/BUGS.md: these must pass normally.
    def test_bare_host_rejects_http_on_443(self):
        self.assertEqual(policy([rule("allow", "example.com")]).decide("http://example.com:443/"),
                         ("deny", "default-deny"))

    def test_bare_host_rejects_https_on_80(self):
        self.assertEqual(policy([rule("allow", "example.com")]).decide("https://example.com:80/"),
                         ("deny", "default-deny"))

    def test_explicit_443_cannot_allow_implicit_http_80(self):
        self.assertEqual(policy([rule("allow", "example.com:443")]).decide("http://example.com/"),
                         ("deny", "default-deny"))

    def test_explicit_80_cannot_allow_implicit_https_443(self):
        self.assertEqual(policy([rule("allow", "example.com:80")]).decide("https://example.com/"),
                         ("deny", "default-deny"))

    def test_any_host_deny_includes_ipv6(self):
        p = policy([rule("allow", "[2001:db8::1]", "ra"), rule("deny", "*/admin*", "rd")])
        self.assertEqual(p.decide("https://[2001:db8::1]/admin"), ("deny", "rd_shared"))

    def test_scheme_port_matrix_for_allows_and_denies(self):
        # Handwritten effective scheme/port pairs, independent of the parser.
        cases = [
            ("example.com", {("http", 80), ("https", 443)}),
            ("example.com:80", {("http", 80), ("https", 80)}),
            ("example.com:443", {("http", 443), ("https", 443)}),
            ("example.com:8443", {("http", 8443), ("https", 8443)}),
            ("http://example.com", {("http", 80)}),
            ("https://example.com", {("https", 443)}),
            ("http://example.com:80", {("http", 80)}),
            ("http://example.com:443", {("http", 443)}),
            ("http://example.com:8443", {("http", 8443)}),
            ("https://example.com:80", {("https", 80)}),
            ("https://example.com:443", {("https", 443)}),
            ("https://example.com:8443", {("https", 8443)}),
        ]
        fallback = rule("allow", "example.com:80, example.com:443, example.com:8443", "rf")
        for target, pairs in cases:
            for kind in ("allow", "deny"):
                p = policy([rule(kind, target + "/api")] + ([fallback] if kind == "deny" else []))
                for scheme, default_port in (("http", 80), ("https", 443)):
                    for port in (None, 80, 443, 8443):
                        authority = "example.com" + (f":{port}" if port else "")
                        for path in ("/api", "/api?x=1", "/API", "/api/", "/other"):
                            url = f"{scheme}://{authority}{path}"
                            path_matches = path in ("/api", "/api?x=1") or (kind == "deny" and path == "/API")
                            matched = (scheme, port or default_port) in pairs and path_matches
                            expected = (kind, "r1_shared") if matched else (
                                ("allow", "rf_shared") if kind == "deny" else ("deny", "default-deny"))
                            with self.subTest(target=target, kind=kind, url=url):
                                self.assertEqual(p.decide(url), expected)

    def test_default_port_group_members_keep_host_and_path_boundaries(self):
        p = policy([rule("allow", "one.example:443/a, two.example:80/b")])
        for scheme, default_port in (("http", 80), ("https", 443)):
            for host in ("one.example", "two.example", "one.example.evil"):
                for port in (None, 80, 443, 8443):
                    for path in ("/a", "/b", "/a/extra"):
                        url = f"{scheme}://{host}" + (f":{port}" if port else "") + path
                        allowed = (host, port or default_port, path) in (
                            ("one.example", 443, "/a"), ("two.example", 80, "/b"))
                        with self.subTest(url=url):
                            self.assertEqual(p.decide(url), ("allow", "r1_shared") if allowed
                                             else ("deny", "default-deny"))

    def test_another_connect_grant_cannot_broaden_url_permissions(self):
        # A second rule admits the tunnel but only grants /public inside it.
        # The first rule must not grant /private on that tunnel's port.
        for target, port, origin in (("example.com/private", 80, "https://example.com:80"),
                                     ("example.com:80/private", 443, "https://example.com")):
            rules = [rule("allow", target, "ra"),
                     rule("allow", f"https://example.com:{port}/public", "rb")]
            conf = squid_rules_conf(rules, ["10.20.0.0/24"])
            with self.subTest(target=target, port=port):
                self.assertIn(f"acl rb_cport port {port}\n", conf)
                self.assertIn("http_access allow CONNECT !ap_bumped rb_chost rb_cport rb_mark\n", conf)
                p = HttpAccess(conf)
                self.assertEqual(p.decide(origin + "/private"), ("deny", "default-deny"))
                self.assertEqual(p.decide(origin + "/public"), ("allow", "rb_shared"))

    def test_any_host_deny_preserves_scheme_port_path_and_attribution(self):
        cases = [
            ("*/admin*", {("http", 80), ("https", 443)}, True),
            ("https://*/admin", {("https", 443)}, False),
            ("*:8443/admin*", {("http", 8443), ("https", 8443)}, True),
        ]
        for host in ("example.com", "192.0.2.1", "[2001:db8::1]", "[::ffff:192.0.2.1]"):
            allow = rule("allow", ", ".join(f"{host}:{port}" for port in (80, 443, 8443)), "ra")
            for target, pairs, prefix_path in cases:
                deny = rule("deny", target, "rd")
                for rules in ([allow, deny], [deny, allow]):
                    p = policy(rules)
                    for scheme, default_port in (("http", 80), ("https", 443)):
                        for port in (None, 80, 443, 8443):
                            for path in ("/admin", "/ADMIN?x=1", "/admin/users", "/public", "/%61dmin"):
                                url = f"{scheme}://{host}" + (f":{port}" if port else "") + path
                                path_matches = path in ("/admin", "/ADMIN?x=1") or (
                                    prefix_path and path == "/admin/users")
                                denied = (scheme, port or default_port) in pairs and path_matches
                                with self.subTest(target=target, url=url, order=[r.id for r in rules]):
                                    self.assertEqual(p.decide(url), ("deny", "rd_shared") if denied
                                                     else ("allow", "ra_shared"))


class ValidationContractTest(unittest.TestCase):
    def test_invalid_inputs_leave_existing_rules_unchanged(self):
        existing = [rule("allow", "good.example")]
        before = copy.deepcopy(existing)
        cases = [
            {"kind": "allow", "target": "good.example,ftp://bad.example"},
            {"kind": "deny", "target": "good.example,,bad.example"},
            {"kind": "allow", "target": "good.example:65536"},
            {"kind": "allow", "target": "good.example:0"},
            {"kind": "allow", "target": "good.example", "name": "x\nhttp_access allow all"},
            {"kind": "tcp", "target": "*.example", "ports": "443"},
            {"kind": "tcp", "target": "192.0.2.1,192.0.2.2", "ports": "443"},
            {"kind": "tcp", "target": "192.0.2.1", "ports": "443; accept"},
            {"kind": "tcp", "target": "192.0.2.1", "ports": "443", "proto": "icmp"},
            {"kind": "tcp", "target": "192.0.2.1", "ports": "8000-7999"},
            {"kind": "tcp", "target": "192.0.2.1", "ports": "65536"},
            {"kind": "allow", "target": "good.example", "allow_websockets": "false"},
        ]
        for data in cases:
            with self.subTest(data=data):
                with self.assertRaises(RuleError):
                    validate_rule(data, existing)
                self.assertEqual(existing, before)

    def test_port_boundaries_are_valid(self):
        for ports in ("1", "65535", "1-65535", "443,8000-8100"):
            with self.subTest(ports=ports):
                self.assertEqual(rule("tcp", "192.0.2.1", ports=ports).ports, ports)


REJECT = [
    'ct state new limit rate 50/second burst 100 packets log group 1 prefix "DENY|default-deny"',
    'meta l4proto tcp reject with tcp reset',
    'reject',
]


def chains(text):
    """Extract complete chain bodies; braces inside address sets remain intact."""
    result = {}
    current = None
    for line in text.splitlines():
        if line.startswith("  chain "):
            current = line.split()[1]
            result[current] = []
        elif line == "  }":
            current = None
        elif current is not None and not line.strip().startswith("#"):
            result[current].append(line.strip())
    return result


class NftContractTest(unittest.TestCase):
    def test_empty_container_complete_policy(self):
        text = nft_ruleset([], {}, [])
        self.assertEqual(text.splitlines()[:2], ["destroy table inet agentproxy", "table inet agentproxy {"])
        self.assertEqual(chains(text), {"output": [
            "type filter hook output priority filter; policy drop;",
            'oifname "lo" accept', "ct state established,related accept", *REJECT,
        ]})
        self.assertNotIn("flush", text)

    def test_direct_rules_complete_grants_in_both_modes(self):
        rules = [rule("tcp", "192.0.2.129/24", "rnet", ports="443,8000-8100"),
                 rule("tcp", "2001:db8::53", "rdns", ports="53", proto="udp"),
                 rule("tcp", "db.example", "rdb", ports="5432"),
                 rule("tcp", "192.0.2.9", "roff", ports="22", enabled=False),
                 rule("allow", "example.com", "rweb"), rule("deny", "blocked.example", "rdeny")]
        expected = [
            'ip daddr { 192.0.2.0/24 } tcp dport { 443, 8000-8100 } ct state new log group 1 prefix "ALLOW|rnet_shared" accept',
            'ip6 daddr { 2001:db8::53/128 } udp dport { 53 } ct state new log group 1 prefix "ALLOW|rdns_shared" accept',
            'ip daddr { 192.0.2.10 } tcp dport { 5432 } ct state new log group 1 prefix "ALLOW|rdb_shared" accept',
            'ip6 daddr { 2001:db8::10 } tcp dport { 5432 } ct state new log group 1 prefix "ALLOW|rdb_shared" accept',
        ]
        for gateway in (None, Gateway("agents0", "wan0", ("10.20.0.0/24", "fd20::/64"))):
            with self.subTest(gateway=gateway):
                rendered = chains(nft_ruleset(rules, {"db.example": ["192.0.2.10", "2001:db8::10"]},
                                             ["meta skuid 31280"], gateway=gateway))
                if gateway:
                    body = rendered["agent_egress"]
                    prefix = ["ct state invalid drop", "ct state established,related accept"]
                else:
                    body = rendered["output"]
                    prefix = ["type filter hook output priority filter; policy drop;", 'oifname "lo" accept',
                              "ct state established,related accept", 'meta skuid 31280 accept comment "proxy egress"']
                self.assertEqual(body, prefix + expected + REJECT)

    def test_dns_refresh_missing_and_empty_are_closed(self):
        rules = [rule("tcp", "db.example", ports="5432")]
        for resolved, addresses in [({}, []), ({"db.example": []}, []),
                                    ({"db.example": ["192.0.2.20"]}, ["192.0.2.20"]),
                                    ({"db.example": ["2001:db8::20"]}, ["2001:db8::20"])]:
            before = copy.deepcopy((rules, resolved))
            with self.subTest(resolved=resolved):
                text = nft_ruleset(rules, resolved, [])
                grants = [line.strip() for line in text.splitlines() if "ALLOW|" in line]
                self.assertEqual(grants, [
                    f'{"ip6" if ":" in address else "ip"} daddr {{ {address} }} tcp dport {{ 5432 }} '
                    'ct state new log group 1 prefix "ALLOW|r1_shared" accept' for address in addresses])
                self.assertNotIn("192.0.2.10", text)
                self.assertEqual((rules, resolved), before)
                self.assertEqual(text, nft_ruleset(rules, resolved, []))

    def test_gateway_complete_chain_boundaries(self):
        for networks in (("10.20.0.0/24",), ("fd20::/64",), ("10.20.0.0/24", "fd20::/64")):
            for nat in (False, True):
                if nat and networks == ("fd20::/64",):
                    continue
                with self.subTest(networks=networks, nat=nat):
                    text = nft_ruleset([], {}, ["meta skuid 31280"],
                                       gateway=Gateway("agents0", "wan0", networks, nat))
                    expected = {
                        "forward": ["type filter hook forward priority filter; policy accept;",
                                    'iifname "agents0" jump from_agents', 'oifname "agents0" jump to_agents'],
                        "from_agents": [
                            f'oifname "wan0" {"ip6" if ":" in n else "ip"} saddr {{ {n} }} jump agent_egress'
                            for n in networks] + REJECT,
                        "agent_egress": ["ct state invalid drop", "ct state established,related accept", *REJECT],
                        "to_agents": [
                            f'iifname "wan0" {"ip6" if ":" in n else "ip"} daddr {{ {n} }} ct state established,related accept'
                            for n in networks] + REJECT,
                    }
                    if nat:
                        expected["postrouting"] = ["type nat hook postrouting priority srcnat; policy accept;",
                            'iifname "agents0" oifname "wan0" ip saddr { 10.20.0.0/24 } masquerade']
                    self.assertEqual(chains(text), expected)
                    self.assertEqual([l for l in text.splitlines() if "table " in l],
                                     ["destroy table inet agentproxy", "table inet agentproxy {"])
                    self.assertNotIn("flush", text)

    def test_cgroup_exemption_and_render_purity(self):
        rules = [rule("allow", "example.com"), rule("tcp", "192.0.2.1", "r2", ports="443")]
        before = copy.deepcopy(rules)
        proxy = ['socket cgroupv2 level 2 "system.slice/squid.service"']
        text = nft_ruleset(rules, {}, proxy)
        self.assertIn('socket cgroupv2 level 2 "system.slice/squid.service" accept comment "proxy egress"', text)
        self.assertNotIn("skuid", text)
        self.assertEqual(rules, before)
        self.assertEqual(text, nft_ruleset(rules, {}, proxy))
        self.assertEqual(squid_rules_conf(rules, ["127.0.0.1"]), squid_rules_conf(rules, ["127.0.0.1"]))
        self.assertEqual(rules, before)


if __name__ == "__main__":
    unittest.main()
