"""Run: python3 -m unittest discover -s tests   (from the repo root)"""
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))

from agentproxy import config as cfg  # noqa: E402
from agentproxy.rules import (  # noqa: E402
    Rule, RuleError, nft_ruleset, normalize_ports, parse_pattern, squid_rules_conf, validate_rule,
)


def matches(pattern: str, url: str) -> bool:
    # the generated ERE subset is also valid Python regex syntax
    return re.search(parse_pattern(pattern).url_regex(), url) is not None


class PatternTest(unittest.TestCase):
    def test_exact_host(self):
        self.assertTrue(matches("test.host.io", "https://test.host.io/x?y=1"))
        self.assertTrue(matches("test.host.io", "http://test.host.io/"))
        self.assertFalse(matches("test.host.io", "https://test.host.io.evil.com/"))
        self.assertFalse(matches("test.host.io", "https://xtest.host.io/"))
        self.assertFalse(matches("test.host.io", "https://test.host.io:8443/"))

    def test_wildcard(self):
        self.assertTrue(matches("*.host.io", "https://a.host.io/"))
        self.assertTrue(matches("*.host.io", "https://a.b.host.io/"))
        self.assertFalse(matches("*.host.io", "https://host.io/"))
        self.assertFalse(matches("*.host.io", "https://ahost.io/"))

    def test_partial_wildcard_host_boundaries(self):
        pattern = "*.example.com"
        self.assertFalse(matches(pattern, "http://other.test?q=.example.com/"))
        self.assertFalse(matches(pattern, "http://other.test#.example.com/"))
        self.assertTrue(matches(pattern, "http://api.example.com/?q=1"))

    def test_scheme_and_path(self):
        self.assertTrue(matches("http://test.io", "http://test.io/anything"))
        self.assertFalse(matches("http://test.io", "https://test.io/"))
        self.assertTrue(matches("http://test.io/*", "http://test.io/a/b"))
        self.assertTrue(matches("https://x.io/api/*", "https://x.io/api/v1"))
        self.assertFalse(matches("https://x.io/api/*", "https://x.io/admin"))
        self.assertTrue(matches("https://x.io/health", "https://x.io/health?full=1"))
        self.assertFalse(matches("https://x.io/health", "https://x.io/healthz"))

    def test_ip_and_port(self):
        self.assertTrue(matches("42.42.42.42", "http://42.42.42.42/"))
        self.assertFalse(matches("42.42.42.42", "http://42.42.42.420/"))
        self.assertTrue(matches("42.42.42.42:8080", "http://42.42.42.42:8080/"))
        self.assertFalse(matches("42.42.42.42:8080", "http://42.42.42.42/"))

    def test_connect(self):
        p = parse_pattern("https://x.io/api/*")
        self.assertTrue(p.applies_to_connect(for_deny=False))
        self.assertFalse(p.applies_to_connect(for_deny=True))
        self.assertFalse(parse_pattern("http://x.io").applies_to_connect(for_deny=False))
        self.assertTrue(parse_pattern("x.io").applies_to_connect(for_deny=True))

    def test_any_host_ipv6_boundaries(self):
        for authority in ("example.com", "192.0.2.1", "[2001:db8::1]", "[2001:DB8::1]",
                          "[::ffff:192.0.2.1]"):
            for scheme, port in (("http", 80), ("https", 443)):
                with self.subTest(authority=authority, scheme=scheme):
                    self.assertTrue(matches("*/admin*", f"{scheme}://{authority}/admin"))
                    self.assertTrue(matches("*/admin*", f"{scheme}://{authority}:{port}/admin"))
        for authority in ("", "[2001:db8::1", "2001:db8::1]", "2001:db8::1",
                          "[2001:db8::1].evil", "[2001:db8::1]@evil.example",
                          "user@[2001:db8::1]", "[2001:db8::1]:8443", "[2001:db8::1]:80",
                          "example.com:8443", "example.com?redirect=", "example.com#"):
            with self.subTest(authority=authority):
                self.assertFalse(matches("*/admin*", f"https://{authority}/admin"))
        self.assertFalse(matches("*.example.com/admin*", "https://[2001:db8::1]/admin"))

    def test_invalid(self):
        for bad in ("", "ftp://x.io", "x io", "a..b", "http://", "x.io:99999"):
            with self.assertRaises(RuleError, msg=bad):
                parse_pattern(bad)


class RuleTest(unittest.TestCase):
    def test_import_preserves_only_ascii_alphanumeric_ids(self):
        ids = ["Rule42", "¹ᵃ٣", "Rule٤2"]
        rules = cfg.rules_from_export({"rules": [
            {"id": rid, "kind": "allow", "target": "example.com"} for rid in ids
        ]})
        self.assertEqual(rules[0].id, "Rule42")
        for rule in rules[1:]:
            self.assertRegex(rule.id, r"\A[A-Za-z0-9]+\Z")

    def test_any_host_path_deny(self):
        deny = validate_rule({"kind": "deny", "target": "*/admin*"}, [])
        allow = Rule("allow1", "allow", "site", "example.com")
        conf = squid_rules_conf([allow, deny], ["127.0.0.1"])
        prefix = f"acl {deny.id}_url url_regex -i "
        regex = next(line[len(prefix):] for line in conf.splitlines() if line.startswith(prefix))
        for url in ("http://example.com/admin", "https://other.org/ADMIN/users?x=1",
                    "https://example.com:8443/admin"):
            self.assertIsNotNone(re.search(regex, url, re.I))
        for url in ("https://example.com/public", "https://example.com/nested/admin",
                    "https://example.com:8443/public", "https://example.com/%61dmin"):
            self.assertIsNone(re.search(regex, url, re.I))
        self.assertNotIn(f"acl {deny.id}_chost", conf)
        self.assertLess(conf.index(f"http_access deny !CONNECT {deny.id}_url"),
                        conf.index("http_access allow !CONNECT !ap_upgrade allow1_url"))
        self.assertTrue(matches("*/*admin*", "https://example.com/nested/admin/users"))

    def test_ports(self):
        self.assertEqual(normalize_ports(" 3306, 8000-8100 "), "3306,8000-8100")
        for bad in ("", "0", "70000", "10-5", "a"):
            with self.assertRaises(RuleError):
                normalize_ports(bad)

    def test_validate_and_names(self):
        r1 = validate_rule({"kind": "allow", "target": "*.host.io"}, [])
        self.assertEqual(r1.name, "allow_host.io")
        r2 = validate_rule({"kind": "allow", "target": "*.host.io"}, [r1])
        self.assertEqual(r2.name, r1.name)
        self.assertNotEqual(r2.id, r1.id)
        r3 = validate_rule({"kind": "allow", "target": "x.io", "name": r1.name}, [r1])
        self.assertEqual(r3.name, r1.name)
        self.assertNotEqual(r3.id, r1.id)
        t = validate_rule({"kind": "tcp", "target": "42.42.42.42", "ports": "3306"}, [])
        self.assertEqual(t.proto, "tcp")
        with self.assertRaises(RuleError):
            validate_rule({"kind": "tcp", "target": "*.x.io", "ports": "1"}, [])

    def test_duplicate_names_round_trip_and_edit(self):
        rules = [
            Rule("r1", "allow", "shared", "one.io"),
            Rule("r2", "deny", "shared", "two.io"),
            Rule("r3", "tcp", "shared", "42.42.42.42", ports="3306"),
            Rule("r4", "tcp", "shared", "42.42.42.43", ports="5432"),
        ]
        restored = cfg.rules_from_export(cfg.export_doc(rules, cfg.DEFAULT_SETTINGS))
        self.assertEqual([r.to_dict() for r in restored], [r.to_dict() for r in rules])
        edited = validate_rule({**rules[0].to_dict(), "target": "new.io"}, rules, rule_id="r1")
        self.assertEqual((edited.id, edited.name, edited.target), ("r1", "shared", "new.io"))
        sq = squid_rules_conf(restored, ["127.0.0.1"])
        for rid in ("r1", "r2"):
            self.assertIn(f"acl {rid}_mark annotate_transaction rule={rid}_shared", sq)
        nft = nft_ruleset(restored, {}, [])
        for rid in ("r3", "r4"):
            self.assertIn(f'prefix "ALLOW|{rid}_shared"', nft)

    def test_generated_configs(self):
        rules = [
            Rule("r1", "allow", "hostio", "*.host.io"),
            Rule("r2", "deny", "nodeadmin", "http://test.io/*"),
            Rule("r3", "tcp", "mysql", "42.42.42.42", ports="3306"),
            Rule("r4", "tcp", "pg", "db.example", ports="5432"),
            Rule("r5", "allow", "off", "off.io", enabled=False),
        ]
        sq = squid_rules_conf(rules, ["127.0.0.1"])
        self.assertLess(sq.index("http_access deny !CONNECT r2_url"), sq.index("http_access allow !CONNECT !ap_upgrade r1_url"))
        self.assertIn("\nhttp_access deny all ap_mark_default\n", sq)
        for mark in ("ap_mark_default", "ap_mark_builtin", "ap_mark_clients", "r2_mark"):
            self.assertIn(f"deny_info ERR_AGENT_DENIED {mark}\n", sq)
        self.assertNotIn("deny_info ERR_AGENT_DENIED r1_mark", sq)
        self.assertNotIn("r5_", sq)
        self.assertNotIn("r2_chost", sq)  # http:// deny never matches CONNECT
        nft = nft_ruleset(rules, {"db.example": ["10.0.0.5", "fd00::5"]}, ["meta skuid 31280"])
        self.assertIn('ip daddr { 42.42.42.42/32 } tcp dport { 3306 }', nft)
        self.assertIn('ip6 daddr { fd00::5 } tcp dport { 5432 }', nft)
        self.assertIn("policy drop", nft)

    def test_legacy_allow_only_grants_connect_before_bump(self):
        rules = cfg.rules_from_export({"rules": [
            {"id": "legacy", "kind": "allow", "target": "https://testing.io/public"}
        ]})
        conf = squid_rules_conf(rules, ["127.0.0.1"])
        access = [line for line in conf.splitlines() if line.startswith("http_access ")]
        self.assertEqual(access[:3], [
            "http_access deny !ap_clients ap_mark_clients",
            "http_access deny to_localhost ap_mark_builtin",
            "http_access deny CONNECT ap_bumped ap_mark_default",
        ])
        self.assertIn("http_access allow CONNECT !ap_bumped legacy_chost legacy_cport legacy_mark", access)
        self.assertFalse(rules[0].allow_websockets)

    def test_websocket_validation_and_persistence(self):
        data = {"kind": "allow", "target": "https://testing.io/socket/*"}
        self.assertFalse(validate_rule(data, []).allow_websockets)
        rule = validate_rule({**data, "allow_websockets": True}, [])
        restored = cfg.rules_from_export(cfg.export_doc([rule], cfg.DEFAULT_SETTINGS))
        self.assertTrue(restored[0].allow_websockets)
        for value in ("false", "true", 0, 1, None):
            with self.assertRaises(RuleError):
                validate_rule({**data, "allow_websockets": value}, [])
        for kind in ("deny", "tcp"):
            with self.assertRaises(RuleError):
                validate_rule({**data, "kind": kind, "allow_websockets": True}, [])

    def test_websocket_default_deny_and_opt_in(self):
        regular = Rule("r1", "allow", "ordinary", "testing.io")
        ws = Rule("r2", "allow", "socket", "https://testing.io:8443/socket/*",
                  allow_websockets=True)
        deny = Rule("r3", "deny", "private", "https://testing.io:8443/socket/private/*")
        disabled = Rule("r4", "allow", "disabled", "other.io", enabled=False,
                        allow_websockets=True)
        default = squid_rules_conf([regular], ["127.0.0.1"])
        self.assertNotIn("http_upgrade_request_protocols websocket allow", default)
        self.assertIn("http_upgrade_request_protocols websocket deny all", default)
        self.assertIn("http_upgrade_request_protocols OTHER deny all", default)
        sq = squid_rules_conf([regular, ws, deny, disabled], ["127.0.0.1"])
        self.assertIn("http_upgrade_request_protocols websocket allow r2_url", sq)
        self.assertNotIn("websocket allow r1_url", sq)
        self.assertNotIn("r4_", sq)
        deny_line = "http_access deny !CONNECT r3_url"
        bound = "ap_https ap_bumped r2_ws_bound r2_ws_name"
        ws_line = f"http_access allow !CONNECT ap_websocket r2_url {bound} r2_mark"
        self.assertIn(f"http_upgrade_request_protocols websocket allow r2_url {bound}", sq)
        self.assertIn("acl r2_ws_bind any-of !r2_chost !r2_cport r2_ws_mark", sq)
        self.assertIn("acl ap_ws_bind all-of r2_ws_bind", sq)
        guard = "http_access deny !CONNECT ap_upgrade ap_mark_default"
        regular_line = "http_access allow !CONNECT !ap_upgrade r1_url"
        self.assertLess(sq.index(deny_line), sq.index(ws_line))
        self.assertLess(sq.index(ws_line), sq.index(guard))
        self.assertLess(sq.index(guard), sq.index(regular_line))
        pattern = parse_pattern(ws.target)
        for url in ("https://sub.testing.io:8443/socket/a",
                    "https://testing.io.evil:8443/socket/a",
                    "https://testing.io/socket/a", "http://testing.io:8443/socket/a",
                    "https://testing.io:8443/other"):
            self.assertIsNone(re.search(pattern.url_regex(), url), url)
        self.assertIsNotNone(re.search(pattern.url_regex(),
                                      "https://testing.io:8443/socket/a"))
        self.assertIn("http_access allow CONNECT !ap_bumped r2_chost r2_cport", sq)

    def test_websocket_connection_binding_for_overlapping_rules(self):
        sq = squid_rules_conf([
            Rule("r1", "allow", "ordinary", "*.example.com"),
            Rule("r2", "allow", "wide", "*.example.com", allow_websockets=True),
            Rule("r3", "allow", "narrow", "https://one.example.com:8443/socket",
                 allow_websockets=True),
            Rule("r4", "allow", "plain", "http://plain.example.com", allow_websockets=True),
        ], ["127.0.0.1"])
        self.assertIn("acl ap_ws_bind all-of r2_ws_bind r3_ws_bind", sq)
        self.assertNotIn("r1_ws_mark", sq)
        self.assertNotIn("r4_ws_bound", sq)
        self.assertIn("websocket allow r2_url ap_http !ap_bumped", sq)
        self.assertIn("websocket allow r4_url ap_http !ap_bumped", sq)
        self.assertNotIn("websocket allow r4_url ap_https", sq)
        self.assertIn("acl r3_cport port 8443", sq)
        self.assertIn("acl r3_ws_name ssl::server_name_regex --client-requested -i ^one\\.example\\.com$", sq)

    def test_proxy_target_groups(self):
        raw = {"kind": "allow", "name": "group", "target":
               " https://test.host.io,*.host2.io, https://host3.io/api ",
               "allow_websockets": True}
        rule = validate_rule(raw, [], rule_id="rgroup")
        self.assertEqual(rule.target,
                         "https://test.host.io, *.host2.io, https://host3.io/api")
        restored = cfg.rules_from_export(cfg.export_doc([rule], cfg.DEFAULT_SETTINGS))
        self.assertEqual(restored[0].to_dict(), rule.to_dict())
        sq = squid_rules_conf(restored, ["127.0.0.1"])
        self.assertEqual(sq.count("annotate_transaction rule=rgroup_group"), 1)
        for index, target in enumerate(rule.target.split(", "), 1):
            aid = f"rgroup_t{index}"
            self.assertIn(f"acl {aid}_url url_regex {parse_pattern(target).url_regex()}", sq)
            self.assertIn(f"http_access allow CONNECT !ap_bumped {aid}_chost {aid}_cport rgroup_mark", sq)
            self.assertIn(f"websocket allow {aid}_url ap_https ap_bumped {aid}_ws_bound {aid}_ws_name", sq)
            self.assertIn(f"acl {aid}_ws_bound note ap_ws_{aid} true", sq)
        disabled_ws = validate_rule({**rule.to_dict(), "allow_websockets": False}, [], rule_id=rule.id)
        without_ws = squid_rules_conf([disabled_ws], ["127.0.0.1"])
        self.assertNotIn("websocket allow", without_ws)
        self.assertIn("rgroup_t3_url", without_ws)
        rule.enabled = False
        self.assertNotIn("rgroup", squid_rules_conf([rule], ["127.0.0.1"]))

    def test_group_validation_and_firewall_exclusion(self):
        for target in ("x.io,", ",x.io", "x.io,,y.io", "x.io, ftp://y.io", "x.io, bad host"):
            with self.assertRaises(RuleError, msg=target):
                validate_rule({"kind": "allow", "target": target}, [])
        with self.assertRaises(RuleError):
            validate_rule({"kind": "tcp", "target": "one.io,two.io", "ports": "443"}, [])
        deny = validate_rule({"kind": "deny", "target": "one.io, https://two.io/private"}, [], rule_id="rd")
        allow = Rule("ra", "allow", "all", "*.io", allow_websockets=True)
        sq = squid_rules_conf([allow, deny], ["127.0.0.1"])
        self.assertIn("http_access deny CONNECT rd_t1_chost rd_t1_cport rd_mark", sq)
        self.assertNotIn("rd_t2_chost", sq)
        self.assertLess(sq.index("http_access deny !CONNECT rd_t2_url"),
                        sq.index("http_access allow !CONNECT ap_websocket"))
        self.assertEqual(sq.count("deny_info ERR_AGENT_DENIED rd_mark"), 1)

    def test_verify_upstream_tls(self):
        self.assertNotIn("sslproxy_cert_error", squid_rules_conf([], ["127.0.0.1"]))
        sq = squid_rules_conf([], ["127.0.0.1"], verify_upstream_tls=False)
        self.assertIn("sslproxy_cert_error allow all", sq)
        self.assertIn("sslproxy_cert_sign signTrusted all", sq)

    def test_settings_from_doc(self):
        base = {"verify_upstream_tls": True}
        self.assertEqual(cfg.settings_from_doc({}, base), base)
        self.assertEqual(cfg.settings_from_doc({"settings": {"verify_upstream_tls": False}}, base),
                         {"verify_upstream_tls": False})
        for bad in ({"verify_upstream_tls": "no"}, {"nope": True}, []):
            with self.assertRaises(RuleError):
                cfg.settings_from_doc({"settings": bad}, base)


if __name__ == "__main__":
    unittest.main()
