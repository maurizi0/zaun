"""Upstream validation, persistence and generated forwarding policy."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import unquote

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))
from agentproxy import apply as applier, config as cfg, upstream
from agentproxy.rules import RuleError, validate_rule


def settings(**values):
    return cfg.settings_from_doc({"settings": values})


class UpstreamTest(unittest.TestCase):
    def test_existing_config_and_disabled_parent(self):
        old = settings(verify_upstream_tls=False)
        self.assertFalse(old["upstream_proxy_enabled"])
        self.assertEqual(upstream.squid_conf(old), "")
        disabled = settings(upstream_proxy_url="http://proxy.example:3128")
        self.assertEqual(upstream.squid_conf(disabled), "")

    def test_parent_auth_encoding_and_no_direct_fallback(self):
        saved = settings(upstream_proxy_enabled=True,
                         upstream_proxy_url="http://user%40example:p%25%20%23%3A%40@proxy.example:3128")
        self.assertEqual(saved["upstream_proxy_url"], "http://proxy.example:3128")
        self.assertEqual(saved["upstream_proxy_password"], "p% #:@")
        text = upstream.squid_conf(saved)
        self.assertIn("cache_peer proxy.example parent 3128 0 no-query default", text)
        self.assertIn("never_direct allow all", text)
        login = text.split("login=", 1)[1].split()[0]
        self.assertEqual(unquote(login), "user@example:p% #:@")
        self.assertNotIn(login, upstream.redact(text))

    def test_url_defaults_https_and_ipv6(self):
        for url, expected in (("http://proxy.example", "proxy.example parent 80"),
                              ("https://proxy.example", "proxy.example parent 443"),
                              ("http://[2001:db8::1]:8080", "[2001:db8::1] parent 8080")):
            with self.subTest(url=url):
                text = upstream.squid_conf(settings(upstream_proxy_enabled=True, upstream_proxy_url=url))
                self.assertIn(expected, text)
                self.assertEqual(" tls " in text, url.startswith("https:"))

    def test_invalid_urls_and_settings(self):
        invalid = ["socks5://host:1080", "http://", "http://host:0", "http://host:65536",
                   "http://host:wrong", "http://host/path", "http://host?x=y", "http://host#x",
                   "http://host\nnever_direct deny all", "http://[broken", "http://ho$st", "http://[::1%eth0]"]
        for url in invalid:
            with self.subTest(url=url), self.assertRaises(RuleError):
                settings(upstream_proxy_url=url)
        for raw in ({"upstream_proxy_enabled": "yes"}, {"upstream_proxy_url": True},
                    {"upstream_proxy_password": None}, {"upstream_proxy_enabled": True},
                    {"upstream_proxy_password": "secret"}, {"upstream_proxy_username": "u:p"},
                    {"upstream_proxy_username": "*"}, {"upstream_proxy_username": "NEGOTIATE"},
                    {"upstream_proxy_username": "u", "upstream_proxy_password": "p\n"}):
            with self.subTest(raw=raw), self.assertRaises(RuleError):
                settings(**raw)

    def test_password_retained_cleared_and_disable_persisted(self):
        original = settings(upstream_proxy_enabled=True, upstream_proxy_url="http://proxy.example",
                            upstream_proxy_username="alice", upstream_proxy_password="secret")
        disabled = cfg.settings_from_doc({"settings": {"upstream_proxy_enabled": False}}, original)
        self.assertEqual(disabled["upstream_proxy_password"], "secret")
        with tempfile.TemporaryDirectory() as directory, patch.object(cfg, "CONFIG_FILE", Path(directory) / "config.json"):
            cfg.save_config([], disabled)
            self.assertEqual(cfg.load_settings(), disabled)
            self.assertEqual(cfg.CONFIG_FILE.stat().st_mode & 0o777, 0o600)
        cleared = cfg.settings_from_doc({"settings": {"upstream_proxy_password": ""}}, disabled)
        self.assertEqual(cleared["upstream_proxy_password"], "")
        self.assertEqual(original["upstream_proxy_password"], "secret")

    def test_env_defaults_and_saved_override(self):
        with tempfile.TemporaryDirectory() as directory:
            env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parent.parent / "app"),
                   "DATA_DIR": directory, "UPSTREAM_PROXY": "http://proxy.example:3128",
                   "UPSTREAM_PROXY_USER": "alice", "UPSTREAM_PROXY_PASSWORD": "secret"}
            code = "from agentproxy import config; import json; print(json.dumps(config.load_settings()))"
            def load():
                return json.loads(subprocess.check_output([sys.executable, "-c", code], env=env))
            initial = load()
            self.assertTrue(initial["upstream_proxy_enabled"])
            self.assertEqual(initial["upstream_proxy_password"], "secret")
            initial["upstream_proxy_enabled"] = False
            (Path(directory) / "config.json").write_text(json.dumps({"settings": initial, "rules": []}))
            self.assertFalse(load()["upstream_proxy_enabled"])

    def test_failed_apply_restores_parent_policy(self):
        enabled = settings(upstream_proxy_enabled=True, upstream_proxy_url="http://proxy.example:3128")
        for fail_reload in (True, False):
            with self.subTest(fail_reload=fail_reload), tempfile.TemporaryDirectory() as directory:
                policy = Path(directory) / "rules.conf"
                policy.write_text("# previous policy\n")
                def write(text):
                    policy.write_text(text)
                reload_result = subprocess.CompletedProcess([], 1 if fail_reload else 0, "", "failed")
                with patch.object(cfg, "SQUID_RULES", policy), patch.object(cfg, "FIREWALL_ENFORCE", False), \
                     patch.object(applier, "_check_squid"), patch.object(applier, "write_squid", side_effect=write), \
                     patch.object(applier, "squid_running", return_value=True), \
                     patch.object(applier, "proxy_matches", return_value=[]), \
                     patch.object(applier, "_run", return_value=reload_result) as run, \
                     patch.object(applier, "apply_nft", side_effect=applier.ApplyError("nft failed")):
                    with self.assertRaises(applier.ApplyError):
                        applier.apply([], enabled)
                    self.assertEqual(policy.read_text(), "# previous policy\n")
                    self.assertEqual(run.call_count, 2)

    def test_parse_errors_redact_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / "base.conf"
            base.write_text("include " + str(cfg.SQUID_RULES))
            failure = subprocess.CompletedProcess([], 1, "", "FATAL: cache_peer host login=user:secret")
            with patch.object(cfg, "SQUID_CONF", base), patch.object(applier, "_run", return_value=failure):
                with self.assertRaises(applier.ApplyError) as error:
                    applier._check_squid("# test")
                self.assertNotIn("secret", str(error.exception))
                self.assertIn("[redacted]", str(error.exception))

    def test_access_policy_and_firewall_preserved(self):
        rules = [validate_rule({"kind": "allow", "target": "example.com"}, [])]
        enabled = settings(upstream_proxy_enabled=True, upstream_proxy_url="http://proxy.example:3128")
        with patch.object(applier, "proxy_matches", return_value=["meta skuid 31280"]):
            direct_sq, direct_nft = applier.render(rules, settings(), {})
            chained_sq, chained_nft = applier.render(rules, enabled, {})
        self.assertTrue(chained_sq.startswith(direct_sq))
        self.assertEqual(direct_nft, chained_nft)
        self.assertIn("never_direct allow all", chained_sq)


if __name__ == "__main__":
    unittest.main()
