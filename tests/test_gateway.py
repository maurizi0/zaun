"""Gateway deployment validation and policy isolation regressions."""
import sys
import os
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))
from agentproxy import apply as applier, config as cfg
from agentproxy.firewall import Gateway, deployment
from agentproxy.rules import Rule, nft_ruleset


class GatewayTest(unittest.TestCase):
    def setUp(self):
        self.gateway = Gateway("agents0", "wan0", ("10.20.0.0/24", "fd20::/64"))
        self.rules = [Rule("r1", "tcp", "db", "db.example", ports="5432"),
                      Rule("r2", "tcp", "dns", "192.0.2.53", ports="53", proto="udp"),
                      Rule("r3", "tcp", "off", "192.0.2.1", ports="443", enabled=False),
                      Rule("r4", "allow", "web", "example.com")]

    def render(self, gateway=None):
        return nft_ruleset(self.rules, {"db.example": ["192.0.2.10", "2001:db8::10"]},
                           ["meta skuid 31280"], gateway=gateway or self.gateway)

    def test_container_remains_default(self):
        self.assertEqual(deployment({}), ("container", None))
        text = nft_ruleset([], {}, ["meta skuid 31280"])
        self.assertIn("hook output priority filter; policy drop", text)
        self.assertIn("meta skuid 31280", text)
        self.assertNotIn("hook forward", text)

    def test_gateway_isolation_and_source_checks(self):
        text = self.render()
        self.assertNotIn("hook output", text)
        self.assertNotIn("hook input", text)
        self.assertNotIn("meta skuid", text)
        self.assertNotIn("flush ruleset", text)
        self.assertIn('iifname "agents0" jump from_agents', text)
        self.assertIn('oifname "agents0" jump to_agents', text)
        from_agents = text.split("chain from_agents {")[1].split("chain agent_egress")[0]
        self.assertIn('oifname "wan0" ip saddr { 10.20.0.0/24 } jump agent_egress', from_agents)
        self.assertIn('oifname "wan0" ip6 saddr { fd20::/64 } jump agent_egress', from_agents)
        self.assertNotIn("ct state established", from_agents)
        self.assertIn("reject", from_agents)
        to_agents = text.split("chain to_agents {")[1]
        self.assertIn('iifname "wan0" ip daddr { 10.20.0.0/24 } ct state established,related accept', to_agents)
        self.assertIn("reject", to_agents)

    def test_rules_and_nat(self):
        text = self.render()
        self.assertIn('ip daddr { 192.0.2.10 } tcp dport { 5432 }', text)
        self.assertIn('ip6 daddr { 2001:db8::10 } tcp dport { 5432 }', text)
        self.assertIn('udp dport { 53 }', text)
        self.assertNotIn("r3_off", text)
        self.assertNotIn("r4_web", text)
        self.assertNotIn("masquerade", text)
        nat = self.render(Gateway("agents0", "wan0", ("10.20.0.0/24",), True))
        self.assertIn('iifname "agents0" oifname "wan0" ip saddr { 10.20.0.0/24 } masquerade', nat)
        self.assertNotIn("ip6 saddr", nat)
        self.assertIn("chain to_agents", nat)  # IPv6 still hits the terminal reject.

    def test_unresolved_names_do_not_open_egress(self):
        text = nft_ruleset([self.rules[0]], {}, [], gateway=self.gateway)
        self.assertIn("unresolved - no addresses", text)
        self.assertNotIn("tcp dport", text)
        self.assertIn("reject", text)

    def test_apply_uses_gateway_for_live_render(self):
        with patch.object(cfg, "GATEWAY", self.gateway), \
             patch.object(applier, "proxy_matches", side_effect=AssertionError("container exemption used")):
            _, text = applier.render([], cfg.DEFAULT_SETTINGS, {})
        self.assertIn("hook forward", text)

    def test_gateway_proxy_clients_default_to_agent_networks(self):
        env = {k: v for k, v in os.environ.items()
               if k not in ("ALLOWED_CLIENTS", "FIREWALL_ENFORCE", "GATEWAY_MASQUERADE")}
        env.update(PYTHONPATH=str(Path(__file__).resolve().parent.parent / "app"),
                   FIREWALL_MODE="gateway", GATEWAY_AGENT_INTERFACE="agents0",
                   GATEWAY_UPLINK_INTERFACE="wan0", GATEWAY_AGENT_NETWORKS="10.20.0.0/24 fd20::/64")
        code = "from agentproxy.config import ALLOWED_CLIENTS; print(' '.join(ALLOWED_CLIENTS))"
        result = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout.strip(), "10.20.0.0/24 fd20::/64")
        env["ALLOWED_CLIENTS"] = "10.20.0.10/32"
        result = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout.strip(), "10.20.0.10/32")

    def test_gateway_retains_extensive_log_history_by_default(self):
        env = {k: v for k, v in os.environ.items() if k not in ("LOG_BACKUPS", "FIREWALL_ENFORCE")}
        env.update(PYTHONPATH=str(Path(__file__).resolve().parent.parent / "app"),
                   FIREWALL_MODE="gateway", GATEWAY_AGENT_INTERFACE="agents0",
                   GATEWAY_UPLINK_INTERFACE="wan0", GATEWAY_AGENT_NETWORKS="10.20.0.0/24")
        code = "from agentproxy.config import LOG_BACKUPS; print(LOG_BACKUPS)"
        result = subprocess.run([sys.executable, "-c", code], env=env,
                                capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout.strip(), "20")
        env["LOG_BACKUPS"] = "7"
        result = subprocess.run([sys.executable, "-c", code], env=env,
                                capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout.strip(), "7")

    def test_invalid_deployments(self):
        base = {"FIREWALL_MODE": "gateway", "GATEWAY_AGENT_INTERFACE": "agents0",
                "GATEWAY_UPLINK_INTERFACE": "wan0", "GATEWAY_AGENT_NETWORKS": "10.20.0.0/24"}
        for overrides in ({"FIREWALL_MODE": "oops"}, {"FIREWALL_ENFORCE": "0"},
                          {"GATEWAY_AGENT_INTERFACE": ""}, {"GATEWAY_UPLINK_INTERFACE": "agents0"},
                          {"GATEWAY_AGENT_INTERFACE": 'eth0" accept'}, {"GATEWAY_UPLINK_INTERFACE": "lo"},
                          {"GATEWAY_AGENT_NETWORKS": ""}, {"GATEWAY_AGENT_NETWORKS": "0.0.0.0/0"},
                          {"GATEWAY_AGENT_NETWORKS": "10.20.0.1/24"},
                          {"GATEWAY_MASQUERADE": "yes"},
                          {"GATEWAY_AGENT_NETWORKS": "fd20::/64", "GATEWAY_MASQUERADE": "1"}):
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                deployment({**base, **overrides})
        mode, gateway = deployment(base)
        self.assertEqual(mode, "gateway")
        self.assertEqual(gateway.networks, ("10.20.0.0/24",))


if __name__ == "__main__":
    unittest.main()
