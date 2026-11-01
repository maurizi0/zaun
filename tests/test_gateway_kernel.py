"""Opt-in kernel checks; all nft commands run in a disposable network namespace.

ZAUN_TEST_NFT=1 python3 -m unittest discover -s tests -p test_gateway_kernel.py
Requires nft, unshare, and permission to create a network/user namespace.
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))
from agentproxy.firewall import Gateway
from agentproxy.rules import Rule, nft_ruleset


@unittest.skipUnless(os.environ.get("ZAUN_TEST_NFT") == "1", "set ZAUN_TEST_NFT=1 for isolated kernel checks")
class KernelTest(unittest.TestCase):
    def test_load_replace_and_atomic_failure(self):
        self.assertIsNotNone(shutil.which("nft"), "install nftables to run kernel checks")
        self.assertIsNotNone(shutil.which("unshare"), "install util-linux to run kernel checks")
        rules = [Rule("r1", "tcp", "db", "192.0.2.0/24", ports="5432"),
                 Rule("r2", "tcp", "dns", "2001:db8::53", ports="53", proto="udp")]
        variants = [
            nft_ruleset(rules, {}, ["meta skuid 0"]),
            nft_ruleset([], {}, [], gateway=Gateway("agents0", "wan0", ("10.20.0.0/24",))),
            nft_ruleset(rules, {}, [], gateway=Gateway("agents0", "wan0", ("10.20.0.0/24",), True)),
            nft_ruleset(rules, {}, [], gateway=Gateway("agents0", "wan0", ("10.20.0.0/24", "fd20::/64"), True)),
            nft_ruleset(rules, {}, [], gateway=Gateway("agents0", "wan0", ("fd20::/64",))),
        ]
        # This subprocess is the only place nft is invoked: it never sees the host netns.
        checker = r'''
import pathlib, subprocess, sys
def nft(*args, **kw):
    return subprocess.run(["nft", *args], text=True, capture_output=True, **kw)
sentinel = nft("-f", "-", input="table inet unrelated { chain untouched { } }\n")
assert sentinel.returncode == 0, sentinel.stderr
for filename in sys.argv[1:]:
    checked = nft("--check", "--file", filename)
    assert checked.returncode == 0, checked.stderr
    applied = nft("--file", filename)
    assert applied.returncode == 0, applied.stderr
    assert nft("list", "table", "inet", "unrelated").returncode == 0
previous = nft("list", "table", "inet", "agentproxy").stdout
failed = nft("-f", "-", input="destroy table inet agentproxy\nadd rule inet missing_zaun_test_table missing_chain counter accept\n")
assert failed.returncode != 0
assert nft("list", "table", "inet", "agentproxy").stdout == previous
'''
        with tempfile.TemporaryDirectory() as directory:
            paths = []
            for index, text in enumerate(variants):
                path = Path(directory) / f"policy-{index}.nft"
                path.write_text(text)
                paths.append(str(path))
            namespace = ["unshare", "--net"] if os.geteuid() == 0 else ["unshare", "--user", "--map-root-user", "--net"]
            result = subprocess.run([*namespace, sys.executable, "-c", checker, *paths],
                                    capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
