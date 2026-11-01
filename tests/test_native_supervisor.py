"""Regression for Supervisor reopening journald's socket as /dev/stdout."""
import configparser
import importlib.util
import io
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("native_supervisor", ROOT / "scripts/render-native-supervisor.py")
renderer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renderer)


class NativeSupervisorTest(unittest.TestCase):
    def test_logs_open_with_journal_style_stdout(self):
        output = io.StringIO()
        with (ROOT / "rootfs/etc/agent-proxy/supervisord.conf").open() as source:
            renderer.render(source, output)
        config = configparser.ConfigParser(interpolation=None)
        config.read_string(output.getvalue())
        self.assertEqual(config["unix_http_server"]["chmod"], "0700")
        self.assertEqual(config["supervisorctl"]["serverurl"], "unix:///run/agent-proxy/supervisor.sock")
        reader, stream = socket.socketpair()
        with tempfile.TemporaryDirectory() as directory, reader, stream:
            reproduction = subprocess.run([sys.executable, "-c",
                "import errno\ntry:\n open('/dev/stdout', 'a')\nexcept OSError as e:\n assert e.errno == errno.ENXIO\nelse:\n raise AssertionError('expected journal socket reopen to fail')"],
                stdout=stream, stderr=subprocess.PIPE)
            self.assertEqual(reproduction.returncode, 0, reproduction.stderr)
            for section in config.sections():
                if not section.startswith("program:"):
                    continue
                settings = config[section]
                name = section.split(":", 1)[1]
                filename = settings["stdout_logfile"] % {"program_name": name}
                self.assertEqual(filename, f"/var/log/agent-proxy/{name}.log")
                self.assertEqual(settings["stdout_logfile_maxbytes"], "10MB")
                self.assertEqual(settings["stdout_logfile_backups"], "3")
                logfile = Path(directory) / Path(filename).name
                result = subprocess.run([sys.executable, "-c",
                                         "import sys; open(sys.argv[1], 'a').write('child started\\n')",
                                         str(logfile)], stdout=stream, stderr=subprocess.PIPE)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(logfile.read_text(), "child started\n")
        # The container template keeps its pipe-compatible stdout logging.
        original = (ROOT / "rootfs/etc/agent-proxy/supervisord.conf").read_text()
        self.assertEqual(original.count("stdout_logfile=/dev/stdout"), 4)


if __name__ == "__main__":
    unittest.main()
