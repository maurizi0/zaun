"""Raw access/firewall log archive completeness and attachment security."""
import asyncio
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))
from agentproxy.logs import LogHub, _rotate_file


async def archive_bytes(hub, paths):
    stream = await hub.open_log_archive(paths)
    return b"".join([chunk async for chunk in stream])


def archive_contents(data):
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        return {member.name: archive.extractfile(member).read() for member in archive.getmembers()}


class LogRotationTest(unittest.TestCase):
    def test_rotation_keeps_configured_number_of_complete_files(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "access.log"
            path.write_bytes(b"current\n")
            for index in range(1, 5):
                (Path(directory) / f"access.log.{index}").write_bytes(f"old-{index}\n".encode())

            _rotate_file(path, 3)

            self.assertFalse(path.exists())
            self.assertEqual((Path(directory) / "access.log.1").read_bytes(), b"current\n")
            self.assertEqual((Path(directory) / "access.log.2").read_bytes(), b"old-1\n")
            self.assertEqual((Path(directory) / "access.log.3").read_bytes(), b"old-2\n")
            self.assertFalse((Path(directory) / "access.log.4").exists())


class LogDownloadTest(unittest.IsolatedAsyncioTestCase):
    async def test_archive_contains_active_logs_and_every_numbered_rotation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            access = root / "access.log"
            firewall = root / "firewall.json"
            expected = {
                "access.log": b"proxy-current\n",
                "access.log.1": b"proxy-previous\n",
                "access.log.2": b"proxy-oldest\n",
                "firewall.json": b'{"event":"current"}\n',
                "firewall.json.1": b'{"event":"previous"}\n',
            }
            for name, content in expected.items():
                (root / name).write_bytes(content)
            (root / "cache.log").write_bytes(b"must not be included\n")
            (root / "access.log.notes").write_bytes(b"must not be included\n")

            data = await archive_bytes(LogHub(), [access, firewall])

            self.assertEqual(archive_contents(data), expected)

    async def test_archive_streams_files_larger_than_one_chunk_without_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "access.log"
            content = bytes(range(256)) * 1024
            path.write_bytes(content)
            data = await archive_bytes(LogHub(), [path])
            self.assertEqual(archive_contents(data), {"access.log": content})


# These exercise the real ASGI auth middleware and route when app dependencies
# are installed; no HTTP client dependency or listening socket is required.
import importlib.util
import base64
from unittest.mock import patch


@unittest.skipUnless(importlib.util.find_spec("fastapi"), "FastAPI is required for ASGI download checks")
class LogDownloadAPITest(unittest.IsolatedAsyncioTestCase):
    async def test_authentication_and_attachment_headers(self):
        from agentproxy import main

        async def request(credentials=None):
            headers = []
            if credentials:
                headers.append((b"authorization", b"Basic " + base64.b64encode(credentials.encode())))
            scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
                     "method": "GET", "scheme": "http", "path": "/api/logs/download",
                     "raw_path": b"/api/logs/download", "query_string": b"file=/etc/passwd&filename=unsafe.html",
                     "headers": headers, "client": ("127.0.0.1", 1234), "server": ("test", 80), "root_path": ""}
            messages = []
            request_sent = False

            async def receive():
                nonlocal request_sent
                if not request_sent:
                    request_sent = True
                    return {"type": "http.request", "body": b"", "more_body": False}
                await asyncio.Event().wait()

            async def send(message):
                messages.append(message)

            await main.app(scope, receive, send)
            start = next(m for m in messages if m["type"] == "http.response.start")
            body = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
            return start["status"], dict(start["headers"]), body

        with tempfile.TemporaryDirectory() as directory:
            access = Path(directory) / "access.log"
            firewall = Path(directory) / "firewall.json"
            access.write_bytes(b"proxy log\n")
            firewall.write_bytes(b'{"firewall":"log"}\n')
            with patch.object(main, "UI_PASSWORD", "download-test-password"), \
                    patch.object(main, "UI_USER", "admin"), \
                    patch.object(main.cfg, "SQUID_LOG", access), \
                    patch.object(main.cfg, "NFLOG_LOG", firewall):
                self.assertEqual((await request())[0], 401)
                self.assertEqual((await request("admin:wrong"))[0], 401)
                status, headers, body = await request("admin:download-test-password")
                self.assertEqual(status, 200)
                self.assertEqual(headers[b"content-disposition"], b'attachment; filename="zaun-logs.tar.gz"')
                self.assertEqual(headers[b"cache-control"], b"no-store")
                self.assertEqual(headers[b"x-content-type-options"], b"nosniff")
                self.assertIn(b"application/gzip", headers[b"content-type"])
                self.assertEqual(archive_contents(body), {
                    "access.log": b"proxy log\n",
                    "firewall.json": b'{"firewall":"log"}\n',
                })
        with patch.object(main, "UI_PASSWORD", ""):
            self.assertEqual((await request())[0], 503)


if __name__ == "__main__":
    unittest.main()
