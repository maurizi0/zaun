"""Access-log export completeness, exact values and attachment security."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))
from agentproxy.logs import LogHub, download_snapshot


class LogDownloadTest(unittest.TestCase):
    def test_export_preserves_all_fields_and_types_without_mutating_events(self):
        hub = LogHub()
        event = {"epoch": 1, "source": "proxy", "host": "alice:secret@example.com?token=secret",
                 "path": "/api?key=secret#private", "url": "https://alice:secret@example.com/api?key=secret",
                 "detail": "secret diagnostic", "password": "secret", "rule": '<script>alert("x")</script>',
                 "client": "=HYPERLINK(\"bad\")"}
        hub.publish(event.copy())
        hub.publish({"epoch": 2, "host": "second.example", "path": "/ok"})
        text = download_snapshot(hub)
        result = json.loads(text)
        self.assertEqual(result["entries"][0]["host"], "second.example")
        row = result["entries"][1]
        self.assertEqual(row, {**event, "id": 1})
        self.assertIsInstance(row["epoch"], int)
        self.assertEqual(hub.buffer[0], {**event, "id": 1})

    def test_empty_and_large_buffers(self):
        hub = LogHub()
        self.assertEqual(json.loads(download_snapshot(hub)), {"entries": []})
        # Use a larger test buffer than the configured default.
        from collections import deque
        hub.buffer = deque({"epoch": i, "path": "/x"} for i in range(5010))
        result = json.loads(download_snapshot(hub))
        self.assertEqual(len(result["entries"]), 5010)
        hub.buffer = deque({"epoch": i, "path": "/" + "x" * 10000} for i in range(1000))
        text = download_snapshot(hub)
        self.assertGreater(len(text), 8 * 1024 * 1024)
        result = json.loads(text)
        self.assertEqual(len(result["entries"]), 1000)
        self.assertEqual(len(result["entries"][0]["path"]), 10001)

    def test_preserves_long_fields_and_nested_metadata(self):
        hub = LogHub()
        event = {"epoch": 0, "host": "password" * 1000 + "@example.com",
                 "metadata": {"enabled": True, "count": 3, "extra": None, "tags": ["one", "two"]}}
        hub.publish(event.copy())
        row = json.loads(download_snapshot(hub))["entries"][0]
        self.assertEqual(row, {**event, "id": 1})


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

            async def receive():
                return {"type": "http.request", "body": b"", "more_body": False}

            async def send(message):
                messages.append(message)

            await main.app(scope, receive, send)
            start = next(m for m in messages if m["type"] == "http.response.start")
            body = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
            return start["status"], dict(start["headers"]), body

        with patch.object(main, "UI_PASSWORD", "download-test-password"), patch.object(main, "UI_USER", "admin"):
            self.assertEqual((await request())[0], 401)
            self.assertEqual((await request("admin:wrong"))[0], 401)
            status, headers, body = await request("admin:download-test-password")
            self.assertEqual(status, 200)
            self.assertEqual(headers[b"content-disposition"], b'attachment; filename="zaun-access-logs.json"')
            self.assertEqual(headers[b"cache-control"], b"no-store")
            self.assertEqual(headers[b"x-content-type-options"], b"nosniff")
            self.assertIn(b"application/json", headers[b"content-type"])
            self.assertIn("entries", json.loads(body))
        with patch.object(main, "UI_PASSWORD", ""):
            self.assertEqual((await request())[0], 503)


if __name__ == "__main__":
    unittest.main()
