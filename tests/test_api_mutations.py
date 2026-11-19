import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import AsyncMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))


@unittest.skipUnless(importlib.util.find_spec("fastapi"), "FastAPI required for middleware checks")
class MutationContentTypeTest(unittest.IsolatedAsyncioTestCase):
    async def dispatch(self, method, path, *content_types):
        from agentproxy.main import RequireJsonMutations

        handler, receive, send = AsyncMock(), AsyncMock(), AsyncMock()
        scope = {"type": "http", "method": method, "path": path,
                 "headers": [(b"content-type", value) for value in content_types]}
        await RequireJsonMutations(handler)(scope, receive, send)
        receive.assert_not_awaited()
        if handler.await_count:
            return None
        return send.await_args_list[0].args[0]["status"]

    async def test_rejects_missing_form_and_ambiguous_media_types_before_dispatch(self):
        for method, path in [("POST", "/api/rules"), ("PUT", "/api/settings"),
                             ("DELETE", "/api/rules/1"), ("POST", "/api/reapply")]:
            for headers in [(), (b"text/plain",), (b"application/x-www-form-urlencoded",),
                            (b"multipart/form-data; boundary=x",), (b"text/plain", b"application/json")]:
                with self.subTest(method=method, path=path, headers=headers):
                    self.assertEqual(await self.dispatch(method, path, *headers), 415)

    async def test_accepts_json_mutations_and_read_requests(self):
        for media_type in [b"application/json", b"Application/JSON; charset=utf-8"]:
            self.assertIsNone(await self.dispatch("POST", "/api/reapply", media_type))
        self.assertIsNone(await self.dispatch("GET", "/api/state"))
