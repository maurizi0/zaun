import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import AsyncMock, patch

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


@unittest.skipUnless(importlib.util.find_spec("fastapi"), "FastAPI required for import checks")
class ImportModeTest(unittest.IsolatedAsyncioTestCase):
    async def test_invalid_mode_rejected_before_commit(self):
        from agentproxy import main

        for query in (b"mode=mrge", b"mode="):
            request = main.Request({"type": "http", "query_string": query})
            with self.subTest(query=query), patch.object(main, "commit") as commit:
                with self.assertRaises(main.HTTPException) as error:
                    await main.import_config(request)
                self.assertEqual(error.exception.status_code, 400)
                commit.assert_not_awaited()

    async def test_supported_modes_and_default(self):
        from agentproxy import main

        existing = main.validate_rule({"kind": "allow", "target": "existing.example"}, [])
        for query, keep_existing in [(b"mode=merge", True), (b"mode=replace", False), (b"", False)]:
            request = main.Request({"type": "http", "query_string": query})
            with (self.subTest(query=query), patch.object(main.state, "rules", [existing]),
                  patch.object(main, "_body", return_value={"rules": []}),
                  patch.object(main, "commit") as commit, patch.object(main, "_state_doc")):
                await main.import_config(request)
                self.assertEqual(commit.await_args.args[0], [existing] if keep_existing else [])
