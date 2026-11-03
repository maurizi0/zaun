"""Web UI + REST API for managing the agent proxy."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import secrets
import subprocess
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response, StreamingResponse

from . import apply as applier
from . import config as cfg
from . import upstream
from .logs import LogHub, parse_nflog, parse_squid, recent
from .rules import DEFAULT_RULE, Rule, RuleError, validate_rule

logging.basicConfig(level=logging.INFO, format="webui: %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("agentproxy")

STATIC = Path(__file__).resolve().parent.parent / "static"
UI_USER = os.environ.get("UI_USER", "admin")
UI_PASSWORD = os.environ.get("UI_PASSWORD") or (
    (cfg.DATA_DIR / "ui-password").read_text().strip() if (cfg.DATA_DIR / "ui-password").exists() else ""
)
PUBLIC_PATHS = {"/ca.pem", "/ca.crt", "/healthz"}


CONTENT_SECURITY_POLICY = (
    "default-src 'none'; script-src 'self'; script-src-attr 'none'; "
    "style-src 'self'; style-src-attr 'none'; connect-src 'self'; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)


class SecurityHeaders:
    """Add the policy without buffering responses, including SSE and downloads."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                message = dict(message)
                message["headers"] = list(message.get("headers", [])) + [
                    (b"content-security-policy", CONTENT_SECURITY_POLICY.encode("ascii")),
                    (b"x-content-type-options", b"nosniff"),
                ]
            await send(message)

        await self.app(scope, receive, send_with_headers)


class BasicAuth:
    """Pure ASGI middleware, so streaming responses (SSE) are untouched."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["path"] in PUBLIC_PATHS or not UI_PASSWORD:
            return await self.app(scope, receive, send)
        header = dict(scope["headers"]).get(b"authorization", b"")
        if header[:6].lower() == b"basic ":
            try:
                user, _, pw = base64.b64decode(header[6:]).decode().partition(":")
                if secrets.compare_digest(user, UI_USER) and secrets.compare_digest(pw, UI_PASSWORD):
                    return await self.app(scope, receive, send)
            except (ValueError, UnicodeDecodeError):
                pass
        resp = PlainTextResponse("authentication required", 401,
                                 headers={"WWW-Authenticate": 'Basic realm="agent-proxy"'})
        await resp(scope, receive, send)


class State:
    def __init__(self) -> None:
        self.rules: list[Rule] = []
        self.settings: dict = dict(cfg.DEFAULT_SETTINGS)
        self.lock = asyncio.Lock()
        self.last_apply = {"ok": None, "at": None, "error": None, "unresolved": []}
        self.hub = LogHub()
        self.tasks: list[asyncio.Task] = []
        self.last_nft = ""


state = State()
app = FastAPI(title="agent-proxy", docs_url=None, redoc_url=None)
app.add_middleware(BasicAuth)
app.add_middleware(SecurityHeaders)


async def commit(new_rules: list[Rule], new_settings: dict | None = None) -> dict:
    """Apply then persist. On failure nothing changes (rules, settings, files, running config)."""
    async with state.lock:
        new_settings = new_settings or state.settings
        try:
            info = await asyncio.to_thread(applier.apply, new_rules, new_settings)
        except applier.ApplyError as e:
            state.last_apply = {"ok": False, "at": time.time(), "error": str(e), "unresolved": []}
            raise HTTPException(422, str(e))
        cfg.save_config(new_rules, new_settings)
        state.rules = new_rules
        state.settings = new_settings
        state.last_nft = cfg.NFT_FILE.read_text() if cfg.NFT_FILE.exists() else ""
        state.last_apply = {"ok": True, "at": time.time(), "error": None, "unresolved": info["unresolved"]}
        return state.last_apply


async def dns_refresh_loop() -> None:
    """Hostname targets in firewall rules are pinned to IPs; keep those fresh."""
    while True:
        await asyncio.sleep(cfg.DNS_REFRESH_SECONDS)
        try:
            async with state.lock:
                _, nft_text = await asyncio.to_thread(applier.render, state.rules, state.settings)
                if nft_text != state.last_nft:
                    await asyncio.to_thread(applier.apply_nft, nft_text)
                    state.last_nft = nft_text
                    log.info("firewall addresses refreshed")
        except Exception:
            log.exception("dns refresh failed")


@app.on_event("startup")
async def startup() -> None:
    state.rules = cfg.load_rules()
    state.settings = cfg.load_settings()
    state.last_nft = cfg.NFT_FILE.read_text() if cfg.NFT_FILE.exists() else ""
    state.last_apply = {"ok": True, "at": time.time(), "error": None, "unresolved": []}
    hub = state.hub
    state.tasks = [
        asyncio.create_task(hub.tail(cfg.SQUID_LOG, parse_squid, ["squid", "-k", "rotate"])),
        asyncio.create_task(hub.tail(cfg.NFLOG_LOG, parse_nflog, ["pkill", "-HUP", "-x", "ulogd"])),
        asyncio.create_task(dns_refresh_loop()),
    ]


@app.on_event("shutdown")
async def shutdown() -> None:
    for t in state.tasks:
        t.cancel()


# --------------------------------------------------------------------------- UI

@app.get("/")
async def index():
    return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-store"})


@app.get("/static/{name}")
async def static(name: str):
    path = (STATIC / name).resolve()
    if path.parent != STATIC or not path.is_file():
        raise HTTPException(404)
    return FileResponse(path, headers={"Cache-Control": "no-store"})


@app.get("/healthz")
async def healthz():
    return {"ok": True, "squid": applier.squid_running()}


# --------------------------------------------------------------------------- rules

def _state_doc() -> dict:
    return {
        "rules": [r.to_dict() for r in state.rules],
        "default": DEFAULT_RULE,
        "apply": state.last_apply,
        "squid_running": applier.squid_running(),
        "firewall_enforced": cfg.FIREWALL_ENFORCE,
        "firewall_mode": cfg.FIREWALL_MODE,
        "gateway": ({"agent_interface": cfg.GATEWAY.agent_interface,
                     "uplink_interface": cfg.GATEWAY.uplink_interface,
                     "networks": list(cfg.GATEWAY.networks),
                     "masquerade": cfg.GATEWAY.masquerade} if cfg.GATEWAY else None),
        "settings": {k: v for k, v in state.settings.items() if k != "upstream_proxy_password"},
        "upstream_proxy_password_set": bool(state.settings.get("upstream_proxy_password")),
    }


@app.get("/api/state")
async def get_state():
    return _state_doc()


async def _body(request: Request) -> dict:
    try:
        data = await request.json()
    except ValueError:
        raise HTTPException(400, "invalid JSON")
    if not isinstance(data, dict):
        raise HTTPException(400, "expected a JSON object")
    return data


@app.post("/api/rules")
async def add_rule(request: Request):
    data = await _body(request)
    try:
        rule = validate_rule(data, state.rules)
    except RuleError as e:
        raise HTTPException(400, str(e))
    await commit(state.rules + [rule])
    return _state_doc()


@app.put("/api/rules/{rule_id}")
async def update_rule(rule_id: str, request: Request):
    data = await _body(request)
    old = next((r for r in state.rules if r.id == rule_id), None)
    if not old:
        raise HTTPException(404, "no such rule")
    merged = {**old.to_dict(), **data, "kind": data.get("kind", old.kind)}
    try:
        rule = validate_rule(merged, state.rules, rule_id=rule_id)
    except RuleError as e:
        raise HTTPException(400, str(e))
    rule.created = old.created
    await commit([rule if r.id == rule_id else r for r in state.rules])
    return _state_doc()


@app.delete("/api/rules/{rule_id}")
async def delete_rule(rule_id: str):
    if not any(r.id == rule_id for r in state.rules):
        raise HTTPException(404, "no such rule")
    await commit([r for r in state.rules if r.id != rule_id])
    return _state_doc()


@app.put("/api/settings")
async def update_settings(request: Request):
    data = await _body(request)
    try:
        settings = cfg.settings_from_doc({"settings": data}, base=state.settings)
    except RuleError as e:
        raise HTTPException(400, str(e))
    await commit(list(state.rules), settings)
    return _state_doc()


@app.post("/api/reapply")
async def reapply():
    await commit(list(state.rules))
    return _state_doc()


# --------------------------------------------------------------------------- export / import

@app.get("/api/export")
async def export():
    doc = cfg.export_doc(state.rules, state.settings)
    doc["exported"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return Response(
        json.dumps(doc, indent=2) + "\n",
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="agent-proxy-config.json"'},
    )


@app.post("/api/import")
async def import_config(request: Request):
    data = await _body(request)
    mode = request.query_params.get("mode", "replace")
    try:
        imported = cfg.rules_from_export(data)
        settings = cfg.settings_from_doc(data, base=state.settings)
        if mode == "merge":
            merged = list(state.rules)
            key = lambda r: (r.kind, r.target.lower(), r.ports, r.proto)  # noqa: E731
            known = {key(r) for r in merged}
            for r in imported:
                if key(r) in known:
                    continue
                d = r.to_dict()
                merged.append(validate_rule(d, merged))
            imported = merged
    except RuleError as e:
        raise HTTPException(400, str(e))
    await commit(imported, settings)
    return _state_doc()


@app.get("/api/generated")
async def generated():
    return {
        "squid": upstream.redact(cfg.SQUID_RULES.read_text()) if cfg.SQUID_RULES.exists() else "",
        "nft": cfg.NFT_FILE.read_text() if cfg.NFT_FILE.exists() else "",
    }


# --------------------------------------------------------------------------- CA

def _ca_info() -> dict:
    pem = cfg.CA_CERT.read_text()
    der = base64.b64decode("".join(l for l in pem.splitlines() if l and not l.startswith("-----")))
    fp = hashlib.sha256(der).hexdigest().upper()
    p = subprocess.run(["openssl", "x509", "-noout", "-subject", "-enddate"],
                       input=pem, capture_output=True, text=True)
    meta = dict(l.split("=", 1) for l in p.stdout.splitlines() if "=" in l)
    return {
        "pem": pem,
        "sha256": ":".join(fp[i:i + 2] for i in range(0, len(fp), 2)),
        "subject": meta.get("subject", "").strip(),
        "not_after": meta.get("notAfter", "").strip(),
        "ui_port": int(os.environ.get("UI_PORT", "8080")),
    }


@app.get("/api/ca")
async def ca():
    if not cfg.CA_CERT.exists():
        raise HTTPException(404, "CA not generated yet")
    return _ca_info()


@app.get("/ca.pem")
@app.get("/ca.crt")
async def ca_pem():
    """Unauthenticated so agents can fetch the CA at startup (the certificate is public)."""
    return Response(cfg.CA_CERT.read_bytes(), media_type="application/x-pem-file",
                    headers={"Content-Disposition": 'attachment; filename="agent-proxy-ca.crt"'})


# --------------------------------------------------------------------------- logs

@app.get("/api/logs")
async def logs(limit: int = 500):
    return recent(state.hub, max(1, min(limit, cfg.LOG_BUFFER)))


@app.get("/api/logs/download")
async def logs_download():
    # BasicAuth protects this route. Also fail closed if the app was started
    # without credentials rather than inheriting its unauthenticated fallback.
    if not UI_PASSWORD:
        raise HTTPException(503, "configure UI credentials before downloading logs")
    archive = await state.hub.open_log_archive([cfg.SQUID_LOG, cfg.NFLOG_LOG])
    return StreamingResponse(archive, media_type="application/gzip",
                             headers={"Content-Disposition": 'attachment; filename="zaun-logs.tar.gz"',
                                      "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


@app.get("/api/logs/stream")
async def logs_stream(request: Request):
    q = state.hub.subscribe()

    async def gen():
        try:
            yield "retry: 2000\n\n"
            while True:
                try:
                    e = await asyncio.wait_for(q.get(), timeout=15)
                    yield f"data: {json.dumps(e)}\n\n"
                except asyncio.TimeoutError:
                    if await request.is_disconnected():
                        break
                    yield ": keepalive\n\n"
        finally:
            state.hub.unsubscribe(q)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


@app.exception_handler(HTTPException)
async def http_error(_, exc: HTTPException):
    return JSONResponse({"error": exc.detail}, status_code=exc.status_code, headers=exc.headers)
