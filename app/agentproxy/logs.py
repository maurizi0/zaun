"""Tail squid's access log and ulogd's NFLOG json, merge them into one live stream."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from . import config as cfg

log = logging.getLogger("agentproxy.logs")
PROTO_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6"}


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="milliseconds")


# host -> (epoch, rule) of recently denied CONNECTs. squid still bumps a denied CONNECT
# to serve its error page and then logs the inner request as NONE_NONE/403 without a rule.
_denied_connects: dict[str, tuple[float, str]] = {}


def parse_squid(line: str) -> dict | None:
    # logformat agentproxy: %ts.%03tu %>a %rm %Ss %>Hs %<a %{rule}note %ru
    parts = line.rstrip("\n").split(" ", 7)
    if len(parts) != 8:
        return None
    ts, client, method, squid_status, http_status, server, rule, url = parts
    try:
        t = float(ts)
    except ValueError:
        return None
    if method == "CONNECT":
        host, path = url, ""
    else:
        u = urlsplit(url)
        host = u.netloc
        path = u.path + (f"?{u.query}" if u.query else "")
    rule = "" if rule == "-" else rule
    denied = "DENIED" in squid_status
    if method == "CONNECT" and denied:
        http_status = "403"
        if len(_denied_connects) > 1000:
            _denied_connects.clear()
        _denied_connects[host.rsplit(":", 1)[0]] = (t, rule)
    elif squid_status.startswith("NONE") and http_status == "403":
        prev = _denied_connects.get(u.hostname or "")
        if prev and t - prev[0] < 30:
            denied, rule = True, prev[1]
    return {
        "ts": _iso(t),
        "epoch": t,
        "source": "proxy",
        "verdict": "DENY" if denied else "ALLOW",
        "rule": rule,
        "method": method,
        "client": client,
        "host": host,
        "path": path,
        "url": url,
        "status": http_status,
        "detail": squid_status + ("" if server == "-" else f" via {server}"),
    }


# flow -> epoch; a retransmitted SYN is still "ct state new" and would be logged twice
_recent_flows: dict[tuple, float] = {}


def parse_nflog(line: str) -> dict | None:
    try:
        d = json.loads(line)
    except ValueError:
        return None
    prefix = d.get("oob.prefix", "")
    verdict, _, rule = prefix.partition("|")
    if verdict not in ("ALLOW", "DENY"):
        return None
    t = d.get("oob.time.sec")
    if t is not None:
        t = float(t) + float(d.get("oob.time.usec", 0)) / 1e6
    else:
        try:
            t = datetime.fromisoformat(d["timestamp"]).timestamp()
        except (KeyError, ValueError):
            t = datetime.now().timestamp()
    flow = (d.get("src_ip"), d.get("src_port"), d.get("dest_ip"), d.get("dest_port"), d.get("ip.protocol"))
    if t - _recent_flows.get(flow, 0) < 2:
        return None
    if len(_recent_flows) > 5000:
        _recent_flows.clear()
    _recent_flows[flow] = t
    proto = PROTO_NAMES.get(d.get("ip.protocol"), str(d.get("ip.protocol", "?")))
    dst = d.get("dest_ip", "?")
    port = d.get("dest_port")
    target = (f"[{dst}]" if ":" in dst else dst) + (f":{port}" if port is not None else "")
    uid = d.get("oob.uid")
    return {
        "ts": _iso(t),
        "epoch": t,
        "source": "firewall",
        "verdict": verdict,
        "rule": rule,
        "method": proto,
        "client": d.get("src_ip", ""),
        "host": target,
        "path": "",
        "url": f"{proto.lower()}://{target}",
        "status": "",
        "detail": f"uid {uid}" if uid is not None else "",
    }


class LogHub:
    def __init__(self) -> None:
        self.buffer: deque[dict] = deque(maxlen=cfg.LOG_BUFFER)
        self.subscribers: set[asyncio.Queue] = set()
        self.seq = 0

    def publish(self, entry: dict) -> None:
        self.seq += 1
        entry["id"] = self.seq
        self.buffer.append(entry)
        for q in list(self.subscribers):
            try:
                q.put_nowait(entry)
            except asyncio.QueueFull:
                pass  # slow client, drop

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self.subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self.subscribers.discard(q)

    async def tail(self, path: Path, parser, rotate_cmd: list[str]) -> None:
        """Follow a file across truncation/rotation. Pre-loads the tail of the existing file."""
        f = None
        inode = None
        while True:
            try:
                if f is None:
                    if not path.exists():
                        await asyncio.sleep(1)
                        continue
                    f = open(path, "rb")
                    inode = os.fstat(f.fileno()).st_ino
                    self._preload(f, parser)
                line = f.readline()
                if line:
                    if line.endswith(b"\n"):
                        e = parser(line.decode(errors="replace"))
                        if e:
                            self.publish(e)
                    else:  # partial line, wait for the writer
                        f.seek(-len(line), os.SEEK_CUR)
                        await asyncio.sleep(0.25)
                    continue
                await asyncio.sleep(0.25)
                st = path.stat() if path.exists() else None
                if st is None or st.st_ino != inode or st.st_size < f.tell():
                    f.close()
                    f = None
                elif st.st_size > cfg.LOG_MAX_BYTES:
                    os.replace(path, path.with_suffix(path.suffix + ".1"))
                    subprocess.run(rotate_cmd, capture_output=True)
            except asyncio.CancelledError:
                raise
            except Exception:  # keep tailing no matter what
                log.exception("tailing %s failed", path)
                if f:
                    f.close()
                f = None
                await asyncio.sleep(2)

    def _preload(self, f, parser) -> None:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        f.seek(max(0, size - 2 * 1024 * 1024))
        if f.tell():
            f.readline()  # skip partial line
        while line := f.readline():
            if not line.endswith(b"\n"):
                f.seek(-len(line), os.SEEK_CUR)
                break
            e = parser(line.decode(errors="replace"))
            if e:
                self.publish(e)


def recent(hub: LogHub, limit: int) -> list[dict]:
    items = sorted(hub.buffer, key=lambda e: e["epoch"])
    return items[-limit:]
