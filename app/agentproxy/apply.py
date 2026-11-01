"""Validate and push a rule set into squid and nftables."""
from __future__ import annotations

import logging
import os
import subprocess
import tempfile
from pathlib import Path

from . import config as cfg
from . import upstream
from .rules import Rule, nft_ruleset, parse_tcp_target, squid_rules_conf

log = logging.getLogger("agentproxy.apply")


class ApplyError(RuntimeError):
    pass


def _run(cmd: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def resolve_host(host: str) -> list[str]:
    """Resolve as the squid user: it is the only uid the firewall lets out (DNS included)."""
    try:
        p = _run(["setpriv", f"--reuid={cfg.SQUID_UID}", f"--regid={cfg.SQUID_UID}",
                  "--clear-groups", "getent", "ahosts", host], timeout=10)
    except subprocess.TimeoutExpired:
        return []
    addrs = []
    for line in p.stdout.splitlines():
        addr = line.split()[0] if line.strip() else ""
        if addr and addr not in addrs:
            addrs.append(addr)
    return sorted(addrs)


def resolve_all(rules: list[Rule]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for r in rules:
        if r.kind == "tcp" and r.enabled:
            t = parse_tcp_target(r.target)
            if isinstance(t, str) and t not in out:
                out[t] = resolve_host(t)
    return out


def _check_squid(rules_text: str) -> None:
    """Run `squid -k parse` against a throw-away copy of the config."""
    with tempfile.TemporaryDirectory(prefix="squidcheck") as d:
        rules_file = Path(d) / "rules.conf"
        rules_file.write_text(rules_text)
        base = cfg.SQUID_CONF.read_text().replace(str(cfg.SQUID_RULES), str(rules_file))
        main = Path(d) / "squid.conf"
        main.write_text(base)
        p = _run(["squid", "-k", "parse", "-f", str(main)])
        errors = [l for l in (p.stdout + p.stderr).splitlines() if "ERROR" in l or "FATAL" in l]
        if p.returncode != 0 or errors:
            raise ApplyError("squid rejected the configuration:\n" + upstream.redact("\n".join(errors or [p.stderr[-2000:]])))


def squid_running() -> bool:
    try:
        pid = int(cfg.SQUID_PID.read_text().strip())
        os.kill(pid, 0)
        return True
    except (OSError, ValueError):
        return False


def proxy_matches() -> list[str]:
    """nft matches that identify sockets owned by this (proxy) container.

    Preferred: the container's cgroup. Agent containers live in other cgroups and cannot
    move themselves into ours, even as root with all capabilities. A `socket cgroupv2`
    match only ever matches sockets inside the given cgroup's subtree, so emitting it
    for several levels is safe; which level is the right one depends on whether the
    kernel counts levels from the cgroup-namespace root (>= 6.12) or the real root.

    Fallback (no cgroup v2): squid's uid. Weaker - an agent with CAP_SETUID can switch to it.
    """
    path = ""
    try:
        for line in Path("/proc/self/cgroup").read_text().splitlines():
            if line.startswith("0::"):
                path = line[3:].strip() or "/"
    except OSError:
        pass
    # the real hierarchy root has no cgroup.events: never exempt the whole machine
    if path and (Path("/sys/fs/cgroup") / path.lstrip("/") / "cgroup.events").exists():
        depth = len([p for p in path.split("/") if p])
        return [f'socket cgroupv2 level {lvl} "{path}"' for lvl in range(max(16, depth + 1))]
    log.warning("cgroup v2 not usable, exempting squid by uid %d (weaker)", cfg.SQUID_UID)
    return [f"meta skuid {cfg.SQUID_UID}"]


def render(rules: list[Rule], settings: dict,
           resolved: dict[str, list[str]] | None = None) -> tuple[str, str]:
    if resolved is None:
        resolved = resolve_all(rules)
    return (squid_rules_conf(rules, cfg.ALLOWED_CLIENTS, settings["verify_upstream_tls"]) + upstream.squid_conf(settings),
            nft_ruleset(rules, resolved, [] if cfg.GATEWAY else proxy_matches(), gateway=cfg.GATEWAY))


def apply_nft(nft_text: str) -> None:
    if not cfg.FIREWALL_ENFORCE:
        cfg.atomic_write(cfg.NFT_FILE, nft_text)
        return
    with tempfile.NamedTemporaryFile("w", suffix=".nft", delete=False) as f:
        f.write(nft_text)
        tmp = f.name
    try:
        # a single nft -f run is one transaction: on failure the old ruleset stays active
        p = _run(["nft", "-f", tmp])
        if p.returncode != 0:
            raise ApplyError("loading nftables ruleset failed:\n" + p.stderr.strip())
    finally:
        os.unlink(tmp)
    cfg.atomic_write(cfg.NFT_FILE, nft_text)


def write_squid(text: str) -> None:
    cfg.atomic_write(cfg.SQUID_RULES, text, 0o640)
    os.chown(cfg.SQUID_RULES, -1, cfg.SQUID_UID)


def apply(rules: list[Rule], settings: dict, reconfigure: bool = True) -> dict:
    """Validate everything first, then commit. Raises ApplyError and leaves the old state on failure."""
    resolved = resolve_all(rules)
    squid_text, nft_text = render(rules, settings, resolved)

    if cfg.FIREWALL_ENFORCE:
        with tempfile.NamedTemporaryFile("w", suffix=".nft") as f:
            f.write(nft_text)
            f.flush()
            p = _run(["nft", "-c", "-f", f.name])
            if p.returncode != 0:
                raise ApplyError("nftables rejected the ruleset:\n" + p.stderr.strip())
    _check_squid(squid_text)

    previous = cfg.SQUID_RULES.read_text() if cfg.SQUID_RULES.exists() else None
    write_squid(squid_text)
    running = reconfigure and squid_running()
    reload_cmd = ["squid", "-k", "reconfigure", "-f", str(cfg.SQUID_CONF)]
    try:
        if running:
            p = _run(reload_cmd)
            if p.returncode != 0:
                raise ApplyError("squid reconfigure failed:\n" + upstream.redact(p.stderr.strip()))
        apply_nft(nft_text)
    except (ApplyError, subprocess.TimeoutExpired) as error:
        if previous is not None:
            write_squid(previous)
            if running:
                _run(reload_cmd)
        else:
            cfg.SQUID_RULES.unlink(missing_ok=True)
        if isinstance(error, subprocess.TimeoutExpired):
            raise ApplyError("timed out applying the configuration; previous Squid policy restored") from None
        raise
    unresolved = [h for h, a in resolved.items() if not a]
    log.info("applied %d rules (unresolved: %s)", len(rules), unresolved or "none")
    return {"resolved": resolved, "unresolved": unresolved}
