#!/usr/bin/env python3
"""Manage targets (rules) of a running agent-proxy through its REST API.

List rules (the ID column is what remove / disable / enable take):
  manage-targets.py list
  manage-targets.py list --kind tcp --json

Add a single rule:
  manage-targets.py add allow api.example.com
  manage-targets.py add deny 'https://api.example.com/admin/*' --name no-admin
  manage-targets.py add tcp 10.0.0.5 --ports 5432 --proto tcp --comment "postgres"

Import a JSON file in the config export format ({"rules": [...]}, a bare list works too):
  manage-targets.py import rules.json             # merge: existing rules are kept, duplicates skipped
  manage-targets.py import rules.json --replace   # replace every rule with the file's

Remove, disable or re-enable rules by ID (several IDs at once are fine):
  manage-targets.py remove r1a2b3c4d
  manage-targets.py disable r1a2b3c4d r5e6f7a8b
  manage-targets.py enable r1a2b3c4d

The username and password are asked for when not given as --user / --password
(or AGENT_PROXY_USER / AGENT_PROXY_PASSWORD). Only the standard library is used.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import sys
import urllib.error
import urllib.request

KINDS = ("allow", "deny", "tcp")


class ApiError(Exception):
    pass


class Client:
    def __init__(self, url: str, user: str, password: str) -> None:
        url = url.strip().rstrip("/")
        self.url = url if "://" in url else f"http://{url}"
        if not self.url.startswith(("http://", "https://")):
            raise ApiError(f"--url must be an http:// or https:// URL, got {url}")
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        self.headers = {"Authorization": f"Basic {token}", "Accept": "application/json"}

    def request(self, method: str, path: str, body: object = None) -> dict:
        data = None
        headers = dict(self.headers)
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.url + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            if e.code == 401:
                raise ApiError("authentication failed (wrong username or password)") from None
            raw = e.read()
            try:
                msg = json.loads(raw).get("error", raw.decode(errors="replace"))
            except ValueError:
                msg = raw.decode(errors="replace")
            raise ApiError(f"HTTP {e.code}: {msg}") from None
        except urllib.error.URLError as e:
            raise ApiError(f"cannot reach {self.url}: {e.reason}") from None
        try:
            return json.loads(raw or b"{}")
        except ValueError:
            raise ApiError(f"{self.url}{path} did not return JSON; is --url the agent-proxy web UI?") from None


def describe(rule: dict) -> str:
    target = rule["target"]
    if rule["kind"] == "tcp":
        target = f"{target} {rule['proto']}/{rule['ports']}"
    state = "" if rule.get("enabled", True) else " (disabled)"
    return f"{rule['id']:<9}  {rule['kind']:<5}  {rule['name']:<30}  {target}{state}"


def rule_key(rule: dict) -> tuple:
    """Same identity the server uses to skip duplicates on merge."""
    return rule["kind"], rule["target"].lower(), rule["ports"], rule["proto"]


def load_rules_file(path: str) -> dict:
    try:
        with (sys.stdin if path == "-" else open(path)) as f:
            doc = json.load(f)
    except OSError as e:
        raise ApiError(f"cannot read {path}: {e.strerror}") from None
    except ValueError as e:
        raise ApiError(f"{path} is not valid JSON: {e}") from None
    if isinstance(doc, list):
        doc = {"rules": doc}
    if not isinstance(doc, dict) or not isinstance(doc.get("rules"), list):
        raise ApiError(f"{path} must contain a 'rules' list (the config export format)")
    return doc


def cmd_add(client: Client, args: argparse.Namespace) -> int:
    if args.kind == "tcp" and not args.ports:
        raise ApiError("tcp rules need --ports (e.g. 3306, 80,443 or 8000-8100)")
    if args.kind != "tcp" and (args.ports or args.proto):
        raise ApiError("--ports and --proto only apply to tcp rules")
    rule = {"kind": args.kind, "target": args.target, "enabled": not args.disabled}
    if args.name:
        rule["name"] = args.name
    if args.comment:
        rule["comment"] = args.comment
    if args.kind == "tcp":
        rule["ports"] = args.ports
        rule["proto"] = args.proto or "tcp"
    before = {r["id"] for r in client.request("GET", "/api/state")["rules"]}
    state = client.request("POST", "/api/rules", rule)
    for r in state["rules"]:
        if r["id"] not in before:
            print(f"added    {describe(r)}")
    report_apply(state)
    return 0


def cmd_import(client: Client, args: argparse.Namespace) -> int:
    doc = args.doc
    body = {"rules": doc["rules"]}
    if args.with_settings and "settings" in doc:
        body["settings"] = doc["settings"]
    mode = "replace" if args.replace else "merge"
    before = client.request("GET", "/api/state")["rules"]
    if args.replace and before and not args.yes:
        try:
            answer = input(f"replace all {len(before)} existing rules with {len(body['rules'])} from {args.file}? [y/N] ")
        except EOFError:
            answer = ""
        if answer.strip().lower() not in ("y", "yes"):
            print("aborted")
            return 1
    state = client.request("POST", f"/api/import?mode={mode}", body)
    after = state["rules"]
    old_keys, new_keys = {rule_key(r) for r in before}, {rule_key(r) for r in after}
    added = [r for r in after if rule_key(r) not in old_keys]
    removed = [r for r in before if rule_key(r) not in new_keys]
    for r in added:
        print(f"added    {describe(r)}")
    for r in removed:
        print(f"removed  {describe(r)}")
    summary = [f"{len(added)} added"]
    if removed:
        summary.append(f"{len(removed)} removed")
    if mode == "merge" and len(body["rules"]) > len(added):
        summary.append(f"{len(body['rules']) - len(added)} skipped (already present)")
    print(", ".join(summary) + f", {len(after)} rules total")
    report_apply(state)
    return 0


def cmd_list(client: Client, args: argparse.Namespace) -> int:
    rules = client.request("GET", "/api/state")["rules"]
    if args.kind:
        rules = [r for r in rules if r["kind"] == args.kind]
    if args.json:
        print(json.dumps(rules, indent=2))
        return 0
    if not rules:
        print("no rules" + (f" of kind {args.kind}" if args.kind else "") + " (everything else: default-deny)")
        return 0
    rows = [("ID", "KIND", "NAME", "TARGET", "PORTS", "STATUS", "COMMENT")]
    for r in rules:
        ports = f"{r['proto']}/{r['ports']}" if r["kind"] == "tcp" else ""
        rows.append((r["id"], r["kind"], r["name"], r["target"], ports,
                     "enabled" if r.get("enabled", True) else "disabled", r.get("comment", "")))
    widths = [max(len(row[c]) for row in rows) for c in range(len(rows[0]))]
    for row in rows:
        print("  ".join(v.ljust(w) for v, w in zip(row, widths)).rstrip())
    print(f"\n{len(rules)} rule{'' if len(rules) == 1 else 's'}; everything else: default-deny")
    return 0


def find_rules(client: Client, ids: list[str]) -> list[dict]:
    """Look up every ID before changing anything, so a typo doesn't leave a half-done batch."""
    by_id = {r["id"]: r for r in client.request("GET", "/api/state")["rules"]}
    missing = [i for i in ids if i not in by_id]
    if missing:
        raise ApiError(f"no rule with ID {', '.join(missing)} (see 'list')")
    return [by_id[i] for i in dict.fromkeys(ids)]


def cmd_remove(client: Client, args: argparse.Namespace) -> int:
    state = {}
    for r in find_rules(client, args.ids):
        state = client.request("DELETE", f"/api/rules/{r['id']}")
        print(f"removed  {describe(r)}")
    report_apply(state)
    return 0


def cmd_set_enabled(client: Client, args: argparse.Namespace) -> int:
    enabled = args.command == "enable"
    state = {}
    for r in find_rules(client, args.ids):
        if r.get("enabled", True) == enabled:
            print(f"already {args.command}d  {describe(r)}")
            continue
        state = client.request("PUT", f"/api/rules/{r['id']}", {"enabled": enabled})
        r = next(x for x in state["rules"] if x["id"] == r["id"])
        print(f"{args.command}d  {describe(r)}")
    report_apply(state)
    return 0


def report_apply(state: dict) -> None:
    unresolved = (state.get("apply") or {}).get("unresolved") or []
    if unresolved:
        print(f"warning: could not resolve {', '.join(unresolved)}", file=sys.stderr)


def credentials(args: argparse.Namespace) -> tuple[str, str]:
    user = args.user or os.environ.get("AGENT_PROXY_USER")
    password = args.password or os.environ.get("AGENT_PROXY_PASSWORD")
    try:
        if not user:
            user = input("username [admin]: ").strip() or "admin"
        if not password:
            password = getpass.getpass(f"password for {user}: ")
    except EOFError:
        raise ApiError("no username/password given and none could be read from the terminal") from None
    return user, password


def main() -> int:
    # connection options work before and after the subcommand; SUPPRESS keeps the
    # subcommand's copy from overwriting a value given before it
    common = argparse.ArgumentParser(add_help=False, argument_default=argparse.SUPPRESS)
    common.add_argument("--url", help="web UI / API base URL (default: $AGENT_PROXY_URL or http://127.0.0.1:8080)")
    common.add_argument("-u", "--user", help="web UI username (asked for when omitted)")
    common.add_argument("-p", "--password", help="web UI password (asked for when omitted)")
    p = argparse.ArgumentParser(description="Manage the targets (rules) of a running agent-proxy.",
                                parents=[common], formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    sub = p.add_subparsers(dest="command", required=True)

    ls = sub.add_parser("list", parents=[common], help="list all rules")
    ls.add_argument("--kind", choices=KINDS, help="only rules of this kind")
    ls.add_argument("--json", action="store_true", help="print the rules as JSON")
    ls.set_defaults(func=cmd_list)

    a = sub.add_parser("add", parents=[common], help="add a single rule")
    a.add_argument("kind", choices=KINDS, help="allow / deny (HTTP(S) via squid) or tcp (L4 firewall)")
    a.add_argument("target", help="e.g. api.x.io, *.x.io, https://x.io/v1/*, 42.42.42.42, 10.0.0.0/24")
    a.add_argument("--name", help="rule name (generated from kind + target when omitted)")
    a.add_argument("--ports", help="tcp only: 3306, 80,443 or 8000-8100")
    a.add_argument("--proto", choices=("tcp", "udp"), help="tcp only: transport protocol (default tcp)")
    a.add_argument("--comment", help="free text, max 200 chars")
    a.add_argument("--disabled", action="store_true", help="add the rule disabled")
    a.set_defaults(func=cmd_add)

    i = sub.add_parser("import", parents=[common], help="import rules from a JSON file (config export format)")
    i.add_argument("file", help="JSON file with a 'rules' list, or '-' for stdin")
    i.add_argument("--replace", action="store_true", help="replace all existing rules instead of merging")
    i.add_argument("--with-settings", action="store_true", help="also apply the file's 'settings' object")
    i.add_argument("-y", "--yes", action="store_true", help="don't ask before --replace")
    i.set_defaults(func=cmd_import)

    for name, func, text in (("remove", cmd_remove, "delete rules by ID"),
                             ("disable", cmd_set_enabled, "disable rules by ID (kept, but not applied)"),
                             ("enable", cmd_set_enabled, "re-enable disabled rules by ID")):
        c = sub.add_parser(name, parents=[common], help=text)
        c.add_argument("ids", nargs="+", metavar="ID", help="rule ID as shown by 'list'")
        c.set_defaults(func=func)

    args = p.parse_args()
    # defaults set here, not on the parsers: the parsers share these actions (see `common`)
    args.url = getattr(args, "url", None) or os.environ.get("AGENT_PROXY_URL", "http://127.0.0.1:8080")
    args.user = getattr(args, "user", None)
    args.password = getattr(args, "password", None)
    try:
        if args.command == "import":
            args.doc = load_rules_file(args.file)  # fail on a bad file before asking for credentials
            if args.file == "-" and not (args.user or os.environ.get("AGENT_PROXY_USER")):
                raise ApiError("reading rules from stdin: pass --user (the password is read from the terminal)")
        client = Client(args.url, *credentials(args))
        return args.func(client, args)
    except ApiError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
