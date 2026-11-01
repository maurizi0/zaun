"""Run once by the entrypoint before squid starts: render config and lock down egress."""
import logging
import sys
from pathlib import Path

from . import config as cfg
from .apply import ApplyError, apply
from .rules import RuleError

logging.basicConfig(level=logging.INFO, format="bootstrap: %(message)s")


def main() -> int:
    if cfg.GATEWAY:
        for interface in (cfg.GATEWAY.agent_interface, cfg.GATEWAY.uplink_interface):
            if not (Path("/sys/class/net") / interface).exists():
                print(f"bootstrap: gateway interface {interface!r} does not exist in this network namespace",
                      file=sys.stderr)
                return 1
        for version, setting in ((4, "/proc/sys/net/ipv4/ip_forward"),
                                 (6, "/proc/sys/net/ipv6/conf/all/forwarding")):
            if any((":" in n) == (version == 6) for n in cfg.GATEWAY.networks):
                if Path(setting).read_text().strip() != "1":
                    logging.warning("IPv%d forwarding is disabled; enable it after installing the boot guard", version)
    try:
        rules = cfg.load_rules()
        settings = cfg.load_settings()
    except (RuleError, ValueError) as e:
        print(f"bootstrap: {cfg.CONFIG_FILE} is invalid: {e}", file=sys.stderr)
        return 1
    if not cfg.CONFIG_FILE.exists():
        cfg.save_config(rules, settings)
    elif settings != cfg.DEFAULT_SETTINGS:
        print(f"bootstrap: settings in {cfg.CONFIG_FILE} override the env: (saved settings)", file=sys.stderr)
    try:
        apply(rules, settings, reconfigure=False)
    except ApplyError as e:
        print(f"bootstrap: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
