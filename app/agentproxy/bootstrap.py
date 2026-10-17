"""Run once by the entrypoint before squid starts: render config and lock down egress."""
import logging
import sys

from . import config as cfg
from .apply import ApplyError, apply
from .rules import RuleError

logging.basicConfig(level=logging.INFO, format="bootstrap: %(message)s")


def main() -> int:
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
