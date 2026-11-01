"""Print an empty-policy boot guard without writing files or loading rules."""
from . import config as cfg
from .rules import nft_ruleset


def main():
    if not cfg.GATEWAY:
        raise SystemExit("boot guard generation requires FIREWALL_MODE=gateway")
    # Kept separate from the live table's saved file: every boot starts default-deny,
    # then bootstrap atomically replaces it with the persisted application policy.
    text = nft_ruleset([], {}, [], gateway=cfg.GATEWAY)
    print(text, end="")


if __name__ == "__main__":
    main()
