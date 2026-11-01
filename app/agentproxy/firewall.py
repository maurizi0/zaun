"""Deployment settings shared by initial apply and live firewall refreshes."""
from dataclasses import dataclass
import ipaddress
import re


@dataclass(frozen=True)
class Gateway:
    agent_interface: str
    uplink_interface: str
    networks: tuple[str, ...]
    masquerade: bool = False

    def __post_init__(self):
        for interface in (self.agent_interface, self.uplink_interface):
            if not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,15}", interface) or interface == "lo":
                raise ValueError("gateway interfaces must be explicit non-loopback interface names")
        if self.agent_interface == self.uplink_interface:
            raise ValueError("gateway agent and uplink interfaces must differ")
        if not self.networks:
            raise ValueError("GATEWAY_AGENT_NETWORKS must contain at least one CIDR")
        normalized = []
        for value in self.networks:
            network = ipaddress.ip_network(value, strict=True)
            if network.prefixlen == 0 or network.is_loopback or network.is_multicast or network.is_link_local:
                raise ValueError("gateway networks must be specific unicast agent subnets")
            normalized.append(str(network))
        object.__setattr__(self, "networks", tuple(normalized))
        if self.masquerade and not any(ipaddress.ip_network(n).version == 4 for n in normalized):
            raise ValueError("GATEWAY_MASQUERADE requires an IPv4 agent subnet")


def deployment(env):
    mode = env.get("FIREWALL_MODE", "container")
    if mode not in ("container", "gateway"):
        raise ValueError("FIREWALL_MODE must be container or gateway")
    gateway = None
    if mode == "gateway":
        if env.get("FIREWALL_ENFORCE", "1") in ("0", "false", "no"):
            raise ValueError("gateway mode requires FIREWALL_ENFORCE=1")
        nat = env.get("GATEWAY_MASQUERADE", "0")
        if nat not in ("0", "1"):
            raise ValueError("GATEWAY_MASQUERADE must be 0 or 1")
        gateway = Gateway(env.get("GATEWAY_AGENT_INTERFACE", ""),
                          env.get("GATEWAY_UPLINK_INTERFACE", ""),
                          tuple(env.get("GATEWAY_AGENT_NETWORKS", "").split()), nat == "1")
    return mode, gateway
