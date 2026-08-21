"""MCP server exposing read-only Cisco show tools.

Hybrid tool design:
* curated, named tools for the common questions, and
* one guarded ``run_show_command`` for anything else,

all routed through the same allowlist + account-selection gate.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from .allowlist import CommandError
from .connection import CommandResult, run_show
from .credentials import CredentialError
from .inventory import Device, Inventory, load_inventory
from .platforms import Platform

mcp = FastMCP("cisco-mcp")

# Inventory is loaded lazily so the server can start even before devices.yaml is
# present, and so tests can inject their own.
_inventory: Inventory | None = None


def get_inventory() -> Inventory:
    global _inventory
    if _inventory is None:
        _inventory = load_inventory()
    return _inventory


def _format(result: CommandResult) -> str:
    return (
        f"# {result.device} :: {result.command}\n"
        f"# (ran via {result.account} account)\n\n"
        f"{result.output}"
    )


def _run_on(device: Device, command: str) -> str:
    try:
        return _format(run_show(device, command))
    except CommandError as e:
        return f"REJECTED (read-only safety gate): {e}"
    except CredentialError as e:
        return f"CONFIG ERROR: {e}"
    except Exception as e:  # netmiko / SSH failures
        return f"CONNECTION ERROR: {type(e).__name__}: {e}"


def _run(device_name: str, command: str) -> str:
    """Shared path for every tool. Translates errors into readable messages."""
    try:
        device = get_inventory().get(device_name)
    except KeyError as e:
        return f"ERROR: {e}"
    return _run_on(device, command)


def _run_by_platform(device_name: str, by_platform: dict[Platform, str]) -> str:
    """Dispatch to a different command per platform (e.g., IOS vs NX-OS)."""
    try:
        device = get_inventory().get(device_name)
    except KeyError as e:
        return f"ERROR: {e}"
    command = by_platform.get(device.platform)
    if command is None:
        return f"ERROR: this tool is not supported on platform {device.platform.value}."
    return _run_on(device, command)


def _ios_family(command: str) -> dict[Platform, str]:
    """Both IOS and IOS-XE take the same command; helper to cut repetition."""
    return {Platform.IOS: command, Platform.IOSXE: command}


# --- Tools -----------------------------------------------------------------


@mcp.tool()
def list_devices() -> str:
    """List the switches available in the inventory, with platform and notes."""
    try:
        devices = get_inventory().list()
    except FileNotFoundError as e:
        return f"CONFIG ERROR: {e}"
    if not devices:
        return "No devices configured. Add them to devices.yaml."
    lines = ["name | host | platform | description"]
    for d in devices:
        lines.append(f"{d.name} | {d.host} | {d.platform.value} | {d.description}")
    return "\n".join(lines)


@mcp.tool()
def run_show_command(device: str, command: str) -> str:
    """Run an arbitrary read-only 'show' command on a device.

    Only 'show' commands are permitted; the server rejects anything else. On
    IOS/IOS-XE/ASA, 'show running-config' is the only command that escalates
    to the privilege-15 account -- everything else, and every command on
    NX-OS, uses the read-only account.
    """
    return _run(device, command)


# --- System / identity ----------------------------------------------------


@mcp.tool()
def get_version(device: str) -> str:
    """Show hardware/software version info ('show version')."""
    return _run(device, "show version")


@mcp.tool()
def get_running_config(device: str) -> str:
    """Show the running configuration ('show running-config').

    On IOS/IOS-XE/ASA this uses the privilege-15 account; on NX-OS the
    read-only (network-operator) account can already read it.
    """
    return _run(device, "show running-config")


@mcp.tool()
def get_inventory_hw(device: str) -> str:
    """Show chassis/module/serial inventory ('show inventory')."""
    return _run(device, "show inventory")


@mcp.tool()
def get_clock(device: str) -> str:
    """Show the device's current time ('show clock')."""
    return _run(device, "show clock")


@mcp.tool()
def get_logs(device: str) -> str:
    """Show the device's log buffer ('show logging'). Can be large on busy devices."""
    return _run(device, "show logging")


# --- Health / capacity ----------------------------------------------------


@mcp.tool()
def get_cpu(device: str) -> str:
    """Show CPU utilization.

    IOS/IOS-XE: 'show processes cpu history'. NX-OS: 'show system resources'.
    ASA: 'show cpu usage'.
    """
    return _run_by_platform(device, {
        **_ios_family("show processes cpu history"),
        Platform.NXOS: "show system resources",
        Platform.ASA: "show cpu usage",
    })


@mcp.tool()
def get_memory(device: str) -> str:
    """Show memory utilization.

    IOS/IOS-XE: 'show memory statistics'. NX-OS: 'show system resources'.
    ASA: 'show memory'.
    """
    return _run_by_platform(device, {
        **_ios_family("show memory statistics"),
        Platform.NXOS: "show system resources",
        Platform.ASA: "show memory",
    })


@mcp.tool()
def get_environment(device: str) -> str:
    """Show environmental info -- power, fans, temperature ('show environment')."""
    return _run(device, "show environment")


@mcp.tool()
def get_poe_status(device: str) -> str:
    """Show PoE inline power status ('show power inline'). Only meaningful on PoE switches."""
    return _run_by_platform(device, {
        **_ios_family("show power inline"),
        Platform.NXOS: "show power inline",
    })


# --- L2 / campus switching ------------------------------------------------


@mcp.tool()
def get_interfaces(device: str) -> str:
    """Show interface details ('show interfaces'; 'show interface' on ASA)."""
    return _run_by_platform(device, {
        **_ios_family("show interfaces"),
        Platform.NXOS: "show interface",
        Platform.ASA: "show interface",
    })


@mcp.tool()
def get_interface_status(device: str) -> str:
    """Show a brief interface status table.

    IOS/IOS-XE/NX-OS: 'show ip interface brief'. ASA: 'show interface ip brief'.
    """
    return _run_by_platform(device, {
        **_ios_family("show ip interface brief"),
        Platform.NXOS: "show ip interface brief",
        Platform.ASA: "show interface ip brief",
    })


@mcp.tool()
def get_vlans(device: str) -> str:
    """Show configured VLANs ('show vlan brief'). Not supported on ASA."""
    return _run_by_platform(device, {
        **_ios_family("show vlan brief"),
        Platform.NXOS: "show vlan brief",
    })


@mcp.tool()
def get_trunks(device: str) -> str:
    """Show trunk interfaces and allowed VLANs ('show interfaces trunk'). Not supported on ASA."""
    return _run_by_platform(device, {
        **_ios_family("show interfaces trunk"),
        Platform.NXOS: "show interface trunk",
    })


@mcp.tool()
def get_spanning_tree(device: str) -> str:
    """Show spanning-tree state per VLAN ('show spanning-tree'). Not supported on ASA."""
    return _run_by_platform(device, {
        **_ios_family("show spanning-tree"),
        Platform.NXOS: "show spanning-tree",
    })


@mcp.tool()
def get_etherchannels(device: str) -> str:
    """Show link-aggregation state.

    IOS/IOS-XE: 'show etherchannel summary'. NX-OS/ASA: 'show port-channel summary'.
    """
    return _run_by_platform(device, {
        **_ios_family("show etherchannel summary"),
        Platform.NXOS: "show port-channel summary",
        Platform.ASA: "show port-channel summary",
    })


@mcp.tool()
def get_mac_address_table(device: str) -> str:
    """Show the MAC address table.

    'show mac address-table' on switches; 'show mac-address-table' on ASA
    (only populated in transparent firewall mode).
    """
    return _run_by_platform(device, {
        **_ios_family("show mac address-table"),
        Platform.NXOS: "show mac address-table",
        Platform.ASA: "show mac-address-table",
    })


# --- L3 / routing ---------------------------------------------------------


@mcp.tool()
def get_arp_table(device: str) -> str:
    """Show the ARP table ('show ip arp'; 'show arp' on ASA)."""
    return _run_by_platform(device, {
        **_ios_family("show ip arp"),
        Platform.NXOS: "show ip arp",
        Platform.ASA: "show arp",
    })


@mcp.tool()
def get_routing_table(device: str) -> str:
    """Show the IPv4 routing table ('show ip route'; 'show route' on ASA)."""
    return _run_by_platform(device, {
        **_ios_family("show ip route"),
        Platform.NXOS: "show ip route",
        Platform.ASA: "show route",
    })


@mcp.tool()
def get_ospf_neighbors(device: str) -> str:
    """Show OSPF neighbors ('show ip ospf neighbor'; 'show ospf neighbor' on ASA)."""
    return _run_by_platform(device, {
        **_ios_family("show ip ospf neighbor"),
        Platform.NXOS: "show ip ospf neighbor",
        Platform.ASA: "show ospf neighbor",
    })


@mcp.tool()
def get_bgp_summary(device: str) -> str:
    """Show BGP peer summary ('show ip bgp summary'; 'show bgp summary' on ASA)."""
    return _run_by_platform(device, {
        **_ios_family("show ip bgp summary"),
        Platform.NXOS: "show ip bgp summary",
        Platform.ASA: "show bgp summary",
    })


@mcp.tool()
def get_eigrp_neighbors(device: str) -> str:
    """Show EIGRP neighbors ('show ip eigrp neighbors'; 'show eigrp neighbors' on ASA)."""
    return _run_by_platform(device, {
        **_ios_family("show ip eigrp neighbors"),
        Platform.NXOS: "show ip eigrp neighbors",
        Platform.ASA: "show eigrp neighbors",
    })


# --- Neighbor discovery ---------------------------------------------------


@mcp.tool()
def get_cdp_neighbors(device: str) -> str:
    """Show directly connected Cisco neighbors ('show cdp neighbors detail'). Not supported on ASA."""
    return _run_by_platform(device, {
        **_ios_family("show cdp neighbors detail"),
        Platform.NXOS: "show cdp neighbors detail",
    })


@mcp.tool()
def get_lldp_neighbors(device: str) -> str:
    """Show LLDP neighbors, including non-Cisco devices ('show lldp neighbors detail'). Not supported on ASA."""
    return _run_by_platform(device, {
        **_ios_family("show lldp neighbors detail"),
        Platform.NXOS: "show lldp neighbors detail",
    })


# --- Firewall (ASA) ---------------------------------------------------------


@mcp.tool()
def get_failover_status(device: str) -> str:
    """Show ASA failover (HA) state and health ('show failover'). ASA only."""
    return _run_by_platform(device, {Platform.ASA: "show failover"})


@mcp.tool()
def get_connection_count(device: str) -> str:
    """Show the ASA connection table count ('show conn count'). ASA only."""
    return _run_by_platform(device, {Platform.ASA: "show conn count"})


@mcp.tool()
def get_xlate_count(device: str) -> str:
    """Show the ASA NAT translation count ('show xlate count'). ASA only."""
    return _run_by_platform(device, {Platform.ASA: "show xlate count"})


@mcp.tool()
def get_nat(device: str) -> str:
    """Show ASA NAT policies with hit counts ('show nat'). ASA only."""
    return _run_by_platform(device, {Platform.ASA: "show nat"})


@mcp.tool()
def get_vpn_sessions(device: str) -> str:
    """Show a summary of active VPN sessions ('show vpn-sessiondb'). ASA only."""
    return _run_by_platform(device, {Platform.ASA: "show vpn-sessiondb"})


@mcp.tool()
def get_access_lists(device: str) -> str:
    """Show access lists with hit counts.

    'show access-lists' on IOS/IOS-XE/NX-OS; 'show access-list' on ASA.
    Can be very large on firewalls with big policies.
    """
    return _run_by_platform(device, {
        **_ios_family("show access-lists"),
        Platform.NXOS: "show access-lists",
        Platform.ASA: "show access-list",
    })


def main() -> None:
    """Console entry point (stdio transport)."""
    mcp.run()


if __name__ == "__main__":
    main()
