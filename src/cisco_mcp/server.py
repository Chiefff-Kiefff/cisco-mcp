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
    IOS/IOS-XE, 'show running-config' is the only command that escalates to
    the privilege-15 account -- everything else, and every command on NX-OS,
    uses the read-only account.
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

    On IOS/IOS-XE this uses the privilege-15 account; on NX-OS the read-only
    (network-operator) account can already read it.
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
    """
    return _run_by_platform(device, {
        Platform.IOS: "show processes cpu history",
        Platform.IOSXE: "show processes cpu history",
        Platform.NXOS: "show system resources",
    })


@mcp.tool()
def get_memory(device: str) -> str:
    """Show memory utilization.

    IOS/IOS-XE: 'show memory statistics'. NX-OS: 'show system resources'.
    """
    return _run_by_platform(device, {
        Platform.IOS: "show memory statistics",
        Platform.IOSXE: "show memory statistics",
        Platform.NXOS: "show system resources",
    })


@mcp.tool()
def get_environment(device: str) -> str:
    """Show environmental info -- power, fans, temperature ('show environment')."""
    return _run(device, "show environment")


@mcp.tool()
def get_poe_status(device: str) -> str:
    """Show PoE inline power status ('show power inline'). Only meaningful on PoE switches."""
    return _run(device, "show power inline")


# --- L2 / campus switching ------------------------------------------------


@mcp.tool()
def get_interfaces(device: str) -> str:
    """Show interface details ('show interfaces')."""
    return _run(device, "show interfaces")


@mcp.tool()
def get_interface_status(device: str) -> str:
    """Show a brief interface status table ('show ip interface brief')."""
    return _run(device, "show ip interface brief")


@mcp.tool()
def get_vlans(device: str) -> str:
    """Show configured VLANs ('show vlan brief')."""
    return _run(device, "show vlan brief")


@mcp.tool()
def get_trunks(device: str) -> str:
    """Show trunk interfaces and allowed VLANs ('show interfaces trunk')."""
    return _run(device, "show interfaces trunk")


@mcp.tool()
def get_spanning_tree(device: str) -> str:
    """Show spanning-tree state per VLAN ('show spanning-tree')."""
    return _run(device, "show spanning-tree")


@mcp.tool()
def get_etherchannels(device: str) -> str:
    """Show link-aggregation state.

    IOS/IOS-XE: 'show etherchannel summary'. NX-OS: 'show port-channel summary'.
    """
    return _run_by_platform(device, {
        Platform.IOS: "show etherchannel summary",
        Platform.IOSXE: "show etherchannel summary",
        Platform.NXOS: "show port-channel summary",
    })


@mcp.tool()
def get_mac_address_table(device: str) -> str:
    """Show the MAC address table ('show mac address-table')."""
    return _run(device, "show mac address-table")


# --- L3 / routing ---------------------------------------------------------


@mcp.tool()
def get_arp_table(device: str) -> str:
    """Show the ARP table ('show ip arp')."""
    return _run(device, "show ip arp")


@mcp.tool()
def get_routing_table(device: str) -> str:
    """Show the IPv4 routing table ('show ip route')."""
    return _run(device, "show ip route")


@mcp.tool()
def get_ospf_neighbors(device: str) -> str:
    """Show OSPF neighbors ('show ip ospf neighbor')."""
    return _run(device, "show ip ospf neighbor")


@mcp.tool()
def get_bgp_summary(device: str) -> str:
    """Show BGP peer summary ('show ip bgp summary')."""
    return _run(device, "show ip bgp summary")


@mcp.tool()
def get_eigrp_neighbors(device: str) -> str:
    """Show EIGRP neighbors ('show ip eigrp neighbors')."""
    return _run(device, "show ip eigrp neighbors")


# --- Neighbor discovery ---------------------------------------------------


@mcp.tool()
def get_cdp_neighbors(device: str) -> str:
    """Show directly connected Cisco neighbors ('show cdp neighbors detail')."""
    return _run(device, "show cdp neighbors detail")


@mcp.tool()
def get_lldp_neighbors(device: str) -> str:
    """Show LLDP neighbors, including non-Cisco devices ('show lldp neighbors detail')."""
    return _run(device, "show lldp neighbors detail")


def main() -> None:
    """Console entry point (stdio transport)."""
    mcp.run()


if __name__ == "__main__":
    main()
