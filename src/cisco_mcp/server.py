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
from .inventory import Inventory, load_inventory

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


def _run(device_name: str, command: str) -> str:
    """Shared path for every tool. Translates errors into readable messages."""
    try:
        device = get_inventory().get(device_name)
    except KeyError as e:
        return f"ERROR: {e}"
    try:
        return _format(run_show(device, command))
    except CommandError as e:
        return f"REJECTED (read-only safety gate): {e}"
    except CredentialError as e:
        return f"CONFIG ERROR: {e}"
    except Exception as e:  # netmiko / SSH failures
        return f"CONNECTION ERROR: {type(e).__name__}: {e}"


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
    IOS/IOS-XE, commands needing privilege 15 (e.g. 'show running-config') are
    automatically run with the privilege-15 account; all other commands and all
    NX-OS commands use the read-only account.
    """
    return _run(device, command)


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
def get_cdp_neighbors(device: str) -> str:
    """Show directly connected Cisco neighbors ('show cdp neighbors detail')."""
    return _run(device, "show cdp neighbors detail")


def main() -> None:
    """Console entry point (stdio transport)."""
    mcp.run()


if __name__ == "__main__":
    main()
