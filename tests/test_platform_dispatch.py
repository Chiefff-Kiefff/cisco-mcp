"""Tests for per-platform command dispatch in the server tools.

No network: the inventory is injected and run_show is stubbed out so we can
assert exactly which CLI command each tool would send per platform.
"""

import pytest

from cisco_mcp import server
from cisco_mcp.connection import CommandResult
from cisco_mcp.inventory import Device, Inventory
from cisco_mcp.platforms import Platform


@pytest.fixture
def sent(monkeypatch):
    inv = Inventory(devices={
        "fw": Device(name="fw", host="1.1.1.1", platform=Platform.ASA),
        "sw": Device(name="sw", host="1.1.1.2", platform=Platform.IOS),
        "nx": Device(name="nx", host="1.1.1.3", platform=Platform.NXOS),
    })
    monkeypatch.setattr(server, "_inventory", inv)

    calls: dict[str, str] = {}

    def fake_run_show(device: Device, command: str) -> CommandResult:
        calls[device.name] = command
        return CommandResult(
            device=device.name, command=command, account="read-only", output="OK"
        )

    monkeypatch.setattr(server, "run_show", fake_run_show)
    return calls


def test_asa_gets_asa_flavored_commands(sent):
    server.get_routing_table("fw")
    assert sent["fw"] == "show route"
    server.get_arp_table("fw")
    assert sent["fw"] == "show arp"
    server.get_interface_status("fw")
    assert sent["fw"] == "show interface ip brief"
    server.get_cpu("fw")
    assert sent["fw"] == "show cpu usage"
    server.get_access_lists("fw")
    assert sent["fw"] == "show access-list"


def test_ios_keeps_ios_commands(sent):
    server.get_routing_table("sw")
    assert sent["sw"] == "show ip route"
    server.get_access_lists("sw")
    assert sent["sw"] == "show access-lists"


def test_asa_only_tools_work_on_asa(sent):
    server.get_failover_status("fw")
    assert sent["fw"] == "show failover"
    server.get_vpn_sessions("fw")
    assert sent["fw"] == "show vpn-sessiondb"


def test_asa_only_tools_reject_other_platforms(sent):
    out = server.get_failover_status("sw")
    assert "not supported" in out
    assert "sw" not in sent  # nothing was sent to the device


def test_switching_tools_reject_asa(sent):
    for tool in (
        server.get_vlans,
        server.get_trunks,
        server.get_spanning_tree,
        server.get_cdp_neighbors,
        server.get_lldp_neighbors,
        server.get_poe_status,
    ):
        out = tool("fw")
        assert "not supported" in out, tool.__name__
    assert "fw" not in sent
