"""Tests for the safety gate and priv-15 policy -- the security-critical core."""

import pytest

from cisco_mcp.allowlist import (
    CommandError,
    check_command,
    normalize,
    requires_privilege15,
)


# --- Allowed commands ------------------------------------------------------


@pytest.mark.parametrize(
    "cmd",
    [
        "show version",
        "SHOW VERSION",
        "  show   ip   interface   brief ",
        "show running-config",
        "sh run",
        "show interfaces status",
        "show vlan brief",
        "show cdp neighbors detail",
        "show running-config | include hostname",  # read-only pipe filter is fine
        "show ip route | section bgp",
    ],
)
def test_allowed(cmd):
    assert check_command(cmd) == normalize(cmd)


# --- Rejected commands -----------------------------------------------------


@pytest.mark.parametrize(
    "cmd",
    [
        "",
        "configure terminal",
        "conf t",
        "write memory",
        "reload",
        "copy running-config startup-config",
        "delete flash:foo",
        "clear counters",
        "debug ip packet",
        "no shutdown",
        "show running-config | redirect flash:cfg.txt",  # pipe-to-write
        "show run | tee flash:cfg.txt",
        "show version ; reload",                          # command chaining
        "ping 8.8.8.8",                                   # not a show
        "show version\nreload",                           # second command
    ],
)
def test_rejected(cmd):
    with pytest.raises(CommandError):
        check_command(cmd)


# --- Privilege-15 detection ------------------------------------------------


@pytest.mark.parametrize(
    "cmd",
    [
        "show running-config",
        "show run",
        "sh run",
        "show running-config all",
        "show startup-config",
        "show start",
        "show tech-support",
        "show archive config differences",
    ],
)
def test_requires_priv15(cmd):
    assert requires_privilege15(cmd) is True


@pytest.mark.parametrize(
    "cmd",
    [
        "show version",
        "show ip interface brief",
        "show vlan brief",
        "show interfaces",
        "show cdp neighbors detail",
        "show running",  # actually 'show run...' abbreviation -> see below
    ],
)
def test_does_not_require_priv15(cmd):
    # 'show running' is the abbreviation for running-config, so it DOES need 15.
    expected = cmd.startswith("show running")
    assert requires_privilege15(cmd) is expected
