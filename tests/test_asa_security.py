"""Adversarial security tests focused on ASA/Firepower.

The whole promise of this server is "read-only, no exceptions". These tests try
to break that promise with ASA-flavored destructive commands, injection, and
privilege tricks. Every one must be rejected by the fail-closed allowlist, and
only ``show running-config`` may ever touch the priv-15 account.
"""

import pytest

from cisco_mcp.allowlist import CommandError, check_command, requires_privilege15
from cisco_mcp.connection import select_account
from cisco_mcp.inventory import Device
from cisco_mcp.platforms import Platform
import cisco_mcp.connection as connection


# --- Destructive / state-changing ASA commands MUST be rejected -----------

# These are real ASA/Firepower EXEC commands that change state, write config,
# read the filesystem directly, or run tools. None is a plain ``show``; all must
# fail the gate.
ASA_FORBIDDEN = [
    # config mode
    "configure terminal",
    "conf t",
    "configure",
    # writing / saving config
    "write memory",
    "write standby",
    "write erase",
    "write net",
    "copy running-config tftp://10.0.0.1/cfg",
    "copy running-config startup-config",
    # reboot / failover control
    "reload",
    "reload noconfirm",
    "failover active",
    "failover reload-standby",
    "failover exec standby show run",
    # clearing counters / connections / xlate (all state changes)
    "clear configure all",
    "clear conn all",
    "clear xlate",
    "clear crypto ipsec sa",
    "clear arp",
    "clear capture CAP",
    # filesystem / erase / delete
    "delete flash:/backup.cfg",
    "erase configuration",
    "format flash:",
    # diagnostic tools that create state or run actively
    "packet-tracer input outside tcp 1.1.1.1 80 2.2.2.2 80",
    "capture CAP interface outside",
    "debug crypto isakmp",
    "test aaa-server authentication LOCAL",
    "perfmon interval 10",
    # context / session pivots
    "changeto context admin",
    "changeto system",
    "session 1",
    # crypto / key material generation
    "crypto key generate rsa",
    # negation
    "no shutdown",
    # reading config WITHOUT 'show' -- 'more' bypasses the show gate, so it must
    # be rejected by the prefix check (fail-closed even though it's read-only).
    "more system:running-config",
    "dir flash:",
    "wr",
]


@pytest.mark.parametrize("cmd", ASA_FORBIDDEN)
def test_asa_destructive_commands_rejected(cmd):
    with pytest.raises(CommandError):
        check_command(cmd)


# --- Injection / chaining tricks MUST be rejected -------------------------

INJECTION = [
    "show version ; reload",
    "show version;reload",
    "show run && write mem",
    "show version\nreload",
    "show version\r\nconfigure terminal",
    "show run | redirect flash:/cfg.txt",
    "show run | tee flash:/cfg.txt",
    "show run | append flash:/cfg.txt",
    "show run > flash:/cfg.txt",
    "show running-config | redirect tftp://10.0.0.1/x",
    # sneaky: legit-looking prefix then a chained destructive command
    "show failover ; clear xlate",
    "show conn count && reload noconfirm",
    # write-to-file via the 'file' keyword (not a pipe) -> a filesystem dest
    "show tech-support file disk0:tech.txt",
    "show running-config file flash:cfg.txt",
    "show tech-support file bootflash:out",
]


@pytest.mark.parametrize("cmd", INJECTION)
def test_injection_and_chaining_rejected(cmd):
    with pytest.raises(CommandError):
        check_command(cmd)


# --- Legit ASA read-only shows MUST pass ----------------------------------

ASA_ALLOWED = [
    "show running-config",
    "show version",
    "show failover",
    "show conn count",
    "show xlate count",
    "show nat",
    "show vpn-sessiondb",
    "show access-list",
    "show arp",
    "show route",
    "show interface",
    "show interface ip brief",
    "show ipv6 neighbor",
    "show ipv6 route",
    "show ipv6 interface brief",
    "show module",
    "show cpu usage",
    "show memory",
    "show capture",                       # shows existing captures -- read only
    "show running-config | include hostname",
    "show access-list | include deny",
    # 'file' guard must NOT false-positive on these legit reads:
    "show file systems",                  # lists filesystems (no fs URI after 'file')
    "show flash:",                        # lists flash contents (no 'file' keyword)
    "show disk0:",
]


@pytest.mark.parametrize("cmd", ASA_ALLOWED)
def test_asa_read_only_shows_allowed(cmd):
    # Should not raise; returns the normalized command.
    assert check_command(cmd)


# --- Encoding / control-character tricks fail closed ----------------------


@pytest.mark.parametrize(
    "cmd",
    [
        "ѕhow version",       # Cyrillic 's' homoglyph -> not ASCII 'sh'
        "show version\x00 ; reload",  # null byte then chained command
        "show|include x",          # no space after show -> not a show prefix
        "",
        "   ",
    ],
)
def test_malformed_input_rejected(cmd):
    with pytest.raises(CommandError):
        check_command(cmd)


# --- Privilege-15 scoping on ASA is exactly 'show running-config' ---------


@pytest.fixture(autouse=True)
def fake_accounts(monkeypatch):
    from cisco_mcp import credentials
    ro_acct = credentials.Account(username="ro", password="x")
    p15_acct = credentials.Account(username="p15", password="x")
    monkeypatch.setattr(connection, "read_only_account", lambda: ro_acct)
    monkeypatch.setattr(connection, "privilege15_account", lambda: p15_acct)
    return ro_acct, p15_acct


def _asa():
    return Device(name="fw", host="1.1.1.1", platform=Platform.ASA)


@pytest.mark.parametrize(
    "cmd",
    ["show running-config", "show run", "sh run", "show running", "show running-config all"],
)
def test_asa_show_run_family_uses_priv15(cmd, fake_accounts):
    _, p15 = fake_accounts
    assert requires_privilege15(cmd) is True
    account, label = select_account(_asa(), cmd)
    assert account is p15 and label == "privilege-15"


@pytest.mark.parametrize(
    "cmd",
    [
        "show version",
        "show failover",
        "show conn count",
        "show xlate count",
        "show nat",
        "show vpn-sessiondb",
        "show access-list",
        "show arp",
        "show route",
        "show ipv6 route",
        "show module",
        # explicitly NOT priv-15 even though they touch config-ish data:
        "show startup-config",
        "show tech-support",
    ],
)
def test_asa_everything_else_stays_read_only(cmd, fake_accounts):
    ro, _ = fake_accounts
    assert requires_privilege15(cmd) is False
    account, label = select_account(_asa(), cmd)
    assert account is ro and label == "read-only"
