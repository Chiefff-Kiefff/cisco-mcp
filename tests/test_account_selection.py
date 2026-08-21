"""Tests for account selection -- verifies the two-account policy per platform.

These don't touch the network; they monkeypatch the credential loaders so we can
assert which account profile would be chosen.
"""

import pytest

from cisco_mcp import connection, credentials
from cisco_mcp.inventory import Device
from cisco_mcp.platforms import Platform


@pytest.fixture(autouse=True)
def fake_accounts(monkeypatch):
    ro = credentials.Account(username="ro", password="x")
    p15 = credentials.Account(username="p15", password="x")
    monkeypatch.setattr(connection, "read_only_account", lambda: ro)
    monkeypatch.setattr(connection, "privilege15_account", lambda: p15)
    return ro, p15


def dev(platform: Platform) -> Device:
    return Device(name="d", host="1.1.1.1", platform=platform)


def test_ios_show_run_uses_priv15(fake_accounts):
    _, p15 = fake_accounts
    account, label = connection.select_account(dev(Platform.IOS), "show running-config")
    assert account is p15
    assert label == "privilege-15"


def test_ios_show_version_uses_readonly(fake_accounts):
    ro, _ = fake_accounts
    account, label = connection.select_account(dev(Platform.IOS), "show version")
    assert account is ro
    assert label == "read-only"


def test_iosxe_show_run_uses_priv15(fake_accounts):
    _, p15 = fake_accounts
    account, _ = connection.select_account(dev(Platform.IOSXE), "show running-config")
    assert account is p15


def test_nxos_show_run_uses_readonly(fake_accounts):
    """Nexus uses RBAC -- the read-only network-operator reads run-config, so we
    never escalate to the priv-15 account there."""
    ro, _ = fake_accounts
    account, label = connection.select_account(dev(Platform.NXOS), "show running-config")
    assert account is ro
    assert label == "read-only"


def test_asa_show_run_uses_priv15(fake_accounts):
    """ASA uses IOS-style privilege levels: show run needs priv 15 there too."""
    _, p15 = fake_accounts
    account, label = connection.select_account(dev(Platform.ASA), "show running-config")
    assert account is p15
    assert label == "privilege-15"


def test_asa_other_shows_use_readonly(fake_accounts):
    ro, _ = fake_accounts
    for cmd in ("show version", "show failover", "show conn count", "show route"):
        account, label = connection.select_account(dev(Platform.ASA), cmd)
        assert account is ro
        assert label == "read-only"
