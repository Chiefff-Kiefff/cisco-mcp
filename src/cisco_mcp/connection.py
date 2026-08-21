"""SSH connection handling and account selection.

This ties the pieces together:

1. The command is validated by ``allowlist.check_command`` (fail-closed).
2. The right account is chosen based on the command + device platform.
3. Netmiko opens an SSH session and runs the single show command.

Account-selection rule (hardcoded policy):

* IOS / IOS-XE / ASA + command needs priv 15 -> priv-15 account
* everything else (incl. all NX-OS)          -> read-only account
"""

from __future__ import annotations

from dataclasses import dataclass

from netmiko import ConnectHandler

from .allowlist import check_command, requires_privilege15
from .credentials import Account, privilege15_account, read_only_account
from .inventory import Device
from .platforms import netmiko_device_type, supports_privilege_levels


@dataclass
class CommandResult:
    device: str
    command: str
    account: str          # "read-only" or "privilege-15" (which profile ran it)
    output: str


def select_account(device: Device, command: str) -> tuple[Account, str]:
    """Pick the account profile for this command/device.

    Returns (account, label) where label is a human-readable name for logging
    and for surfacing to the caller -- never the credentials themselves.
    """
    if supports_privilege_levels(device.platform) and requires_privilege15(command):
        return privilege15_account(), "privilege-15"
    return read_only_account(), "read-only"


def run_show(device: Device, command: str) -> CommandResult:
    """Validate, connect, and run a single show command. Read-only end to end."""
    norm = check_command(command)  # raises CommandError if not a safe show
    account, label = select_account(device, norm)

    params: dict[str, object] = {
        "device_type": netmiko_device_type(device.platform),
        "host": device.host,
        "port": device.port,
        "username": account.username,
        "password": account.password,
        "fast_cli": False,
    }
    if account.enable_secret:
        params["secret"] = account.enable_secret

    with ConnectHandler(**params) as conn:
        # Only enter privileged EXEC when we actually have an enable secret and
        # the command needs it. Auto-priv-15 accounts skip this entirely.
        if account.enable_secret and label == "privilege-15":
            conn.enable()
        output = conn.send_command(norm, read_timeout=60)

    return CommandResult(
        device=device.name,
        command=norm,
        account=label,
        output=output,
    )
