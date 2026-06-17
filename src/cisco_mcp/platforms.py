"""Platform definitions and per-platform behavior.

The key behavioral difference between platforms drives the whole two-account
design:

* IOS / IOS-XE use numeric *privilege levels*. Most ``show`` commands run at
  privilege 1, but ``show running-config`` / ``show startup-config`` require
  privilege 15. This is why we keep a separate priv-15 account.

* NX-OS (Nexus) uses *role-based access control* (RBAC), not privilege levels.
  The built-in ``network-operator`` role is read-only yet can already run
  ``show running-config``. So on Nexus there is nothing to escalate to -- the
  single read-only account covers everything, and we never use the priv-15
  account there.
"""

from __future__ import annotations

from enum import Enum


class Platform(str, Enum):
    IOS = "ios"
    IOSXE = "iosxe"
    NXOS = "nxos"


# Maps our inventory platform names to Netmiko device_type strings.
NETMIKO_DEVICE_TYPE: dict[Platform, str] = {
    Platform.IOS: "cisco_ios",
    Platform.IOSXE: "cisco_xe",
    Platform.NXOS: "cisco_nxos",
}


def supports_privilege_levels(platform: Platform) -> bool:
    """True if the platform uses numeric privilege levels (IOS family).

    Nexus uses RBAC, so privilege escalation is meaningless there and we always
    stay on the read-only account.
    """
    return platform in (Platform.IOS, Platform.IOSXE)


def netmiko_device_type(platform: Platform) -> str:
    return NETMIKO_DEVICE_TYPE[platform]
