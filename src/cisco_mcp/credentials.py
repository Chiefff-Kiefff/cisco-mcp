"""Credential profiles loaded from the environment.

Two accounts, per the design:

* Read-only account  -- used for ALL normal tool calls.
* Priv-15 account    -- used ONLY for ``show running-config`` on IOS/IOS-XE.

Secrets are never hardcoded in source. They come from environment variables
(typically loaded from a gitignored ``.env``). The *policy* of which account to
use is hardcoded (see ``allowlist.py`` / ``connection.py``); the *secrets* are
not.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()  # load .env if present; real env vars take precedence


@dataclass(frozen=True)
class Account:
    username: str
    password: str
    # Optional enable secret. With auto priv-15 accounts this stays empty; it is
    # supported so a deployment that logs in lower can still `enable`.
    enable_secret: str = ""


class CredentialError(RuntimeError):
    pass


def _require(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise CredentialError(
            f"Missing required environment variable: {name}. "
            f"See .env.example."
        )
    return value


def read_only_account() -> Account:
    """The account used for every normal tool call."""
    return Account(
        username=_require("CISCO_RO_USERNAME"),
        password=_require("CISCO_RO_PASSWORD"),
        enable_secret=os.environ.get("CISCO_RO_ENABLE_SECRET", "").strip(),
    )


def privilege15_account() -> Account:
    """The account used only for priv-15 commands on IOS/IOS-XE."""
    return Account(
        username=_require("CISCO_PRIV15_USERNAME"),
        password=_require("CISCO_PRIV15_PASSWORD"),
        enable_secret=os.environ.get("CISCO_PRIV15_ENABLE_SECRET", "").strip(),
    )
