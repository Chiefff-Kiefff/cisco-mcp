"""Command safety gate and account-selection policy.

This module is the security heart of the server. It is *fail-closed*: anything
that is not a recognized, safe ``show`` command is rejected. The LLM never gets
to decide what is safe -- the server enforces it mechanically, which also
protects against prompt-injection arriving through command output or arguments.

Two independent decisions live here:

1. ``check_command`` -- is this command allowed to run at all?
2. ``requires_privilege15`` -- does it need the priv-15 account (IOS only)?
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# --- Normalization ---------------------------------------------------------

_WHITESPACE = re.compile(r"\s+")


def normalize(command: str) -> str:
    """Lowercase and collapse whitespace so matching is predictable."""
    return _WHITESPACE.sub(" ", command.strip().lower())


# --- Hard blocks -----------------------------------------------------------

# A command must START with show / sh (Cisco allows abbreviation).
_SHOW_PREFIX = re.compile(r"^sh(ow)?\s+\S")

# Tokens that indicate writing to the device/filesystem or chaining commands.
# Even though we only ever send a single ``show``, these defend in depth against
# pipe-to-write tricks and command stacking.
_FORBIDDEN = (
    "redirect",   # show ... | redirect flash:...
    "tee",        # show ... | tee ...
    "append",     # show ... | append ...
    ">",          # any redirect-style operator
    ";",          # command chaining
    "\n",         # multiple commands
    "\r",
    "&",
)

# Even read-oriented EXEC commands that we explicitly never want to run.
_FORBIDDEN_PHRASES = (
    "configure",
    "config t",
    "config terminal",
    "write",        # write memory / write erase
    "erase",
    "reload",
    "copy",
    "delete",
    "clear",        # clear counters / clear logging etc. are state changes
    "debug",
    "no ",
    "test ",
)


# --- Privilege-15 policy (IOS/IOS-XE) -------------------------------------

# Commands that require privileged EXEC (priv 15) on IOS/IOS-XE. Matched after
# normalization, with abbreviations handled. This is the hardcoded policy the
# user asked for: these route to the priv-15 account on IOS devices.
_PRIV15 = re.compile(
    r"^sh(ow)?\s+("
    r"run(n(ing(-config)?)?)?"      # show run / running / running-config
    r"|start(up(-config)?)?"        # show startup / startup-config
    r"|tech(-support)?"             # show tech-support
    r"|archive"                     # show archive config ...
    r")\b"
)


def requires_privilege15(command: str) -> bool:
    """True if the command needs privilege 15 on IOS/IOS-XE."""
    return bool(_PRIV15.match(normalize(command)))


# --- Public check ----------------------------------------------------------


@dataclass
class CommandError(Exception):
    """Raised when a command fails the allowlist."""

    reason: str

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.reason


def check_command(command: str) -> str:
    """Validate a command and return its normalized form.

    Raises ``CommandError`` (fail-closed) if the command is not a safe show.
    """
    norm = normalize(command)

    if not norm:
        raise CommandError("Empty command.")

    if not _SHOW_PREFIX.match(norm):
        raise CommandError(
            "Only 'show' commands are permitted. This server is strictly "
            "read-only."
        )

    for token in _FORBIDDEN:
        if token in norm:
            raise CommandError(f"Command contains forbidden token: {token!r}")

    for phrase in _FORBIDDEN_PHRASES:
        # match as a word/segment to avoid false positives inside arguments
        if re.search(rf"(^|\s|\|){re.escape(phrase.strip())}(\s|$)", norm):
            raise CommandError(f"Command contains forbidden keyword: {phrase.strip()!r}")

    return norm
