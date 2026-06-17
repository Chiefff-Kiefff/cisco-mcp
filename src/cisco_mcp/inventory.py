"""Device inventory loaded from devices.yaml."""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator

from .platforms import Platform


class Device(BaseModel):
    name: str
    host: str
    platform: Platform
    port: int = 22
    # Free-form description shown to the LLM via list_devices.
    description: str = ""

    @field_validator("platform", mode="before")
    @classmethod
    def _norm_platform(cls, v: object) -> object:
        if isinstance(v, str):
            return v.strip().lower()
        return v


class Inventory(BaseModel):
    devices: dict[str, Device] = Field(default_factory=dict)

    def get(self, name: str) -> Device:
        device = self.devices.get(name)
        if device is None:
            known = ", ".join(sorted(self.devices)) or "(none)"
            raise KeyError(
                f"Unknown device {name!r}. Known devices: {known}."
            )
        return device

    def list(self) -> list[Device]:
        return list(self.devices.values())


def _default_path() -> Path:
    # Allow override; otherwise look next to the project root / cwd.
    override = os.environ.get("CISCO_MCP_INVENTORY")
    if override:
        return Path(override)
    return Path.cwd() / "devices.yaml"


def load_inventory(path: str | os.PathLike[str] | None = None) -> Inventory:
    p = Path(path) if path else _default_path()
    if not p.exists():
        raise FileNotFoundError(
            f"Inventory file not found: {p}. Copy devices.example.yaml to "
            f"devices.yaml or set CISCO_MCP_INVENTORY."
        )
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    devices_raw = raw.get("devices", {})

    devices: dict[str, Device] = {}
    for name, body in devices_raw.items():
        body = dict(body or {})
        body.setdefault("name", name)
        devices[name] = Device(**body)

    return Inventory(devices=devices)
