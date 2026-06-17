# cisco-mcp

A read-only [MCP](https://modelcontextprotocol.io) server for Cisco **IOS / IOS-XE**
and **Nexus (NX-OS)** switches. It lets an LLM run `show` commands over SSH — and
nothing else.

## The two-account model

To run `show running-config` on IOS you need privilege 15, but you don't want a
priv-15 account doing everything. So the server uses **two accounts**:

| Account | Used for |
| --- | --- |
| **Read-only** (`CISCO_RO_*`) | Every normal tool call |
| **Privilege-15** (`CISCO_PRIV15_*`) | Only commands that need priv 15 on IOS/IOS-XE (`show running-config`, `show startup-config`, `show tech-support`, …) |

**Platform-aware:** privilege levels are an IOS/IOS-XE concept. Nexus uses RBAC —
its read-only `network-operator` role can already read the running config — so on
NX-OS devices the server **always** uses the read-only account and never escalates.

## Safety

Every command passes through a **fail-closed allowlist** (`allowlist.py`) before it
runs:

- must be a `show` command (abbreviations like `sh run` included);
- config mode, `write`/`erase`/`reload`/`copy`/`clear`/`debug`, command chaining
  (`;`, newlines), and pipe-to-write (`| redirect`, `| tee`, `| append`) are rejected.

The LLM never decides what's safe — the server enforces it mechanically, which also
contains prompt-injection arriving through arguments or command output.

## Setup

```bash
# 1. install (uv recommended)
uv sync           # or: pip install -e .

# 2. credentials
cp .env.example .env            # fill in the two accounts

# 3. inventory
cp devices.example.yaml devices.yaml   # list your switches + platform

# 4. run tests
uv run pytest
```

## Register with an MCP client

stdio transport, e.g. in a client config:

```json
{
  "mcpServers": {
    "cisco": {
      "command": "uv",
      "args": ["run", "cisco-mcp"],
      "cwd": "/path/to/cisco-mcp"
    }
  }
}
```

## Tools

- `list_devices` — inventory with platform + notes
- `get_version`, `get_interfaces`, `get_interface_status`, `get_vlans`, `get_cdp_neighbors`
- `get_running_config` — priv-15 account on IOS, read-only on NX-OS
- `run_show_command(device, command)` — any allowlisted `show`, with the same gate

## Layout

```
src/cisco_mcp/
  server.py       MCP tools (FastMCP, stdio)
  allowlist.py    safety gate + priv-15 policy   <- security core
  connection.py   account selection + Netmiko SSH
  credentials.py  two account profiles from env
  inventory.py    devices.yaml loader
  platforms.py    IOS vs NX-OS behavior
tests/            allowlist + account-selection tests (no network)
```
