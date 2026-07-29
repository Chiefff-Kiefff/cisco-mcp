# cisco-mcp

A read-only [MCP](https://modelcontextprotocol.io) server for Cisco **IOS / IOS-XE**
and **Nexus (NX-OS)** switches. It lets an LLM run `show` commands over SSH — and
nothing else.

## The two-account model

To run `show running-config` on IOS you need privilege 15, but you don't want a
priv-15 account doing everything. So the server uses **two accounts**:

| Account | Used for |
| --- | --- |
| **Read-only** (`CISCO_RO_*`) | Every tool call |
| **Privilege-15** (`CISCO_PRIV15_*`) | Only `show running-config` on IOS/IOS-XE |

The priv-15 account is scoped as tightly as possible: it fires **only** when the
command is `show running-config` (or its abbreviations `show run` / `sh run` /
`show running`) on an IOS/IOS-XE device. Everything else — including
`show startup-config`, `show tech-support`, and `show archive` — stays on the
read-only account.

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

25 tools total. Every one runs through the same allowlist + account-selection
gate; only `get_running_config` (or `run_show_command` with `show running-config`)
on an IOS/IOS-XE device escalates to the priv-15 account.

**Meta**
- `list_devices` — inventory with platform + notes
- `run_show_command(device, command)` — any allowlisted `show`, with the same gate

**System / identity**
- `get_version` — `show version`
- `get_running_config` — `show running-config` *(priv-15 on IOS/IOS-XE, read-only on NX-OS)*
- `get_inventory_hw` — `show inventory` (chassis / modules / serial numbers)
- `get_clock` — `show clock`
- `get_logs` — `show logging`

**Health / capacity**
- `get_cpu` — `show processes cpu history` (IOS/IOS-XE) / `show system resources` (NX-OS)
- `get_memory` — `show memory statistics` (IOS/IOS-XE) / `show system resources` (NX-OS)
- `get_environment` — `show environment`
- `get_poe_status` — `show power inline`

**L2 / switching**
- `get_interfaces` — `show interfaces`
- `get_interface_status` — `show ip interface brief`
- `get_vlans` — `show vlan brief`
- `get_trunks` — `show interfaces trunk`
- `get_spanning_tree` — `show spanning-tree`
- `get_etherchannels` — `show etherchannel summary` (IOS/IOS-XE) / `show port-channel summary` (NX-OS)
- `get_mac_address_table` — `show mac address-table`

**L3 / routing**
- `get_arp_table` — `show ip arp`
- `get_routing_table` — `show ip route`
- `get_ospf_neighbors` — `show ip ospf neighbor`
- `get_bgp_summary` — `show ip bgp summary`
- `get_eigrp_neighbors` — `show ip eigrp neighbors`

**Neighbor discovery**
- `get_cdp_neighbors` — `show cdp neighbors detail`
- `get_lldp_neighbors` — `show lldp neighbors detail`

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
