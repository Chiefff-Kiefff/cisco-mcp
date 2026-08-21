# cisco-mcp

A read-only [MCP](https://modelcontextprotocol.io) server for Cisco **IOS / IOS-XE**
and **Nexus (NX-OS)** switches, plus **ASA firewalls** (including Firepower
appliances running the ASA image). It lets an LLM run `show` commands over SSH —
and nothing else.

> **ASA vs FTD:** the `asa` platform covers the ASA *software image* — classic
> 5500-X boxes and Firepower 1000/2100/4100 hardware running ASA. Firepower
> Threat Defense (FTD) is a different CLI and is not supported (yet).
>
> **ASA account setup:** an SSH login on ASA lands in user EXEC (`>`) unless the
> account auto-enables. Either configure
> `aaa authorization exec LOCAL auto-enable` on the ASA (accounts land at their
> configured privilege level), or set `CISCO_RO_ENABLE_SECRET` /
> `CISCO_PRIV15_ENABLE_SECRET` so the server can `enable`. Give the read-only
> account a low privilege level (e.g. 5) with the `show` commands it needs, and
> reserve privilege 15 for the `CISCO_PRIV15_*` account.

## The two-account model

To run `show running-config` on IOS you need privilege 15, but you don't want a
priv-15 account doing everything. So the server uses **two accounts**:

| Account | Used for |
| --- | --- |
| **Read-only** (`CISCO_RO_*`) | Every tool call |
| **Privilege-15** (`CISCO_PRIV15_*`) | Only `show running-config` on IOS/IOS-XE/ASA |

The priv-15 account is scoped as tightly as possible: it fires **only** when the
command is `show running-config` (or its abbreviations `show run` / `sh run` /
`show running`) on an IOS/IOS-XE/ASA device. Everything else — including
`show startup-config`, `show tech-support`, and `show archive` — stays on the
read-only account.

**Platform-aware:** privilege levels are an IOS-family concept that ASA shares
(`show running-config` needs priv 15 on ASA too). Nexus instead uses RBAC — its
read-only `network-operator` role can already read the running config — so on
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

31 tools total. Every one runs through the same allowlist + account-selection
gate; only `get_running_config` (or `run_show_command` with `show running-config`)
on an IOS/IOS-XE/ASA device escalates to the priv-15 account. Tools dispatch the
right command variant per platform; a tool that doesn't apply to a platform
(e.g. VLANs on ASA, failover on a switch) returns a clear "not supported" error
without touching the device.

**Meta**
- `list_devices` — inventory with platform + notes
- `run_show_command(device, command)` — any allowlisted `show`, with the same gate

**System / identity**
- `get_version` — `show version`
- `get_running_config` — `show running-config` *(priv-15 on IOS/IOS-XE/ASA, read-only on NX-OS)*
- `get_inventory_hw` — `show inventory` (chassis / modules / serial numbers)
- `get_clock` — `show clock`
- `get_logs` — `show logging`

**Health / capacity**
- `get_cpu` — `show processes cpu history` (IOS/IOS-XE) / `show system resources` (NX-OS) / `show cpu usage` (ASA)
- `get_memory` — `show memory statistics` (IOS/IOS-XE) / `show system resources` (NX-OS) / `show memory` (ASA)
- `get_environment` — `show environment`
- `get_poe_status` — `show power inline` *(switches only)*

**L2 / switching**
- `get_interfaces` — `show interfaces` / `show interface` (NX-OS, ASA)
- `get_interface_status` — `show ip interface brief` / `show interface ip brief` (ASA)
- `get_vlans` — `show vlan brief` *(not ASA)*
- `get_trunks` — `show interfaces trunk` *(not ASA)*
- `get_spanning_tree` — `show spanning-tree` *(not ASA)*
- `get_etherchannels` — `show etherchannel summary` (IOS/IOS-XE) / `show port-channel summary` (NX-OS, ASA)
- `get_mac_address_table` — `show mac address-table` / `show mac-address-table` (ASA, transparent mode)

**L3 / routing**
- `get_arp_table` — `show ip arp` / `show arp` (ASA)
- `get_routing_table` — `show ip route` / `show route` (ASA)
- `get_ospf_neighbors` — `show ip ospf neighbor` / `show ospf neighbor` (ASA)
- `get_bgp_summary` — `show ip bgp summary` / `show bgp summary` (ASA)
- `get_eigrp_neighbors` — `show ip eigrp neighbors` / `show eigrp neighbors` (ASA)

**Neighbor discovery**
- `get_cdp_neighbors` — `show cdp neighbors detail` *(not ASA)*
- `get_lldp_neighbors` — `show lldp neighbors detail` *(not ASA)*

**Firewall (ASA only, except access lists)**
- `get_failover_status` — `show failover` (HA state and health)
- `get_connection_count` — `show conn count`
- `get_xlate_count` — `show xlate count` (NAT translation count)
- `get_nat` — `show nat` (NAT policies with hit counts)
- `get_vpn_sessions` — `show vpn-sessiondb` (active VPN session summary)
- `get_access_lists` — `show access-lists` / `show access-list` (ASA) — all platforms

## Layout

```
src/cisco_mcp/
  server.py       MCP tools (FastMCP, stdio)
  allowlist.py    safety gate + priv-15 policy   <- security core
  connection.py   account selection + Netmiko SSH
  credentials.py  two account profiles from env
  inventory.py    devices.yaml loader
  platforms.py    IOS vs NX-OS vs ASA behavior
tests/            allowlist + account-selection + dispatch tests (no network)
```
