# STT Discover — Self-Contained Network Discovery

**Recursive topology mapping through an SSH terminal tunnel. One command. One process. One SSH session.**

`sttsnmp.discover` is a bundled discovery engine that turns STT from a transport tool into a complete network mapping solution. It starts the SNMP proxy, connects the SSH tunnel, launches the dynamic registration API, and recursively discovers every device on the network — all from a single command.

No separate proxy process. No external SNMP tools. No pre-built port maps. No additional dependencies beyond what STT already requires.

```
$ python -m sttsnmp.discover crawl 172.16.1.2 \
    -c snmpproxy.yaml --community lab -d lab.local -o ./output

  STT Discover — crawl via jumpbox.example.com
  Seeds: 172.16.1.2
  Max depth: 10, concurrent: 20
  Community: lab

  Depth 0: 1 device
    OK    172.16.1.2       wan-core-1                     cisco      neighbors:2  [snmp] 657ms

  Depth 1: 2 devices
    OK    172.16.100.2     usa-rtr-1                      cisco      neighbors:5  [snmp] 1273ms
    OK    172.16.128.2     eng-rtr-1                      cisco      neighbors:5  [snmp] 1273ms

  Depth 2: 3 devices
    OK    172.16.1.6       usa-spine-2                    arista     neighbors:6  [snmp] 743ms
    OK    172.16.2.6       eng-spine-2                    arista     neighbors:5  [snmp] 707ms
    FAIL  172.16.2.2: No SNMP response

  Depth 3: 7 devices
    OK    172.16.10.2      usa-spine-1                    arista     neighbors:4  [snmp] 1268ms
    OK    172.16.10.23     usa-leaf-3                     cisco      neighbors:2  [snmp] 1255ms
    OK    172.16.10.22     usa-leaf-2                     cisco      neighbors:2  [snmp] 1284ms
    OK    172.16.10.21     usa-leaf-1                     cisco      neighbors:2  [snmp] 1203ms
    OK    172.16.11.43     eng-leaf-3                     cisco      neighbors:2  [snmp] 1202ms
    OK    172.16.11.42     eng-leaf-2                     cisco      neighbors:2  [snmp] 1308ms
    OK    172.16.11.41     eng-leaf-1                     cisco      neighbors:2  [snmp] 1252ms

  ============================================================
    Discovery complete
  ============================================================
    Devices:   12 discovered, 1 failed
    Duration:  10.2s
    Map:       output/map.json (12 devices)

    Proxy targets registered: 13
```

---

## How It Works

A single Python process runs three subsystems on the same async event loop:

```
┌─────────────────────────────────────────────────────────────────┐
│  python -m sttsnmp.discover crawl ...                           │
│                                                                 │
│  ┌───────────────┐  ┌──────────────┐  ┌───────────────────────┐ │
│  │  SSH Tunnel   │  │  REST API    │  │  Discovery Engine     │ │
│  │  (SSHTunnel)  │  │  :8901       │  │                       │ │
│  │               │  │              │  │  1. Register seed     │ │
│  │  SCNG client  │  │  /targets    │◄─┤  2. GET sysInfo       │ │
│  │  → jumpbox    │  │  /health     │  │  3. WALK CDP/LLDP     │ │
│  │  → stty raw   │  │              │  │  4. Register neighbors│ │
│  │  → agent      │  │  Target      │  │  5. Repeat to depth N │ │
│  │               │  │  Registry    │  │                       │ │
│  │  Framed       │  │  + Port      │  │  ProxyWalker wraps    │ │
│  │  protocol     │  │  Allocator   │  │  DirectWalker:        │ │
│  │  over PTY     │  │              │  │  walk("10.2.1.18",..) │ │
│  │               │  │  UDP Listener│  │  → walk("127.0.0.1",  │ │
│  │               │  │  Hot-Add     │  │     port=10002, ..)   │ │
│  └──────┬────────┘  └──────────────┘  └───────────────────────┘ │
│         │ SSH                                                   │
└─────────┼───────────────────────────────────────────────────────┘
          ▼
    ┌──────────┐
    │ Jumpbox  │ → snmpproxy_remote.py → UDP to real devices
    └──────────┘
```

### ProxyWalker — The Integration Seam

The key architectural piece is `ProxyWalker`. It wraps the proven `DirectWalker` (pysnmp 7.1.22) and intercepts target addresses, redirecting them through the proxy:

```python
# The CDP collector calls:
walker.walk("10.2.1.18", cdp_oid, auth)

# ProxyWalker translates to:
inner_walker.walk("127.0.0.1", cdp_oid, auth, port=10002)
```

This means the existing SNMP collectors — with their proven LLDP subtype decoding, `lldpLocPortTable` resolution, CDP binary IP parsing, management address fetching, and all the vendor-specific edge case handling — work completely unchanged through the tunnel. No reimplemented collectors. No reimplemented pysnmp. Proven code top to bottom.

### Transport Abstraction

The engine is transport-agnostic. It takes a list of `Transport` objects and tries them in order:

```python
class Transport(ABC):
    async def register(self, remote_host, remote_port) -> int  # local port
    async def get_system_info(self, target) -> DeviceInfo
    async def get_neighbors(self, target, vendor) -> list[Neighbor]
    async def health(self) -> bool
```

Currently implemented:
- **SNMPTransport** — proxy API + ProxyWalker + pysnmp collectors

Designed for (future):
- **SSHTransport** — stt-tcp API + paramiko + CLI parsing (`show cdp neighbors detail`)

The SSH fallback would activate when SNMP fails (wrong community, SNMP disabled, v3-only). The engine just calls `transport.get_neighbors()` either way — it doesn't care if the data came from SNMP walks or CLI parsing.

---

## Commands

### test — Quick SNMP Reachability Check

```bash
python -m sttsnmp.discover test 172.16.1.2 \
    -c snmpproxy.yaml --community lab
```

Connects tunnel, registers target, pulls sysName/sysDescr, exits. Proves the full pipeline works for a single device.

```
  Testing 172.16.1.2 via STT tunnel to localhost

  sysName:     wan-core-1.lab.local
  sysDescr:    Cisco IOS Software, 7200 Software (C7200-ADVENTERPRISEK9-M), Version 15.2(4)M...
  Vendor:      cisco
  sysLocation: N/A
  Uptime:      10468206

  SNMP reachable.
```

### discover — Single Device Discovery

```bash
python -m sttsnmp.discover discover 172.16.1.2 \
    -c snmpproxy.yaml --community lab -d lab.local -o ./output
```

Full collection: system info, interface table, CDP neighbors, LLDP neighbors. Shows the neighbor table so you can verify what the crawl will find.

```
  =======================================================
  wan-core-1  [OK]
  =======================================================
  IP:        172.16.1.2
  sysName:   wan-core-1.lab.local
  Vendor:    cisco
  sysDescr:  Cisco IOS Software, 7200 Software (C7200-ADVENTERPRISEK9-M)...
  Neighbors: 2
    CDP  Ethernet1/1          → usa-rtr-1.lab.local            GigabitEthernet0/0
    CDP  Ethernet1/2          → eng-rtr-1.lab.local            GigabitEthernet0/0
  Duration:  657ms

  Saved: output/wan-core-1.json
```

### crawl — Recursive Discovery

```bash
python -m sttsnmp.discover crawl 172.16.1.2 \
    -c snmpproxy.yaml --community lab \
    -d lab.local --max-depth 10 -o ./output
```

Breadth-first recursive discovery. Walks CDP/LLDP neighbor tables, registers new devices with the proxy on the fly, discovers them at the next depth level. Produces `map.json` compatible with the sc-js.app topology viewer.

**Output directory structure:**

```
output/
├── map.json                    # Topology map — load in sc-js.app viewer
├── wan-core-1/
│   └── device.json             # Per-device discovery data
├── usa-rtr-1/
│   └── device.json
├── eng-rtr-1/
│   └── device.json
├── usa-spine-2/
│   └── device.json
└── ...
```

**map.json format** (sc-js.app compatible):

```json
{
  "wan-core-1.lab.local": {
    "node_details": {
      "ip": "172.16.1.2",
      "platform": "Cisco 7200 IOS 15.2(4)M11"
    },
    "peers": {
      "usa-rtr-1.lab.local": {
        "ip": "172.16.100.2",
        "platform": "Cisco IOSv IOS 15.6(2)T",
        "connections": [["Et1/1", "Gi0/0"]]
      }
    }
  }
}
```

---

## Configuration

Only one file needed — the same YAML the proxy uses:

```yaml
# snmpproxy.yaml
ssh:
  host: jumpbox.example.com
  port: 22
  username: netops
  key_file: ~/.ssh/id_rsa
  remote_python: python3
  remote_agent: /opt/snmpproxy/snmpproxy_remote.py

bind_address: 127.0.0.1
request_timeout: 10
keepalive_interval: 30

targets:
  - local_port: 10001
    remote_host: 10.1.255.1
    remote_port: 161
    label: seed
```

The YAML defines the SSH tunnel and a single seed device. Everything else is discovered dynamically.

---

## CLI Reference

```
python -m sttsnmp.discover [-h] {test,discover,crawl} ...

Global options (work before or after subcommand):
  -c, --config CONFIG          STT proxy YAML config file (required)
  --community COMMUNITY        SNMP community string (default: public)
  -v, --verbose                Debug output
  --json                       JSON output
  -t, --timeout TIMEOUT        SNMP timeout in seconds (default: 5)
  --api-port API_PORT          Proxy API port (default: 8901)

test <target>
  Quick SNMP reachability check.

discover <target>
  Single device discovery with full collection.
  -d, --domains DOMAIN         Domain suffix for hostname stripping (repeatable)
  -o, --output-dir DIR         Save device JSON to directory

crawl <seeds...>
  Recursive neighbor-walk discovery.
  -o, --output-dir DIR         Output directory for map.json + device files
  --max-depth N                Max recursion depth (default: 10)
  --max-concurrent N           Max simultaneous discoveries (default: 20)
  -d, --domains DOMAIN         Domain suffix (repeatable)
  -x, --exclude PATTERN        Exclude pattern for sysDescr/hostname (repeatable)
```

---

## Module Structure

```
sttsnmp/discover/
├── __init__.py                 # Package version
├── __main__.py                 # CLI entry point — starts proxy + runs discovery
├── engine.py                   # Crawl orchestrator — breadth-first, concurrent, dedup
├── transport.py                # ProxyWalker + SNMPTransport + SSHTransport (stub)
├── walker.py                   # DirectWalker — pysnmp 7.1.22 bulk_cmd/get_cmd
├── models.py                   # Device, Neighbor, topology map builder
├── snmp.py                     # Collector dispatcher
├── oids.py                     # SNMP OID constants
├── parsers.py                  # Value decoders — chassis ID, port ID, strings
├── scrubber.py                 # Output sanitization — safe JSON serialization
├── collectors/
│   ├── __init__.py
│   ├── system.py               # sysName, sysDescr, vendor detection
│   ├── cdp.py                  # CDP neighbor table collection
│   ├── lldp.py                 # LLDP neighbor table + management addresses
│   ├── interfaces.py           # Interface table + extended (status, speed, MTU)
│   └── arp.py                  # ARP table (for LLDP chassis-ID → IP resolution)
└── ssh/
    ├── __init__.py
    └── client.py               # SCNG SSH client (shared with proxy)
```

### Key Design Decisions

**Self-contained.** No dependency on netaudit or any other external project. The collectors, parsers, OID definitions, and walker are all bundled. The only Python dependencies are `pysnmp==7.1.22`, `paramiko`, `pyyaml`, and `aiohttp` — all already required by the STT proxy itself.

**ProxyWalker, not reimplemented pysnmp.** The transport layer doesn't talk to pysnmp directly. It wraps `DirectWalker` (which is proven against pysnmp 7.1.22) with a port-mapping layer. The collectors call `walker.walk(target, oid, auth)` as if talking to the real device — ProxyWalker silently redirects to `127.0.0.1:{proxy_port}`.

**Collectors from Secure Cartography lineage.** The CDP and LLDP collectors are lifted from the Secure Cartography / netaudit codebase with full LLDP subtype handling, `lldpLocPortTable` resolution, management address table parsing, and binary value decoding. Not simplified versions — the complete, proven code.

**Single-process architecture.** The CLI starts the SSH tunnel, dynamic registry, REST API, and discovery engine on the same asyncio event loop. No inter-process communication, no port conflicts from separate proxy instances, clean shutdown.

**Transport abstraction for SSH fallback.** `SNMPTransport` is the working implementation. `SSHTransport` is a stub with the same interface — designed for future stt-tcp integration where SNMP-unreachable devices can be discovered via SSH + CLI parsing.

---

## Dependencies

| Package | Version | Purpose |
|---|---|---|
| pysnmp | 7.1.22 | SNMP engine (bulk_cmd, get_cmd) |
| pyasn1 | 0.6.3 | ASN.1 codec (pysnmp dependency) |
| paramiko | any | SSH client for tunnel |
| pyyaml | any | YAML config parsing |
| aiohttp | any | REST API server + HTTP client |

All are already required by the STT proxy. Zero additional dependencies.

---

## Relationship to Other STT Components

| Component | Role | Discover Uses |
|---|---|---|
| `snmpproxy_local.py` | SSH tunnel + UDP listeners + API | SSHTunnel, TargetRegistry, ProxyAPI |
| `snmpproxy_remote.py` | Remote SNMP relay agent | Unchanged — no awareness of discover |
| `snmpproxy_protocol.py` | Framed wire protocol | Unchanged — used by tunnel |
| `ssh_client.py` | SCNG SSH client | Used by SSHTunnel for connection |

The discover module imports directly from `snmpproxy_local` to start the proxy in-process. The remote agent, wire protocol, and SSH client are completely unaware that discover exists.

---

## Future: SSH Fallback via stt-tcp

The `SSHTransport` stub in `transport.py` outlines the SSH fallback path:

1. When SNMP fails for a device (timeout, wrong community, disabled)
2. Engine tries the next transport in the list — `SSHTransport`
3. SSHTransport registers `target:22` with stt-tcp's dynamic API (when built)
4. Connects to `localhost:{tcp_port}` via paramiko
5. Runs vendor-specific show commands:
   - Cisco: `show cdp neighbors detail`, `show lldp neighbors detail`
   - Arista: same commands (EOS CLI compatibility)
   - Juniper: `show lldp neighbors`, `show chassis hardware`
6. Parses CLI output into the same `DeviceInfo` and `Neighbor` objects
7. Engine continues crawling — doesn't care which transport found the data

This would give full SNMP + SSH hybrid discovery through two terminal tunnels (stt-snmp + stt-tcp) from a single jumpbox.

---

## License

MIT — Same as the parent Secure Terminal Transport project.