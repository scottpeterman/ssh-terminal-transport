# SSH Terminal Transport (STT)

A general-purpose application relay protocol that runs structured, multiplexed, asynchronous messages over interactive SSH terminal sessions. The protocol is payload-agnostic — it carries bytes, not any specific application protocol. The terminal's inherent chaos (echo, ANSI escapes, prompts, line discipline) is treated as noise to filter, not a problem to avoid.

**stt-snmp** is the first implementation: a transparent SNMP proxy that lets any standard SNMP tool — `snmpwalk`, `snmpget`, LibreNMS, Cacti, trafikwatch — reach devices on remote networks through an SSH session. No listening ports on the remote side. No root. No daemons. No firewall changes. No change control window.


![stt-snmp trace](../screenshots/snmp-trace.png)

```
Arista EOS:
  snmpget -v2c -c lab localhost:10001 sysDescr.0
  → "Arista Networks EOS version 4.x running on an Arista vEOS-lab"
  → Sub 15ms RTT through SSH terminal tunnel

Juniper JUNOS:
  snmpget -v2c -c lab localhost:10006 sysDescr.0
  → "Juniper Networks, Inc. vmx internet router, kernel JUNOS 14.x"
  → Confirmed working through same tunnel session
```

Multiple devices across vendors, one SSH session, full SNMP reachability. The SNMP tools have no awareness of the tunnel — they see normal UDP responses from localhost.

```
SC-JS network discovery (multi-vendor lab fabric):
  → Multiple devices discovered: Arista (spines), Cisco (routers, leafs, WAN core)
  → LLDP + CDP + ARP table walks across all devices
  → Layer-2 connections mapped, full topology built
  → < 10s total discovery time, zero failures
  → All SNMP traffic tunneled through a single SSH session
```

```
SC-JS multi-vendor discovery:
  → Dozens of devices discovered: Juniper, Arista, Cisco
  → Thousands of SNMP requests, 0 tunnel errors
  → Equipment spanning 10+ year old Junos to current EOS
  → All traffic through a single SSH invoke-shell session
```

Full three-tier leaf-spine fabric across multiple sites, WAN core at the top, discovered from a single seed address. The discovery tool walks LLDP neighbor tables, CDP tables, ARP tables, interface tables, and system MIBs — hundreds of concurrent SNMP requests multiplexed through the tunnel. The tool has no awareness of STT. It sees localhost UDP endpoints.

## The insight

SSH tunnels don't support UDP. That's where every previous attempt to solve this problem dead-ends. The standard workarounds — `socat` chains, named pipes with `netcat`, TCP-to-UDP converters — all require listening ports on the remote side, one tunnel per target, fragile multi-process plumbing, and tool installation on the jumpbox.

STT sidesteps the entire problem. Instead of tunneling a *transport protocol* (UDP-over-TCP-over-SSH), it tunnels *messages*. The SSH terminal session is a bidirectional text stream. The protocol wraps application payloads in base64, frames them with sentinels, and sends them as text lines. The remote agent decodes the payload, performs the actual network operation (UDP sendto, TCP connect, DNS query, whatever), and sends the response back the same way.

The terminal is not a limitation to work around. It is the transport layer.

## How it works

```
┌─ Your machine ─────────────────────┐     ┌─ Jumpbox ──────────────────────────┐
│                                    │     │                                    │
│  Any SNMP tool                     │     │  snmpproxy_remote.py               │
│    │  UDP to localhost:10001       │     │    │  raw UDP to real device       │
│    ▼                               │     │    ▼                               │
│  snmpproxy_local.py                │     │  172.17.1.128:161  (spine1)        │
│    │  Framed text protocol         │     │  172.17.1.1:161    (spine2)        │
│    │  over invoke-shell            │     │  172.17.1.131:161  (peer1-02)      │
│    ▼                               │     │  172.17.1.24:161   (edge-leaf01)   │
│  SCNG SSH Client ──── SSH ─────────┼─────┼──► stdin/stdout of agent           │
│  (legacy cipher/KEX support)       │     │  ...and more                       │
└────────────────────────────────────┘     └────────────────────────────────────┘
```

### Minimal Requirements

```
pip install paramiko pyyaml aiohttp pysnmp==7.1.22
```

`aiohttp` is only required for dynamic mode (`--api`). `pysnmp` is only required for the bundled discover module. The static proxy needs only `paramiko` and `pyyaml`.

### Data flow for a single request

```
snmpwalk sends UDP to localhost:10001
  → SNMPListener captures raw SNMP PDU (binary bytes)
  → Base64-encode the PDU
  → Wrap in framed message:
      ~##~REQ|000042|172.17.1.128:161|MCYCAQEEBmxhYqAcAgQ...~##~
  → Enqueue through ChannelWriter (serialized, no interleaving)
  → ChannelWriter coalesces queued frames, single sendall()
  → (SSH encryption, network transit)
  → Remote agent's FrameReader extracts message
  → Base64-decode → raw PDU bytes
  → socket.sendto(172.17.1.128, 161, pdu_bytes)
  → Real SNMP agent on the Arista responds
  → Remote agent base64-encodes response
  → Batch-writes RSP frames via write_batch() (single stdout flush)
  → (SSH transit back)
  → Local reader thread → FrameReader → resolve async Future
  → SNMPListener sends raw UDP response to snmpwalk
  → snmpwalk prints: "Arista Networks EOS version 4.x..."
```

The SNMP tool never knows. The remote agent never parses SNMP. The protocol never inspects the payload. It's just bytes in, bytes out.

### Port-mapped routing

SNMP requests to localhost carry no information about the intended target. Routing is handled by port mapping — each remote device gets a unique local UDP port:

```
localhost:10001  →  172.17.1.128:161  (spine1)
localhost:10002  →  172.17.1.1:161    (spine2)
localhost:10003  →  172.17.1.131:161  (peer1-02)
localhost:10004  →  172.17.1.24:161   (edge-leaf01)
localhost:10005  →  172.17.1.18:161   (edge-leaf03)
localhost:10006  →  172.17.1.12:161   (edge-leaf1-01)
localhost:10007  →  172.17.1.16:161   (edge-leaf1-02)
```

In dynamic mode (`--api`), this map builds itself at runtime as targets are registered through the REST API.

### Boot sequence

```
1. SCNG SSHClient.connect()
   │  Handles: legacy ciphers/KEX, key loading, invoke-shell,
   │  banner drain, ANSI filtering
   │
2. SSHClient.find_prompt()
   │  Confirms shell is ready. Extracts jumpbox hostname.
   │
3. Combined: stty raw -echo + exec agent + stderr redirect
   │  Single shell command:
   │    "stty raw -echo; exec python3 -u agent.py 2>/tmp/snmpproxy_agent.log"
   │  Bash parses the full line in cooked mode, sets raw mode
   │  with echo disabled, then exec replaces bash with the agent.
   │  stderr redirect keeps agent logs off the PTY.
   │  -u = unbuffered stdout (critical).
   │  Log path configurable via remote_log in YAML.
   │
4. Send: ~##~PING~##~
   │  FrameReader processes all output.
   │  With echo disabled and stderr redirected, boot noise is minimal.
   │
5. Receive: ~##~PONG~##~
   │  Handshake complete. Agent owns the channel.
   │
6. Start ChannelWriter + reader thread
   │  Writer serializes all channel writes (prevents frame interleaving).
   │  Reader thread feeds SSH output through FrameReader.
   │
7. UDP listeners start on localhost
   │  One per target mapping. Any SNMP tool can query immediately.
   │
8. Keepalive loop
   Periodic PING/PONG detects dead tunnels.
```

## Operating modes

### Static mode (original)

All targets defined in YAML. No API, no aiohttp dependency:

```bash
python -m sttsnmp.snmpproxy_local -c snmpproxy.yaml
```

### Dynamic mode

REST API for runtime target registration. Enables recursive discovery without pre-built port maps:

```bash
python -m sttsnmp.snmpproxy_local -c snmpproxy.yaml --api
```

YAML targets are loaded as seeds. New targets are registered via `POST /targets` and get auto-allocated ports. See **API Reference** below.

### Bundled discovery

The `sttsnmp.discover` module bundles a complete recursive discovery engine. One command starts the tunnel, API, and crawl:

```bash
python -m sttsnmp.discover crawl 10.255.255.1 \
    -c snmpproxy.yaml --community public \
    --max-depth 10 -d example.com -o ./output
```

Single process, single SSH session. See [STT Discover README](README_Discover.md) for full documentation.

## Security posture

The security model is inherent to the design, not bolted on. The constraints of the approach *are* the security guarantees.

**No listening ports on the remote network.** The remote agent reads from stdin and writes to stdout. It opens outbound UDP sockets to SNMP devices — the same thing any `snmpwalk` on the jumpbox would do. There is nothing to connect to, nothing to scan, nothing to exploit.

**No root or elevated privileges.** Both sides run as your normal user. Local listeners bind to `127.0.0.1` on high ports (10000+). The remote agent uses standard unprivileged UDP sockets.

**No daemon, no service, no install.** The remote side is two Python files with zero external dependencies (Python 3.7+ stdlib only). Copy them to the jumpbox, run them over SSH, delete them when you're done. Nothing persists.

**No attack surface expansion.** The tunnel rides your existing SSH session. No new ports, no new protocols, no new authentication mechanisms. If your SSH access gets revoked, the proxy stops working — exactly as it should.

**Loopback only by default.** Local listeners bind to `127.0.0.1`. Only tools on your machine can use them. Nothing is exposed to your local network unless you explicitly change `bind_address`. The dynamic API also binds to `127.0.0.1`.

**No credentials in transit.** SNMP community strings travel inside the PDU bytes, which travel inside base64, which travels inside SSH encryption. The proxy never inspects, logs, or stores credentials.

## Wire protocol specification

### Framing

All messages are wrapped in sentinel pairs and terminated with a newline:

```
~##~{message_content}~##~\n
```

The sentinel `~##~` was chosen because it cannot appear in:

- Base64 output (uses `A-Za-z0-9+/=` only)
- ANSI escape sequences (use `\x1b[...`)
- Standard shell prompts
- SNMP community strings or OID notation

The `FrameReader` state machine processes a raw byte stream and extracts only the content between sentinel pairs. Everything outside the sentinels — terminal echo, shell prompts, ANSI sequences, Python warnings, blank lines, carriage returns — is silently discarded. This is what makes the protocol work over an interactive terminal session where no other framing mechanism would survive.

### Message types

```
Request (local → remote):
  ~##~REQ|{msg_id}|{host}:{port}|{base64_pdu}~##~

Response — success (remote → local):
  ~##~RSP|{msg_id}|OK|{base64_response}~##~

Response — error (remote → local):
  ~##~RSP|{msg_id}|ERR|{error_text}~##~

Response — timeout (remote → local):
  ~##~RSP|{msg_id}|TIMEOUT|~##~

Keepalive:
  ~##~PING~##~
  ~##~PONG~##~

Shutdown:
  ~##~QUIT~##~
```

### Message ID

The `msg_id` is a zero-padded 6-digit counter (`000001`, `000002`, ...) generated by the local side. It correlates requests with responses for concurrent/async operation. The remote agent echoes it back unchanged.

### FrameReader behavior

The `FrameReader` class handles all edge cases:

- **Noise between frames:** Silently discarded.
- **Frames split across reads:** Accumulated until end sentinel arrives.
- **Multiple frames in one read:** All extracted and returned.
- **Sentinels split across read boundaries:** The reader retains the last 3 characters (SENTINEL_LEN - 1) in its buffer between `feed()` calls. If a 4-byte sentinel `~##~` lands on a `recv()` boundary as `~#` | `#~`, the first half is preserved and completes when the next chunk arrives. Without this, split sentinels are discarded as noise and the frame is irrecoverably lost — a ~0.1% probability per frame that compounds over hundreds of table walk responses.
- **Overflow protection:** Frames exceeding 100KB are discarded (corrupt state recovery).

## Why text-based? Why not binary framing?

The transport is an interactive SSH shell session. This channel has properties that make binary protocols fragile:

**Terminal echo.** The shell echoes back everything you send. A binary length-prefix header echoed back corrupts the next message boundary. (STT disables echo with `stty raw -echo` — see Taming the PTY — but text-based framing survives even if echo suppression fails on exotic systems.)

**Line discipline.** The terminal may translate `\r\n`, strip high bytes, or inject control characters depending on `TERM` settings.

**ANSI injection.** The shell prompt, `stty` settings, and Python's readline can inject escape sequences into the stream at any time.

**Character encoding.** The channel may apply UTF-8 encoding, translating byte sequences that corrupt binary data.

The text-based approach sidesteps all of this. Base64 survives any encoding. Sentinels are unambiguous. The FrameReader treats everything outside frames as invisible. And the protocol is human-readable — you can watch it in `--trace` mode and see exactly what's happening.

The overhead of base64 (~33% size increase) is irrelevant for SNMP PDUs, which are typically a few hundred bytes.

## Why invoke-shell instead of exec?

`exec_command` gives you clean stdin/stdout with no terminal emulation. But:

**Not all SSH implementations support exec.** Many network devices, old Linux boxes, and hardened bastions only allow interactive shell access.

**Bastion traversal.** The SCNG SSH client is built for invoke-shell sessions — multi-hop chains, legacy devices, prompt detection. Using exec would bypass the entire toolkit.

**Operational consistency.** If you can SSH to the jumpbox and type commands, STT works. No surprises about channel types or subsystem support.

The framed protocol makes invoke-shell just as reliable as exec. The FrameReader gives you the clean message stream that exec would have given you natively.

## Taming the PTY

An interactive SSH shell session is a pseudo-terminal (PTY). By default, the PTY does things that are helpful for humans and catastrophic for a data protocol. Three problems required three fixes, discovered through progressive debugging against real networks.

**Echo.** The PTY echoes everything sent through the channel back to the channel output. Send `~##~REQ|000042|...~##~` and the echo comes back as channel output. The FrameReader sees the echoed sentinel `~##~` and interprets it as the end marker of whatever frame is currently being accumulated — truncating the real RSP frame in progress. Corrupted base64, response dropped, device missing from the map. Under light load the timing rarely collides. Under table walks with rapid GetNext bursts, it's almost guaranteed.

*Fix:* `stty raw -echo` before launching the agent. `-echo` eliminates the echo. `raw` disables canonical mode (which imposes a 4096-byte input buffer limit that can truncate large frames), disables OPOST `\n` → `\r\n` output translation, and disables signal character processing. The `stty` command and the agent launch must be a single shell command (`stty raw -echo; exec python3 -u agent.py 2>/tmp/snmpproxy_agent.log`) — if sent separately, bash is already in raw mode when it tries to read the second command, and line discipline is off so `\n` doesn't terminate input.

**Stderr contamination.** In a PTY, stderr and stdout share the same output path through the pty master into the SSH channel. The remote agent's `log()` calls write to stderr, which injects unframed text into the protocol stream. Between frames, the FrameReader discards it as noise. But if a log line arrives *during* a large RSP write — while the kernel is mid-`write()` of the base64 payload — the stderr bytes get spliced into the frame content. Corrupted base64, response lost. The longer the session runs, the more log lines, the more chances for mid-frame collision. This manifests as progressive data loss that worsens over time.

*Fix:* Redirect stderr on the agent launch command. The default redirect path is `/tmp/snmpproxy_agent.log` (configurable via `remote_log` in YAML), so agent logs are preserved for debugging via a separate SSH session. To eliminate log noise entirely, set `remote_log: /dev/null`. The channel carries only framed protocol output.

**Python readline buffering.** Even with `stty raw`, Python's `sys.stdin.readline()` has its own internal buffer that waits for `\n`. Under raw mode, the kernel line discipline no longer treats `\n` as a line terminator for buffering purposes — but Python's readline doesn't know that. It blocks waiting for a character that may never arrive as a line break in the way readline expects.

*Fix:* `os.read(stdin_fd, 32768)` in the remote agent instead of `sys.stdin.readline()`. Returns whatever bytes the kernel has available — could be one frame, could be ten coalesced frames from the ChannelWriter. The FrameReader handles partial frames — it doesn't need line-oriented input.

## Concurrency model

### Local side — write serialization (ChannelWriter)

The `asyncio` event loop handles all UDP listeners concurrently. Multiple SNMP tools can query different ports simultaneously. Each request gets a unique `msg_id` and an `asyncio.Future` that resolves when the correlated response arrives.

The critical concurrency challenge is write serialization. Multiple concurrent asyncio coroutines calling `channel.sendall()` can interleave frames on the wire — paramiko's channel write isn't atomic for multi-byte payloads. Two REQ frames sent concurrently can fragment into SSH packets that interleave, and the remote FrameReader sees a sentinel in the middle of another frame, corrupting both.

The `ChannelWriter` solves this with a single drain loop that owns all channel writes:

1. Callers enqueue framed messages via `await writer.send(frame)` — non-blocking.
2. The drain loop wakes, collects everything queued, coalesces small frames into batches (up to 16KB, staying under SSH's 32KB max packet).
3. A single `sendall()` call writes the batch atomically — runs in executor to avoid blocking the event loop.

This guarantees frames never interleave, small frames coalesce into fewer SSH packets for better throughput, and blocking I/O never stalls asyncio. The writer exposes metrics (queue depth, high water mark, coalesced frame count, bytes written) through the `/health` endpoint for diagnosing throughput issues.

The ChannelWriter is **not** used during the handshake phase (connect/PING/PONG) — the event loop isn't running yet, and handshake writes are single-threaded. It activates when `start_reader()` is called.

### SSH I/O — reader thread

A dedicated reader thread reads from the SSH channel (32KB recv to match SSH max packet) and feeds the `FrameReader`. Responses dispatch to the correct Future via `call_soon_threadsafe`. This hybrid avoids blocking asyncio on SSH reads.

### Remote side — batch writes and os.read

`select()`-based multiplexing on stdin + UDP socket. Requests dispatch immediately. Responses return asynchronously — the agent doesn't block waiting for device replies.

The remote side has its own write coalescing via `write_batch()`. When `poll_responses()` drains multiple UDP responses in one cycle, it collects all RSP frames and writes them in a single `stdout.write()` + `flush()`, reducing pty buffer round-trips and SSH packet fragmentation. Under load with 20+ concurrent requests, this can coalesce 10+ RSP frames into one stdout write.

The stdin reader uses `os.read(stdin_fd, 32768)` — not `readline()`. This grabs the entire contents of the pty buffer in one shot, including any frames the ChannelWriter coalesced on the local side. Using `readline()` would peel off one frame per select cycle, starving UDP response processing between each.

### Response correlation

The remote agent extracts the SNMP request-id from each PDU's BER/ASN.1 header (pure stdlib, no SNMP library) and matches UDP responses by `(target_address, snmp_request_id)`. This is critical for table walks — an `snmpwalk` fires rapid GetNext requests to the same device, creating multiple pending requests to the same `(host, port)`. Without request-id correlation, responses cross-wire and walks hang or return garbled data. Falls back to address-only matching for PDUs where request-id extraction fails, maintaining compatibility with non-SNMP payloads.

### Stale state cleanup

When the remote agent receives a PING (keepalive or handshake), it flushes all pending requests. Any entries that pre-date a PING are stale — the local side is either doing keepalive or re-handshaking after a crash. Either way, those requests will never be resolved on the local side. The flush prevents zombie entries from accumulating.

### Timeout handling — three layers

1. **Remote agent:** UDP socket timeout per device (5s default, 1 retry = 10s total). Sends `RSP|{id}|TIMEOUT|` if no response.
2. **Local tunnel:** Per-request asyncio timeout (10s default). Must exceed the remote total with margin for SSH round-trip — if both are equal, the local timeout fires before the remote TIMEOUT response arrives, producing orphaned responses.
3. **SNMP tool:** The calling tool's own timeout (tool-specific). Fires if the entire proxy stalls.

If the device doesn't respond, the remote agent reports TIMEOUT. If the tunnel stalls, the local timeout fires. If both fail, the SNMP tool sees "no response" — identical to a direct SNMP timeout.

## Remote agent hardening

The remote agent runs on the jumpbox with no direct visibility from the operator. When it fails, you see timeouts on the local side with no indication of why. The hardened agent is built to survive errors, report what's happening, and never silently corrupt state.

**SNMP request-id extraction.** The agent parses the BER-encoded request-id from each PDU using ~40 lines of ASN.1 tag-length-value walking. No external libraries — pure Python stdlib. Handles GetRequest (0xA0), GetNextRequest (0xA1), GetBulkRequest (0xA5), and all SNMPv1/v2c PDU types. Malformed PDUs return `None` and fall back to address-only matching. The parser is defensive — it never raises on bad input.

**Periodic stats to stderr.** Every 60 seconds the agent dumps a one-line stats summary:

```
[snmpproxy] STATS  uptime=00:05:00  req=347  ok=340  timeout=7  err=0
            retry=3  rid_match=338  rid_fallback=2  bad_frame=0  bad_pdu=0
            dropped=0  flushed=12
```

In normal operation, stderr is redirected to the agent log file (default `/tmp/snmpproxy_agent.log`, configurable via `remote_log`). Read the log via a separate SSH session. The `rid_match` vs `rid_fallback` counters tell you whether request-id correlation is working or falling back to address-only matching.

**Exception armor.** Every code path that touches external I/O — stdin reads, UDP sends, frame parsing, response matching — is wrapped in try/except. Individual message handler failures are logged and skipped without killing the agent. The main loop continues through transient errors.

**Pending request cap.** Maximum 500 in-flight requests (configurable). If the local side floods requests faster than devices respond, excess requests are rejected with an immediate error response rather than accumulating unbounded memory.

**Stdin watchdog.** If no data arrives on stdin for 120 seconds (no requests, no keepalive PINGs), the agent logs a warning. Doesn't self-terminate — the situation may be transient — but provides visibility that the tunnel may be dead.

**PDU validation.** Rejects PDUs smaller than 10 bytes with an immediate error response. Prevents sending garbage to devices and waiting 5+ seconds for a timeout that was always going to happen.

## API reference (dynamic mode)

All endpoints bind to `127.0.0.1:{api_port}` (default 8901). Localhost only.

### POST /targets

Register a new SNMP target. Idempotent — returns the existing mapping if the target is already registered.

**Request:**
```json
{
  "remote_host": "10.2.1.42",
  "remote_port": 161,
  "label": "spine-1"
}
```

Only `remote_host` is required. `remote_port` defaults to 161.

**Response:**
```json
{
  "local_port": 10002,
  "remote_host": "10.2.1.42",
  "remote_port": 161,
  "label": "spine-1",
  "source": "api",
  "request_count": 0
}
```

**Status codes:**
- `201 Created` — new target registered, UDP listener started
- `200 OK` — target already existed, returned existing mapping
- `400` — missing `remote_host`
- `503` — port pool exhausted (max 2000 targets)

### GET /targets

List all registered targets. Optional query parameter `source` to filter by `config` (YAML seeds) or `api` (dynamically registered).

### GET /targets/{host}

Lookup a specific target by remote IP. Optional query parameter `port` (default 161).

### DELETE /targets/{host}

Remove a target and close its UDP listener.

### GET /health

Tunnel and proxy health check, including ChannelWriter metrics:

```json
{
  "status": "ok",
  "tunnel_active": true,
  "target_count": 42,
  "writer": {
    "queue_depth": 0,
    "high_water_mark": 12,
    "frames_queued": 4820,
    "frames_written": 4820,
    "batches_written": 3100,
    "bytes_written": 286400,
    "coalesced_frames": 1720
  }
}
```

### Port allocation

- YAML seed targets keep their explicitly configured port numbers
- API-registered targets get auto-allocated ports starting from `--base-port` (default 10001)
- The allocator automatically skips any ports already claimed by YAML seeds
- Same remote target registered twice returns the existing port (idempotent)
- Maximum 2000 concurrent targets (configurable)

### Idle target reaper

A background task runs every 5 minutes and removes API-registered targets that haven't seen SNMP traffic in 1 hour. YAML seed targets are never reaped. This prevents port exhaustion during long-running proxy sessions with multiple discovery runs.

## Deployment

### Prerequisites

**Local machine:**
- Python 3.9+
- `paramiko` and `pyyaml` (static mode minimum)
- `aiohttp` (required for `--api` dynamic mode)
- `pysnmp==7.1.22` (required for bundled discover module)
- SCNG SSH Client (included as `ssh_client.py`)

**Jumpbox:**
- Python 3.7+ (stdlib only — no pip packages needed)
- UDP access to target SNMP devices

### One-time setup on the jumpbox

```bash
ssh jumpbox "mkdir -p /opt/snmpproxy"
scp snmpproxy_protocol.py snmpproxy_remote.py jumpbox:/opt/snmpproxy/
```

That's it. No install, no virtualenv, no pip, no service file.

### Project layout

```
stt/
├── .venv/
└── sttsnmp/
    ├── __init__.py
    ├── README.md                    # This file
    ├── README_Discover.md           # Discover module documentation
    ├── snmpproxy_local.py           # Local proxy — UDP listeners + SSH tunnel + API
    ├── snmpproxy_remote.py          # Remote agent — stdin/stdout + UDP relay
    ├── snmpproxy_protocol.py        # Shared protocol — framing + FrameReader
    ├── ssh_client.py                # SCNG SSH client
    ├── snmpproxy.yaml               # Port mappings + SSH config
    ├── stt-gen.js                   # Node.js STT client for sc-js integration
    │
    └── discover/                    # Bundled discovery engine
        ├── __init__.py
        ├── __main__.py              # CLI entry point
        ├── engine.py                # Crawl orchestrator
        ├── transport.py             # ProxyWalker + SNMPTransport
        ├── walker.py                # DirectWalker — pysnmp 7.1.22
        ├── models.py                # Device, Neighbor, topology map builder
        ├── snmp.py                  # Collector dispatcher
        ├── oids.py                  # SNMP OID constants
        ├── parsers.py               # Value decoders
        ├── scrubber.py              # Output sanitization
        ├── collectors/
        │   ├── system.py            # sysName, sysDescr, vendor detection
        │   ├── cdp.py               # CDP neighbor table
        │   ├── lldp.py              # LLDP neighbor table + mgmt addresses
        │   ├── interfaces.py        # Interface table
        │   └── arp.py               # ARP table (chassis-ID → IP resolution)
        └── ssh/
            ├── __init__.py
            └── client.py            # SCNG SSH client (discover copy)
```

### Device configuration

Arista EOS — minimal SNMP:
```
snmp-server community lab ro
```

Juniper JUNOS — minimal SNMP:
```
set snmp community lab authorization read-only
```

### Cleanup

```bash
ssh jumpbox "rm -rf /opt/snmpproxy"
```

Nothing else to undo. No services, no firewall rules, no cron jobs.

## Configuration reference

```yaml
ssh:
  host: jump.dc2.example.com       # Jumpbox hostname or IP (required)
  port: 22                          # SSH port
  username: user                    # SSH username (defaults to $USER)
  password: ""                      # Password auth (optional)
  key_file: ~/.ssh/id_rsa           # Private key path (optional)
  key_content: ""                   # PEM key string in-memory (optional)
  legacy_mode: false                # Legacy ciphers/KEX for old gear
  connect_timeout: 30               # SSH connection timeout (seconds)
  shell_timeout: 5.0                # Shell init timeout (seconds)

  # Remote agent execution
  # Actual command: stty raw -echo; exec {remote_python} -u {remote_agent} 2>{remote_log}
  remote_python: python3            # Python path on jumpbox
  remote_agent: /opt/snmpproxy/snmpproxy_remote.py
  remote_log: ""                    # Agent log path on jumpbox
                                    # Default (empty): /tmp/snmpproxy_agent.log
                                    # Set to /dev/null to suppress logs

# Local listener settings
bind_address: 127.0.0.1             # Loopback only (default)
request_timeout: 10                 # Per-request timeout (seconds)
keepalive_interval: 30              # Tunnel keepalive (seconds)

# Port-mapped targets
targets:
  - local_port: 10001
    remote_host: 172.17.1.128
    remote_port: 161
    label: spine1
```

### Authentication

| Method | Config fields |
|---|---|
| Password | `password` |
| Key file | `key_file` (+ optional `password` for passphrase) |
| In-memory key | `key_content` (PEM string) |

At least one of `password`, `key_file`, or `key_content` is required.

### Legacy mode

`legacy_mode: true` enables SCNG client legacy algorithm support for old SSH implementations:

- KEX: `diffie-hellman-group1-sha1`, `diffie-hellman-group14-sha1`
- Ciphers: `aes128-cbc`, `aes256-cbc`, `3des-cbc`
- Host keys: `ssh-rsa`, `ssh-dss`

## Usage

### Start the proxy (static mode)

```bash
python -m sttsnmp.snmpproxy_local -c sttsnmp/snmpproxy.yaml
```

Output:
```
  snmpproxy — 7 targets via localhost

    127.0.0.1:10001  → 172.17.1.128:161       spine1
    127.0.0.1:10002  → 172.17.1.1:161         spine2
    127.0.0.1:10003  → 172.17.1.131:161       peer1-02
    ...

  Ready. Use any SNMP tool against localhost.
```

### Start the proxy (dynamic mode)

```bash
python -m sttsnmp.snmpproxy_local -c sttsnmp/snmpproxy.yaml --api

# Custom API port, custom base port for auto-allocation
python -m sttsnmp.snmpproxy_local -c sttsnmp/snmpproxy.yaml --api --api-port 9000 --base-port 20001
```

Output:
```
  snmpproxy — dynamic mode via jumpbox.example.com
  Seed targets: 1

    127.0.0.1:10001  → 10.255.255.1:161       seed  [seed]

  API:   http://127.0.0.1:8901/targets
  Ready. Register new targets dynamically.
```

### Query devices

```bash
# Arista
snmpget -v2c -c lab localhost:10001 1.3.6.1.2.1.1.1.0
# → "Arista Networks EOS version 4.x running on an Arista vEOS-lab"

# Juniper
snmpget -v2c -c lab localhost:10006 1.3.6.1.2.1.1.1.0
# → "Juniper Networks, Inc. vmx internet router, kernel JUNOS 14.x"

# Walk a full table
snmpwalk -v2c -c lab localhost:10001 1.3.6.1.2.1.31.1.1.1.1

# Dynamic: register + query
PORT=$(curl -s -X POST http://127.0.0.1:8901/targets \
       -H 'Content-Type: application/json' \
       -d '{"remote_host":"10.2.1.42"}' | jq .local_port)
snmpwalk -v2c -c public localhost:$PORT 1.3.6.1.2.1.1
```

### Trace mode

```bash
python -m sttsnmp.snmpproxy_local -c sttsnmp/snmpproxy.yaml --trace
```

Shows every protocol message with round-trip timing:

```
02:53:56.708 snmpproxy.trace  INFO    TX  ~##~REQ|000001|172.17.1.128:161|MCYCAQEEA2xhYqAc...~##~
02:53:56.719 snmpproxy.trace  INFO    RX  000001 OK 105B  rtt=11ms
02:53:56.720 snmpproxy.trace  INFO    UDP :10001 spine1  40B → 105B  13ms
```

### All modes

```bash
# Normal — status and errors only
python -m sttsnmp.snmpproxy_local -c sttsnmp/snmpproxy.yaml

# Dynamic — with REST API
python -m sttsnmp.snmpproxy_local -c sttsnmp/snmpproxy.yaml --api

# Trace — protocol messages + RTT timing
python -m sttsnmp.snmpproxy_local -c sttsnmp/snmpproxy.yaml --trace

# Verbose — everything (trace + debug + noise discards + paramiko)
python -m sttsnmp.snmpproxy_local -c sttsnmp/snmpproxy.yaml --verbose

# Quiet — errors only
python -m sttsnmp.snmpproxy_local -c sttsnmp/snmpproxy.yaml --quiet
```

## Prior art and how STT differs

The problem of tunneling SNMP over SSH has been discussed for over a decade. The common approaches:

**netcat + named pipes + SSH port forward.** Create a fifo, run `nc` listening on TCP, pipe through SSH, run `nc` on the remote converting TCP back to UDP. Requires listening ports on both sides, one tunnel per target, fragile multi-process plumbing, and falls apart when any piece silently dies.

**socat TCP-to-UDP.** `socat tcp4-listen:10000,fork UDP:target:161` on the remote, SSH port forward for TCP, another socat locally. Same problems: listening ports, one target per tunnel, requires socat installed on the jumpbox.

**RFC 5592 — SNMP over SSH subsystem.** A formal standard defining SNMP transport over SSH channels. Requires SSH subsystem support on both ends, changes to the SNMP engine, and purpose-built agents. Practically nobody implements it.

**What STT does differently:**

| | netcat/socat | RFC 5592 | STT |
|---|---|---|---|
| Remote listening ports | Yes | Yes | **None** |
| Targets per tunnel | 1 | N/A | **Unlimited** |
| Remote dependencies | socat/netcat | SSH subsystem | **Python stdlib** |
| Root required | Often | Usually | **Never** |
| Install on jumpbox | Tools | Subsystem | **Two files, no install** |
| Protocol awareness | None | SNMP-specific | **Payload-agnostic** |
| Terminal-safe | No | N/A | **By design** |
| Async multiplexing | No | N/A | **msg_id correlation** |
| Debuggable | tcpdump | snmpd logs | **Human-readable trace** |
| Dynamic targets | No | N/A | **REST API + auto-port** |

## Beyond SNMP

The protocol is payload-agnostic. The framed message carries bytes. The remote agent's job is: receive bytes, perform a network operation, return bytes. Swap the network operation and you have a different application with the same transport.

**stt-dns:** Remote agent sends decoded payload to a DNS resolver via UDP:53 instead of SNMP:161. Local side listens on a UDP port as a DNS stub resolver. Query internal DNS zones behind a bastion.

**stt-http:** Remote agent opens a TCP connection, sends the decoded payload as an HTTP request, returns the response. Access REST APIs on isolated management networks.

**stt-voice:** Push-to-talk voice over SSH. Record locally, Opus-compress, base64 the clip, send as one framed message. No jitter problem — it's a complete message, not a stream. A 5-second clip at Opus 6kbps is ~5KB base64. Secure voice comms with zero additional infrastructure.

The sentinel framing, message ID correlation, FrameReader state machine, and noise immunity don't change. The `snmpproxy_protocol.py` module is already application-agnostic — it's the STT protocol layer. The application-specific part is only the remote agent and the local listener type.

## Limitations (current scope)

**SNMPv2c tested.** The proxy is version-agnostic at the PDU level (raw bytes), but hasn't been tested with SNMPv3 engine-level context. Community strings and v3 credentials travel inside the PDU transparently. The request-id extractor handles all SNMPv1/v2c PDU types; SNMPv3 PDUs with different BER structure will fall back to address-only matching.

**Single jumpbox.** One SSH connection to one jumpbox per proxy instance. Multiple remote networks need multiple instances or a config extension.

**No reconnection.** If the SSH session drops, the proxy exits. A future version should add automatic reconnection with backoff.

**No SNMP trap forwarding.** Request/response only. Traps are unsolicited — they'd need a listener on the remote side, conflicting with the zero-footprint design.

**Sequential stdin on remote.** The agent reads stdin via `os.read()` — not `readline()`. Under extreme concurrent load this could bottleneck. Tested with multi-vendor discovery across dozens of devices (thousands of concurrent table walk requests) with no observable bottleneck.

## File inventory

```
sttsnmp/
├── snmpproxy_local.py        Local proxy — UDP listeners + SSH tunnel + API
│                              SCNG SSH client for connection
│                              stty raw -echo + exec + stderr redirect
│                              ChannelWriter (serialized, coalescing writes)
│                              TargetRegistry + REST API (dynamic mode)
│                              asyncio + reader thread
│                              --trace mode with RTT timing
│                              ~1350 lines
│
├── snmpproxy_remote.py       Remote agent — stdin/stdout + UDP relay
│                              Zero external dependencies
│                              select() + os.read() multiplexing
│                              write_batch() coalescing for RSP frames
│                              SNMP request-id extraction (BER/ASN.1)
│                              Periodic stats, exception armor
│                              Stale flush on PING, stdin watchdog
│                              ~565 lines
│
├── snmpproxy_protocol.py     Shared STT protocol
│                              Sentinel framing (~##~)
│                              Message builders + parser
│                              FrameReader state machine
│                              Sentinel-split retention across recv()
│                              Zero external dependencies
│                              ~310 lines
│
├── ssh_client.py             SCNG SSH Client
│                              Legacy cipher/KEX support
│                              invoke-shell + prompt detection
│                              ANSI filtering, pagination disable
│
├── stt-gen.js                Node.js STT client for sc-js integration
│
├── snmpproxy.yaml            Configuration
│                              SSH connection + port mappings
│
├── discover/                 Bundled discovery engine
│   ├── engine.py             Crawl orchestrator — BFS, concurrent, dedup
│   ├── transport.py          ProxyWalker + SNMPTransport
│   ├── walker.py             DirectWalker — pysnmp 7.1.22
│   ├── models.py             Device, Neighbor, topology map builder
│   ├── snmp.py               Collector dispatcher
│   ├── oids.py               SNMP OID constants
│   ├── parsers.py            Value decoders
│   ├── scrubber.py           Output sanitization
│   ├── collectors/           CDP, LLDP, system, interfaces, ARP
│   └── ssh/client.py         SCNG SSH client (discover copy)
│
└── __init__.py               Package init
```

## Performance

Measured on local lab (SSH to localhost, Arista target):

| Metric | Value |
|---|---|
| Request RTT (tunnel) | < 15ms |
| Full UDP round-trip | < 15ms |
| Request size | ~40 bytes |
| Response size | ~100 bytes |
| Base64 overhead | ~33% |
| Framing overhead | 8 bytes (two sentinels) |
| Boot to ready | ~500ms (after SSH connected) |
| Handshake | Single PING/PONG exchange |

At a 60-second poll interval with 16 interfaces across several devices, the tunnel handles multiple concurrent requests per cycle. Each request is independent and asynchronous. The SSH session is idle >99% of the time.


## License

MIT