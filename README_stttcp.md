# stt-tcp — Transparent TCP over SSH Terminal Transport

A generic TCP relay that tunnels any TCP connection through an interactive SSH terminal session. HTTP, SSH, PostgreSQL, Redis, REST APIs, web UIs — anything that speaks TCP goes through. One SSH session, unlimited targets.

**stt-tcp** is the second implementation of the SSH Terminal Transport protocol. Where stt-snmp relays UDP/SNMP, stt-tcp relays arbitrary TCP streams. Same architecture. Same framing. Same two-file remote deployment. Same refusal to care about `AllowTcpForwarding`.

Two routing modes: **static port maps** (each local port forwards to a fixed remote `host:port`) and a **SOCKS5 proxy** (one local port reaches any host the client names, resolved on the remote side — a drop-in `ssh -D` replacement for servers that forbid `-D`). Both run on the same tunnel simultaneously.

## Proven

This is not a concept. SSH-in-SSH through a terminal transport — confirmed working against real network equipment.

```
Juniper QFX5100 (JUNOS 14.1X53-D40.8) via jumpbox:
  ssh -p 12001 user@127.0.0.1
  → Through Debian 11 jumpbox
  → Full interactive session: JUNOS banner, show version, CLI
  → QFX5100-48S-6Q, JUNOS built 2016
  → SSH key exchange, interactive shell — all carried as framed
    base64 text through an invoke-shell session

Arista vEOS-lab (EOS 4.33.1F) via lab jumpbox:
  ssh -p 12001 cisco@127.0.0.1
  → Full interactive session: login, enable, show version
  → SSH key exchange, password auth, interactive CLI
```

**SOCKS5 mode — a full web UI rendered in a browser through the shell session:**

```
Arista EOS Command API Explorer (eAPI) via jumpbox:
  Firefox → SOCKS5 127.0.0.1:1080 (socks_remote_dns=true) → http://172.16.2.2/
  → 301 redirect to /eapi/ followed transparently
  → Full Arista Command API web app rendered: nav tree, request
    builder, all CSS/JS/assets — a live, interactive switch UI
  → Reached from a laptop with no route to the device, through an
    invoke-shell on a host the device sits behind
```

The browser never knows it's talking to anything but a normal SOCKS5 proxy. A real, modern, multi-asset web application assembled itself over a base64 text channel — including correctly carrying TLS streams end-to-end (the proxy never sees plaintext; the certificate stays the origin's).

The SSH client has no awareness of the tunnel. The network device has no awareness of the tunnel. The jumpbox SSH server has no awareness that structured TCP traffic is flowing through its shell session.

```
$ ssh -p 12001 user@127.0.0.1
--- JUNOS 14.1X53-D40.8 built 2016-11-09 02:13:22 UTC
{master:0}
user@qfx> show version
fpc0:
--------------------------------------------------------------------------
Hostname: qfx
Model: qfx5100-48s-6q
Junos: 14.1X53-D40.8
JUNOS Base OS boot [14.1X53-D40.8]
JUNOS Base OS Software Suite [14.1X53-D40.8]
JUNOS Crypto Software Suite [14.1X53-D40.8]
JUNOS Kernel Software Suite [14.1X53-D40.8]
JUNOS Packet Forwarding Engine Support (qfx-ex-x86-32) [14.1X53-D40.8]
JUNOS Routing Software Suite [14.1X53-D40.8]
JUNOS Enterprise Software Suite [14.1X53-D40.8]
JUNOS Host Software [14.1X53-D40.8]
```

## The insight

SSH tunnels (`-L`, `-R`, `-D`) are the standard answer to "I need to reach a host behind a jumpbox." They work great — until `AllowTcpForwarding no` appears in `sshd_config`. One line and port forwarding is dead.

stt-tcp sidesteps the entire mechanism. Instead of opening an SSH forwarding channel, it runs a framed text protocol over an interactive shell session — the same channel you'd get by typing `ssh jumpbox`. The SSH server sees a user launch a Python script and type text. That's all it sees.

The terminal is not a limitation to work around. It is the transport layer.

## How it works

```
┌─ Your machine ─────────────────────┐     ┌─ Jumpbox ──────────────────────────┐
│                                    │     │                                    │
│  Any TCP tool                      │     │  stttcp_remote.py                  │
│    │  TCP to localhost:12001       │     │    │  real TCP to target hosts     │
│    ▼                               │     │    ▼                               │
│  stttcp_local.py                   │     │  10.2.2.1:22   (qfx)               │
│    │  Framed text protocol         │     │  10.1.1.50:8080    (api-server)    │
│    │  over invoke-shell            │     │  10.1.1.100:5432   (postgres)      │
│    ▼                               │     │  10.1.1.101:6379   (redis)         │
│  SCNG SSH Client ──── SSH ─────────┼─────┼──► stdin/stdout of agent           │
│  (legacy cipher/KEX support)       │     │  ...and more                       │
└────────────────────────────────────┘     └────────────────────────────────────┘
```

### Port-mapped routing

Each remote target gets a unique local TCP port:

```
localhost:12001  →  10.2.2.1:22   (qfx)
localhost:12002  →  10.1.1.1:22       (core-router)
localhost:18080  →  10.1.1.50:8080    (api-server)
localhost:15432  →  10.1.1.100:5432   (postgres-primary)
localhost:16379  →  10.1.1.101:6379   (redis-cache)
localhost:13000  →  10.1.1.200:3000   (grafana)
```

### TCP stream lifecycle

```
1. ssh connects to localhost:12001
     → TCPListener accepts the connection
     → Assigns stream_id 000001
     → Sends through SSH channel:
         ~##~OPEN|000001|10.2.2.1:22~##~

2. Remote agent opens TCP socket to 10.2.2.1:22
     → Sends back:
         ~##~OPENED|000001~##~

3. ssh sends key exchange data (binary SSH protocol)
     → Local proxy base64-encodes and frames:
         ~##~DATA|000001|U1NILTIuMC1PcGVuU1NIXzkuOQ0K...~##~
     → Remote agent decodes → writes to TCP socket

4. QFX responds with its SSH banner + kex
     → Remote agent reads TCP socket → base64-encodes:
         ~##~DATA|000001|U1NILTIuMC1PcGVuU1NIXzguNA0K...~##~
     → Local proxy decodes → writes to ssh client

5. Full interactive session proceeds — login, commands, output
     → Bidirectional DATA frames carry everything transparently

6. ssh disconnects (or QFX closes)
     → CLOSE|000001 sent in appropriate direction
     → Both sides clean up stream state
```

The SSH client never knows. The protocol never inspects the payload. It's just bytes in, bytes out.

### Boot sequence

```
1. SCNG SSHClient.connect()
   │  Handles: legacy ciphers/KEX, key loading, invoke-shell,
   │  banner drain, ANSI filtering
   │
2. SSHClient.find_prompt()
   │  Confirms shell is ready. Extracts jumpbox hostname.
   │
3. Grab raw channel
   │  Take the paramiko channel from SSHClient.
   │  From this point forward, SSHClient is just a connection holder.
   │
4. Combined: stty raw -echo + exec agent + stderr redirect
   │  Single shell command:
   │    "stty raw -echo; exec python3 -u agent.py 2>/tmp/stttcp_agent.log"
   │  Bash parses the entire line in cooked mode, sets raw mode
   │  with echo disabled, then exec replaces bash with the agent.
   │  The agent inherits the raw PTY. Must be one command — if
   │  stty is sent separately, bash can't parse the next command.
   │  -echo is explicit because stty raw alone doesn't suppress
   │  echo on all systems (confirmed: Debian 11).
   │  stderr redirect keeps agent logs off the PTY while preserving
   │  them on the jumpbox. Path configurable via remote_log in YAML.
   │  (See: "Taming the PTY" below — this is critical.)
   │
5. Send: ~##~PING~##~
   │  FrameReader processes all output.
   │  Discards: command echo, python startup, ANSI, MOTD residue.
   │
6. Receive: ~##~PONG~##~
   │  Handshake complete. Agent owns the channel.
   │
7. Start ChannelWriter + reader thread
   │  Writer serializes all channel writes (prevents frame interleaving).
   │  Reader thread feeds SSH output through FrameReader.
   │
8. TCP listeners start on localhost
   │  One per target mapping. Any tool can connect immediately.
   │
9. Keepalive loop
   Periodic PING/PONG detects dead tunnels.
```

## Taming the PTY

An interactive SSH shell session is a pseudo-terminal (PTY). By default, the PTY does things that are helpful for humans and catastrophic for a data protocol:

**Echo.** The shell echoes everything you type back through the channel. Send `~##~DATA|000001|...~##~` and it comes back at you. The FrameReader parses the echo as a valid incoming DATA message and delivers it to the local client — duplicating every outbound byte as if it came from the remote target. Corrupt data on every connection.

**Canonical (cooked) mode.** The kernel buffers PTY input until a newline arrives. The input buffer is typically 4096 bytes. A 1832-byte SSH kex payload becomes ~2500 characters of base64 plus framing — fits. But anything larger overflows the buffer, `\n` never arrives in the buffer, and the agent's stdin blocks. The select loop deadlocks. No reads, no writes, no PONGs.

**Line discipline.** The terminal translates `\r` to `\n`, interprets control characters (Ctrl-C becomes `SIGINT`), and may strip high bytes depending on `TERM` settings. Any of these corrupts binary payloads.

The fix is three things, and you need all of them:

**`stty raw -echo; exec python3 -u agent.py 2>/tmp/stttcp_agent.log`** — a single shell command. This is critical: `stty raw -echo` and the agent launch must be on the same line. If you send `stty raw` as a separate command and then send the agent command, bash is already in raw mode when it tries to read the second line — line discipline is off, `\n` doesn't terminate input, and bash can't parse it. By combining them with `;`, bash reads and parses the full line in cooked mode, then executes `stty raw -echo`, then `exec` replaces bash with the agent. The agent inherits the raw PTY. `exec` also eliminates the idle bash parent process. `-u` (unbuffered stdout) is critical — without it, Python buffers framed responses and the local side never receives them. The `-echo` flag is explicit and required — `stty raw` alone doesn't suppress echo on all systems (confirmed on Debian 11), and echo causes sent DATA frames to be received back as incoming data, corrupting every bidirectional stream.

**`2>/tmp/stttcp_agent.log`** — stderr redirect on the agent launch command. In a PTY, stderr and stdout share the same output path through the pty master into the SSH channel. The remote agent's log calls write to stderr, which injects unframed text into the protocol stream. Between frames, the FrameReader discards it as noise. But if a log line arrives *during* a large DATA write — while the kernel is mid-`write()` of a base64 chunk — the stderr bytes get spliced into the frame content. Corrupted base64, DATA frame lost. With multiple concurrent TCP streams generating log output, the collision rate increases over time. Redirecting stderr to a file on the jumpbox keeps the protocol stream clean while preserving debug logs for later inspection. The log path is configurable via `remote_log` in YAML (default: `/tmp/stttcp_agent.log`).

**`os.read(stdin_fd, 65536)`** in the remote agent instead of `sys.stdin.readline()`. Even with `stty raw`, Python's `readline()` waits for `\n` in its own internal buffer. `os.read()` returns whatever bytes are available from the file descriptor — no line buffering, no waiting. The FrameReader already handles partial frames, so feeding it raw chunks is exactly right.

**`ChannelWriter`** on the local side — serialized, coalescing write queue. Multiple concurrent TCP streams calling `channel.sendall()` from different asyncio coroutines can interleave frames on the wire. For TCP this is more dangerous than for SNMP — interleaved DATA frames corrupt byte streams, not just individual request/response pairs. The ChannelWriter's single drain loop owns all channel writes. Callers enqueue frames, the drain loop coalesces them into batches, and a single `sendall()` call writes atomically. This guarantees frames never interleave even under heavy concurrent load.

These lessons apply to any STT implementation (stt-snmp, stt-tcp, or future protocols). If you're carrying data over an invoke-shell, the terminal defaults will fight you at every layer: kernel line discipline, PTY echo, Python I/O buffering, stderr contamination, write interleaving, and even bash's own input parsing. Kill all of them.

## Use cases

### SSH-in-SSH (SSH through terminal transport)

```bash
python3 -m stttcp.stttcp_local -c stttcp.yaml

# Port 12001 maps to qfx:22 through the jumpbox
ssh -p 12001 user@127.0.0.1

# scp through the tunnel
scp -P 12001 user@127.0.0.1:running-config ./backup/
```

This is SSH carried as framed base64 text inside another SSH invoke-shell session. The outer SSH server has no idea it's carrying nested SSH traffic. `AllowTcpForwarding no` doesn't matter — there's no forwarding happening.

### REST APIs behind a jumpbox

```bash
# Hit an internal API
curl http://localhost:18080/api/v1/status

# POST with JSON
curl -X POST http://localhost:18080/api/v1/devices \
  -H "Content-Type: application/json" \
  -d '{"hostname": "spine1"}'
```

### Database access

```bash
# PostgreSQL
psql -h localhost -p 15432 -U dbadmin mydb

# Redis
redis-cli -h localhost -p 16379
```

### Web UIs

```bash
# Open Grafana in your browser
open http://localhost:13000
```

Point your browser at the local port. The entire HTTP session — WebSocket upgrades, chunked transfers, keep-alive connections — all works transparently.

### SOCKS5 dynamic mode

Static maps require knowing every target in advance. SOCKS5 mode replaces them with a single proxy port that reaches anything the client asks for — and resolves DNS on the remote side, so internal hostnames behind the jumpbox just work.

```bash
# Start with a SOCKS5 proxy on 127.0.0.1:1080 (default port)
python3 -m stttcp.stttcp_local -c stttcp.yaml --socks

# Or pick the port explicitly
python3 -m stttcp.stttcp_local -c stttcp.yaml --socks 1080
```

`--socks` runs alongside any static `targets` in the config — both modes share the one tunnel.

```bash
# curl through the proxy — --socks5-hostname forces remote DNS
curl --socks5-hostname 127.0.0.1:1080 http://internal-host/

# proxychains, for tools without native SOCKS support
proxychains4 psql -h db.internal -U dbadmin mydb
```

Browser setup (Firefox): SOCKS host `127.0.0.1`, port `1080`, and **`network.proxy.socks_remote_dns = true`** — without remote DNS, internal hostnames won't resolve. Chromium does remote DNS over SOCKS5 automatically (`--proxy-server="socks5://127.0.0.1:1080"`).

The proxy implements `CONNECT` with all three address types (IPv4, IPv6, and domain-name pass-through), maps remote connection failures to the correct SOCKS reply code so clients fail fast instead of hanging, and gates the success reply on the tunnel round-trip so no data races ahead of the handshake. `BIND` and `UDP ASSOCIATE` are declined — `CONNECT` is the only command browsers and proxychains need.

**SOCKS5 is a local-side feature only.** The remote agent is unchanged — an `OPEN|stream_id|host:port` looks identical whether the host:port came from a static map or a SOCKS request. No redeploy to enable it.

## Wire protocol specification

### Framing

Identical to stt-snmp — all messages are wrapped in sentinel pairs:

```
~##~{message_content}~##~\n
```

The sentinel `~##~` was chosen because it cannot appear in:

- Base64 output (uses `A-Za-z0-9+/=` only)
- ANSI escape sequences (use `\x1b[...`)
- Standard shell prompts
- Any binary payload after base64 encoding

The `FrameReader` state machine processes a raw stream and extracts only the content between sentinel pairs. Everything outside the sentinels — terminal echo (if `stty raw` failed), shell prompts, ANSI sequences, Python warnings, blank lines — is silently discarded.

### Message types

```
Stream lifecycle:
  ~##~OPEN|{stream_id}|{host}:{port}~##~       Local → remote: open TCP connection
  ~##~OPENED|{stream_id}~##~                    Remote → local: connection established
  ~##~OPEN_ERR|{stream_id}|{error}~##~          Remote → local: connection failed

Data transfer (bidirectional):
  ~##~DATA|{stream_id}|{base64_chunk}~##~       Data in either direction

Stream teardown:
  ~##~CLOSE|{stream_id}~##~                     Either direction: close stream

Keepalive:
  ~##~PING~##~
  ~##~PONG~##~

Shutdown:
  ~##~QUIT~##~
```

### Stream ID

The `stream_id` is a zero-padded 6-digit counter (`000001`, `000002`, ...) generated by the local side. It identifies a TCP stream for its entire lifecycle. Multiple streams can be active concurrently — the protocol is fully multiplexed.

### Data chunking and fairness

TCP reads are capped at 16KB (`DATA_CHUNK_SIZE`), so each DATA frame is ~21KB on the wire after base64 — well under the 200KB overflow limit. The cap is also what keeps one bulk transfer from starving the interactive streams, but the fairness lives in the *read scheduling*, not the writer: the select loop reads at most one 16KB chunk per ready socket per cycle, so a large transfer yields the channel between its chunks instead of monopolizing it. The serialized `ChannelWriter` then preserves that already-interleaved order on the wire.

This is visible in a live trace — during a page load, a bulk asset shows back-to-back RX frames climbing to exactly `16384B` (one read hitting the cap) while other streams' frames continue to land between them.

### Multiplexing

Unlike SSH port forwarding, which opens a separate channel per tunnel, stt-tcp multiplexes all streams over a single invoke-shell channel. Stream IDs allow interleaved DATA frames from different connections to coexist. The reader thread dispatches each frame to the correct stream context.

## Security posture

### The honest conversation

This tool bypasses `AllowTcpForwarding no`. That's a security control, and circumventing it deserves a straight answer.

**The control was already illusory.** If a user has interactive shell access, they can relay TCP traffic. `socat`, `netcat`, `python3 -c "import socket..."`, even `curl` — any of these can bridge a connection manually. `AllowTcpForwarding no` prevents SSH's built-in forwarding mechanism. It does not prevent TCP relay through a shell session.

**stt-tcp makes the implicit explicit.** Instead of ad-hoc shell commands that leave no audit trail, stt-tcp is a structured tool with logging, configuration, and clean lifecycle management. Security teams can detect it, monitor it, and control it.

**The real security boundary is shell access.** If you don't want someone relaying TCP traffic through a jumpbox, don't give them shell access to the jumpbox. `AllowTcpForwarding no` is defense-in-depth for accidental misuse, not a security boundary against an authorized user with a terminal.

### What stt-tcp doesn't do

- **No listening ports on the remote network.** The agent reads stdin. Nothing to scan.
- **No root or elevated privileges.** Both sides run as your normal user.
- **No daemon, no service, no install.** Two Python files. Delete when done.
- **No new attack surface.** The tunnel rides your existing SSH session.
- **No credential exposure.** All application traffic is inside SSH encryption.
- **Loopback only by default.** Local listeners bind to 127.0.0.1.

## Deployment

### Prerequisites

**Local machine:**
- Python 3.9+
- `paramiko` and `pyyaml` (`pip install paramiko pyyaml`)
- SCNG SSH Client (included as `ssh_client.py`)

**Jumpbox:**
- Python 3.7+ (stdlib only — no pip packages needed)
- TCP access to target hosts from the jumpbox

### One-time setup on the jumpbox

```bash
ssh jumpbox "mkdir -p /opt/stttcp"
scp stttcp_protocol.py stttcp_remote.py jumpbox:/opt/stttcp/
```

That's it. No install, no virtualenv, no pip, no service file.

### Project layout

```
stt/
├── .venv/
├── stttcp/
│   ├── __init__.py
│   ├── README.md
│   ├── ssh_client.py               # SCNG SSH client
│   ├── stttcp_local.py             # Local proxy — TCP listeners + SSH tunnel
│   │                                  ChannelWriter (serialized writes)
│   ├── socks5.py                   # SOCKS5 front-end (dynamic routing)
│   ├── stttcp_protocol.py          # Shared protocol — framing + FrameReader
│   └── stttcp_remote.py            # Remote agent — stdin/stdout + TCP relay
└── stttcp.yaml                     # Port mappings + SSH config
```

### Cleanup

```bash
ssh jumpbox "rm -rf /opt/stttcp"
```

Nothing else to undo. No services, no firewall rules, no cron jobs.

## Configuration reference

```yaml
ssh:
  host: jump.dc2.example.com       # Required
  port: 22
  username: user
  password: ""
  key_file: ~/.ssh/id_rsa
  key_content: ""
  legacy_mode: false
  connect_timeout: 30
  shell_timeout: 5.0
  remote_python: python3
  remote_agent: /opt/stttcp/stttcp_remote.py
  remote_log: ""                    # Agent log path on jumpbox
                                    # Default (empty): /tmp/stttcp_agent.log
                                    # Set to /dev/null to suppress logs

bind_address: "127.0.0.1"
connect_timeout: 15                 # Timeout for remote TCP connect
keepalive_interval: 30

targets:
  - local_port: 12001
    remote_host: 10.2.2.1
    remote_port: 22
    label: router

  - local_port: 18080
    remote_host: 10.1.1.50
    remote_port: 8080
    label: api-server
```

### Environment variables

- `USER` — default SSH username (if not specified in config)

## Comparison with SSH port forwarding

| Feature | SSH -L forwarding | stt-tcp |
|---|---|---|
| `AllowTcpForwarding no` | Blocked | Works |
| Dynamic SOCKS (`-D`) | Blocked when forwarding off | SOCKS5 mode, remote DNS |
| Server configuration | Requires forwarding enabled | Requires shell access only |
| Multiplexing | One channel per tunnel | All streams on one shell |
| Jumpbox install | None | Two Python files (stdlib only) |
| Protocol awareness | None (raw TCP relay) | None (raw TCP relay) |
| Audit trail | SSH logs show forwarding | SSH logs show shell session |
| Performance | Native SSH channel | Base64 overhead (~33%) + framing |
| Concurrency | Excellent | Good (terminal is serialized) |

### Performance note

The base64 encoding adds ~33% to payload size, and the terminal channel serializes all traffic through a single SSH stream. For interactive use (APIs, SSH, database queries, web UIs), this is imperceptible. For bulk file transfers, use `scp` or `rsync` directly — stt-tcp is optimized for connectivity, not throughput.

## Tracing

```bash
python3 -m stttcp.stttcp_local -c stttcp.yaml --trace
```

Real output from SSH-in-SSH to Juniper QFX5100 through a jumpbox:

```
09:22:28.099 stttcp           INFO    :12001 ← ('127.0.0.1', 59614) → qfx
09:22:28.100 stttcp.trace     INFO    TX  OPEN 000002 → 10.2.2.1:22
09:22:28.174 stttcp.trace     INFO    RX  OPENED 000002
09:22:28.175 stttcp.trace     INFO    TX  DATA 000002 21B
09:22:28.214 stttcp.trace     INFO    RX  DATA 000002 16B
09:22:28.233 stttcp.trace     INFO    RX  DATA 000002 5B
09:22:28.239 stttcp.trace     INFO    RX  DATA 000002 21B
09:22:28.241 stttcp.trace     INFO    TX  DATA 000002 1832B
```

The 21-byte exchange is the SSH version string. The 16+5 byte split is the QFX's version string arriving in two TCP reads. The 1832-byte frame is the kex init. All carried as base64 text on an invoke-shell channel through a Debian 11 jumpbox.

Real output from SOCKS5 mode during a browser page load — note the remote-resolved FQDN, the interleaved stream IDs (concurrent connections sharing one shell), and a bulk asset on stream 000024 reading up to the 16384-byte chunk cap while other streams continue between its frames:

```
SOCKS5 (127.0.0.1, 47522) → CONNECT prod-images...webservices.mozgcp.net:443
TX  OPEN 000026 → prod-images...webservices.mozgcp.net:443
RX  OPENED 000026
TX  DATA 000026 1929B          ← TLS ClientHello, carried as base64 text
RX  DATA 000026 3120B          ← ServerHello — TLS negotiated end-to-end
...
TX  DATA 000019 343B           ┐ stream 000019, 000024, 000026 all
RX  DATA 000024 7240B          │ interleaving on one invoke-shell
RX  DATA 000024 13032B         │
RX  DATA 000024 16384B         ← one read hit the chunk cap exactly
RX  DATA 000024 6784B          ┘ bulk asset yields between chunks
```

Eight-plus concurrent streams, remote DNS, and TLS all riding a single shell session — fast enough that a modern web app renders without perceptible lag.

## Future

SOCKS5 mode (formerly listed here as future work) is implemented and proven — see **SOCKS5 dynamic mode** above. What remains:

- **Concurrency backpressure.** The remote agent caps in-flight streams (`MAX_STREAMS`). A heavy page load can open many connections at once; the agent should return a clean `OPEN_ERR` at the cap so the client retries gracefully rather than stalling. Not yet stress-tested to the ceiling against a real workload.
- **Reconnection.** If the SSH session drops, the proxy exits. A future version should reconnect with backoff and re-establish the agent handshake.
- **Generalized agent loader.** The remote agent is currently a fixed TCP relay. The longer-term shape is a minimal stage-one loader that receives an agent over the same channel (`LOAD|{base64_module}`) and execs it — turning "deliver an agent" into a protocol verb so one bootstrap can host TCP, SNMP, or any future payload, chosen at runtime. The loader stays deliberately dumb (no auth of its own — it inherits the SSH session's) precisely so it remains an agent loader and not a backdoor.