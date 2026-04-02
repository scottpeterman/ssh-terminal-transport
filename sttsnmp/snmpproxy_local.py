#!/usr/bin/env python3
"""
snmpproxy_local.py — Local transparent SNMP-over-SSH proxy

Creates real UDP SNMP listeners on localhost. Any SNMP tool can query
localhost:{port} and the request is transparently relayed through an
SSH tunnel to the actual device on the remote network.

Routing: port-mapped — each remote target gets a unique local port.

Modes:
  Static  — targets defined in YAML config (original behavior)
  Dynamic — targets registered at runtime via REST API (--api flag)
            Enables recursive discovery without pre-built port maps.

Security posture:
  - No listening ports on the remote network
  - No root/elevated privileges required
  - No daemon or install on the jumpbox (just a python script)
  - All traffic rides an existing SSH session
  - User-level access only

Usage:
  # Static mode (original)
  python3 snmpproxy_local.py -c snmpproxy.yaml

  # Dynamic mode — API on localhost:8901
  python3 snmpproxy_local.py -c snmpproxy.yaml --api

  # Dynamic mode — custom API port, no YAML targets required
  python3 snmpproxy_local.py -c snmpproxy.yaml --api --api-port 9000

Then from any SNMP tool:
  snmpwalk -v2c -c public localhost:10001 1.3.6.1.2.1.1
  snmpget  -v2c -c public localhost:10002 1.3.6.1.2.1.1.1.0

Dynamic registration:
  curl -X POST http://127.0.0.1:8901/targets \\
       -H 'Content-Type: application/json' \\
       -d '{"remote_host": "10.2.1.42"}'
  # → {"local_port": 10017, "remote_host": "10.2.1.42", ...}

  snmpwalk -v2c -c public localhost:10017 1.3.6.1.2.1.1

Requires: paramiko, pyyaml, aiohttp (only if --api is used)
SSH client: Uses SCNG SSHClient (scng/discovery/ssh/client.py)
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

# SCNG SSH Client — adjust import path to match your project layout
# e.g., from scng.discovery.ssh.client import SSHClient, SSHClientConfig
from sttsnmp.ssh_client import SSHClient, SSHClientConfig

from sttsnmp.snmpproxy_protocol import (
    FrameReader,
    Request,
    Response,
    MsgType,
    RspStatus,
    build_request,
    build_ping,
    build_quit,
)

log = logging.getLogger("snmpproxy")
trace = logging.getLogger("snmpproxy.trace")


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class SSHConfig:
    host: str = ""
    port: int = 22
    username: str = ""
    password: str = ""
    key_file: str = ""
    key_content: str = ""
    remote_python: str = "python3"
    remote_agent: str = "/opt/snmpproxy/snmpproxy_remote.py"
    remote_log: str = ""       # stderr redirect on jumpbox (default: /tmp/snmpproxy_agent.log)
    legacy_mode: bool = False
    connect_timeout: int = 120
    shell_timeout: float = 5.0


@dataclass
class TargetMapping:
    local_port: int = 0
    remote_host: str = ""
    remote_port: int = 161
    label: str = ""

    @property
    def display(self) -> str:
        return self.label or f"{self.remote_host}:{self.remote_port}"

    @property
    def remote_addr(self) -> str:
        return f"{self.remote_host}:{self.remote_port}"


@dataclass
class ProxyConfig:
    ssh: SSHConfig = field(default_factory=SSHConfig)
    targets: list[TargetMapping] = field(default_factory=list)
    bind_address: str = "127.0.0.1"
    request_timeout: float = 10.0
    keepalive_interval: float = 30.0


def load_config(path: str | Path) -> ProxyConfig:
    """Load proxy config from YAML"""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Config not found: {path}")

    with open(path) as f:
        raw = yaml.safe_load(f)

    if not raw:
        raise ValueError(f"Empty config: {path}")

    cfg = ProxyConfig()

    ssh = raw.get("ssh", {})
    cfg.ssh = SSHConfig(
        host=ssh.get("host", ""),
        port=int(ssh.get("port", 22)),
        username=ssh.get("username", os.environ.get("USER", "")),
        password=ssh.get("password", ""),
        key_file=ssh.get("key_file", ""),
        key_content=ssh.get("key_content", ""),
        remote_python=ssh.get("remote_python", "python3"),
        remote_agent=ssh.get("remote_agent", "/opt/snmpproxy/snmpproxy_remote.py"),
        remote_log=ssh.get("remote_log", ""),
        legacy_mode=ssh.get("legacy_mode", False),
        connect_timeout=int(ssh.get("connect_timeout", 30)),
        shell_timeout=float(ssh.get("shell_timeout", 5.0)),
    )

    cfg.bind_address = raw.get("bind_address", "127.0.0.1")
    cfg.request_timeout = float(raw.get("request_timeout", 10))
    cfg.keepalive_interval = float(raw.get("keepalive_interval", 30))

    for t in raw.get("targets", []):
        cfg.targets.append(TargetMapping(
            local_port=int(t["local_port"]),
            remote_host=t["remote_host"],
            remote_port=int(t.get("remote_port", 161)),
            label=t.get("label", ""),
        ))

    if not cfg.ssh.host:
        raise ValueError("ssh.host is required")
    # NOTE: targets list can now be empty when using --api mode
    # The original check is deferred to run() / run_with_api()

    return cfg


# ---------------------------------------------------------------------------
# Serialized channel writer — eliminates frame interleaving
# ---------------------------------------------------------------------------

class ChannelWriter:
    """
    Serialized, coalescing write queue for the SSH channel.

    Problem: Multiple concurrent asyncio coroutines calling channel.sendall()
    can interleave frames on the wire. Paramiko's channel write isn't atomic
    for multi-byte payloads — two REQ frames sent concurrently can fragment
    into SSH packets that interleave. The remote FrameReader sees a sentinel
    in the middle of another frame, corrupting both.

    Solution: Single drain loop owns all writes. Callers enqueue frames via
    send() and the drain loop coalesces queued frames into single sendall()
    calls. This guarantees:
      1. Frames never interleave on the wire
      2. Small frames coalesce into fewer SSH packets (better throughput)
      3. Blocking sendall() runs in executor (doesn't block the event loop)

    The writer is NOT used during the handshake phase (connect/PING/PONG)
    because the event loop isn't running yet. Handshake writes are
    single-threaded and sequential — interleaving isn't possible.
    """

    def __init__(self, channel, max_batch_bytes: int = 16384):
        self._channel = channel
        self._queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._max_batch = max_batch_bytes   # stay under SSH max packet (32KB)
        self._task: Optional[asyncio.Task] = None
        self._running = False

        # Metrics — exposed for trace logging and health checks
        self.frames_queued = 0
        self.frames_written = 0
        self.batches_written = 0
        self.bytes_written = 0
        self.coalesced_count = 0           # frames that rode with another
        self.high_water_mark = 0           # max queue depth observed

    def start(self) -> None:
        """Start the drain loop. Call from the asyncio event loop thread."""
        self._running = True
        self._task = asyncio.ensure_future(self._drain_loop())
        log.debug("ChannelWriter started")

    async def send(self, frame: str) -> None:
        """
        Enqueue a framed message for writing. Non-blocking from the
        caller's perspective — returns immediately after enqueue.
        """
        data = frame.encode()
        await self._queue.put(data)
        self.frames_queued += 1

        qsize = self._queue.qsize()
        if qsize > self.high_water_mark:
            self.high_water_mark = qsize
        if qsize > 40:
            log.warning(f"Write queue depth: {qsize} (high water: {self.high_water_mark})")

    async def _drain_loop(self) -> None:
        """
        Single writer coroutine. Drains the queue, coalesces small
        frames into batches, writes atomically to the channel.
        """
        loop = asyncio.get_running_loop()

        while self._running:
            try:
                # Block until at least one frame is ready
                batch = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

            frames_in_batch = 1

            # Coalesce: grab everything else that's queued right now,
            # up to max_batch_bytes to stay within SSH packet limits
            while not self._queue.empty() and len(batch) < self._max_batch:
                try:
                    batch += self._queue.get_nowait()
                    frames_in_batch += 1
                except asyncio.QueueEmpty:
                    break

            if frames_in_batch > 1:
                self.coalesced_count += frames_in_batch
                log.debug(f"Coalesced {frames_in_batch} frames into {len(batch)}B batch")

            # Write to channel in executor — don't block the event loop
            try:
                await loop.run_in_executor(None, self._channel.sendall, batch)
                self.frames_written += frames_in_batch
                self.batches_written += 1
                self.bytes_written += len(batch)
            except Exception as e:
                if self._running:
                    log.error(f"ChannelWriter sendall failed: {e}")
                break

        log.debug("ChannelWriter drain loop exiting")

    async def stop(self) -> None:
        """Stop the drain loop. Flushes remaining queued frames first."""
        self._running = False
        if self._task:
            # Give the drain loop a moment to flush
            try:
                await asyncio.wait_for(self._task, timeout=2.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._task.cancel()
            self._task = None

        log.debug(
            f"ChannelWriter stopped — "
            f"queued:{self.frames_queued} written:{self.frames_written} "
            f"batches:{self.batches_written} bytes:{self.bytes_written} "
            f"coalesced:{self.coalesced_count} hwm:{self.high_water_mark}"
        )

    def send_sync(self, frame: str) -> None:
        """
        Synchronous write — bypasses the queue for shutdown QUIT.
        Only safe when the drain loop is already stopped.
        """
        try:
            self._channel.sendall(frame.encode())
        except Exception:
            pass


# ---------------------------------------------------------------------------
# SSH tunnel — SCNG client for connection, framed protocol for data
# ---------------------------------------------------------------------------

class SSHTunnel:
    """
    Uses SCNG SSHClient for SSH connection + prompt detection, then
    switches the channel to raw framed protocol mode for SNMP relay.

    Boot sequence:
      1. SSHClient.connect()       → invoke-shell, drain banner
      2. SSHClient.find_prompt()   → confirm shell is ready
      3. stty raw -echo            → disable pty echo + canonical mode
      4. exec python3 -u ...       → start agent (replaces shell)
      5. FrameReader: PING/PONG    → handshake, drain boot noise
      6. Reader thread takes over  → protocol is live
    """

    def __init__(self, cfg: ProxyConfig):
        self.cfg = cfg
        self._ssh_client: Optional[SSHClient] = None
        self._channel = None    # paramiko Channel (from SSHClient._shell)
        self._reader_thread: Optional[threading.Thread] = None
        self._running = False

        # Pending requests: msg_id → asyncio.Future
        self._pending: dict[str, asyncio.Future] = {}
        self._send_times: dict[str, float] = {}  # msg_id → monotonic timestamp
        self._pending_lock = threading.Lock()
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        # Serialized writer — initialized after channel is established
        self._writer: Optional[ChannelWriter] = None

        # Message ID counter
        self._msg_counter = 0
        self._msg_lock = threading.Lock()

    def next_msg_id(self) -> str:
        with self._msg_lock:
            self._msg_counter += 1
            return f"{self._msg_counter:06d}"

    def connect(self) -> None:
        """
        Connect via SCNG SSHClient, find prompt, launch remote agent,
        handshake, and transition to protocol mode.
        """
        ssh_cfg = self.cfg.ssh

        # Build SCNG SSHClientConfig
        client_config = SSHClientConfig(
            host=ssh_cfg.host,
            port=ssh_cfg.port,
            username=ssh_cfg.username,
            password=ssh_cfg.password or None,
            key_file=ssh_cfg.key_file or None,
            key_content=ssh_cfg.key_content or None,
            timeout=ssh_cfg.connect_timeout,
            shell_timeout=ssh_cfg.shell_timeout,
            legacy_mode=ssh_cfg.legacy_mode,
        )

        log.info(
            f"Connecting to {ssh_cfg.username}@{ssh_cfg.host}:{ssh_cfg.port}"
            f"{' (legacy mode)' if ssh_cfg.legacy_mode else ''}"
        )

        # ── Phase 1: SCNG client handles SSH + shell + banner drain ──
        self._ssh_client = SSHClient(client_config)
        self._ssh_client.connect()

        # ── Phase 2: Find prompt — confirms shell is clean and ready ──
        prompt = self._ssh_client.find_prompt()
        log.info(f"Shell ready — prompt: {prompt!r}")

        hostname = self._ssh_client.hostname
        if hostname:
            log.info(f"Jumpbox hostname: {hostname}")

        # ── Phase 3: Grab the raw channel for protocol I/O ──
        # From this point forward, we bypass SSHClient's command execution
        # and talk directly to the paramiko channel via framed protocol.
        self._channel = self._ssh_client._shell
        if not self._channel:
            raise ConnectionError("SSHClient shell channel not available")

        # ── Phase 4: Disable pty echo + canonical mode, launch agent ──
        # CRITICAL: The pty echoes everything sent through the channel back
        # to the channel output. Echo of REQ frames contains valid sentinels
        # (~##~) that corrupt in-progress RSP frames in the FrameReader —
        # the echoed sentinel gets misread as the end-of-frame marker,
        # truncating the RSP and producing garbled base64. This is the
        # primary cause of intermittent frame corruption under load.
        #
        # stty raw -echo fixes three things:
        #   -echo    → no echo, eliminates phantom sentinel corruption
        #   raw      → no canonical mode (removes 4096-byte input line
        #              buffer limit that can truncate large frames)
        #            → no OPOST (eliminates \n → \r\n output translation)
        #            → no signal chars (Ctrl-C won't SIGINT the agent)
        #
        # exec replaces the shell with python — one fewer process,
        # SIGHUP goes directly to the agent on channel close.
        #
        # CRITICAL: stderr redirect (2>). The remote agent logs to stderr
        # for visibility, but in a pty session stderr shares the same fd
        # as stdout. Under load, retry/timeout/request logs flood the
        # channel alongside protocol frames. The FrameReader ignores them
        # (no sentinels), but they consume bandwidth and pty buffer space.
        # Redirecting stderr to a file on the jumpbox keeps the protocol
        # stream clean while preserving debug logs for later inspection.
        remote_log = ssh_cfg.remote_log or "/tmp/snmpproxy_agent.log"
        agent_cmd = (
            f"stty raw -echo; "
            f"exec {ssh_cfg.remote_python} -u {ssh_cfg.remote_agent} "
            f"2>{remote_log}\n"
        )
        log.info(f"Starting remote agent: {agent_cmd.strip()}")
        log.info(f"Remote agent log: {remote_log}")
        self._channel.sendall(agent_cmd.encode())

        # Brief pause to let the agent start before sending PING
        time.sleep(0.5)

        # ── Phase 5: Handshake — PING/PONG through FrameReader ──
        # With echo disabled, boot noise is minimal: just the stty/exec
        # command output (if any) and the agent's stderr startup line.
        # FrameReader discards everything until PONG.
        log.debug("Sending PING for handshake...")
        self._channel.sendall(build_ping().encode())

        self._wait_for_pong()
        log.info("Remote agent ready — handshake complete")

    def _wait_for_pong(self, timeout: float = 20.0) -> None:
        """
        Feed channel output through FrameReader until PONG arrives.
        Everything outside the sentinels is silently discarded.
        """
        reader = FrameReader(
            on_noise=lambda s: log.debug(f"Boot noise: {s.strip()[:120]}")
            if s.strip() else None
        )
        self._channel.settimeout(1.0)
        start = time.monotonic()
        ping_resent = False

        while time.monotonic() - start < timeout:
            try:
                chunk = self._channel.recv(4096).decode("utf-8", errors="replace")
            except socket.timeout:
                # Re-send PING once after 5s in case the first was swallowed
                # by terminal echo or arrived before the agent's read loop
                elapsed = time.monotonic() - start
                if elapsed > 5.0 and not ping_resent:
                    log.debug("Re-sending PING...")
                    self._channel.sendall(build_ping().encode())
                    ping_resent = True
                continue

            if not chunk:
                raise ConnectionError("SSH channel closed during handshake")

            for msg in reader.feed(chunk):
                if msg == MsgType.PONG:
                    return

        raise ConnectionError(f"Handshake failed — no PONG within {timeout}s")

    # ------------------------------------------------------------------
    # Reader thread — steady-state protocol I/O
    # ------------------------------------------------------------------

    def start_reader(self, loop: asyncio.AbstractEventLoop) -> None:
        """Start background reader thread and serialized writer for protocol I/O"""
        self._loop = loop
        self._running = True
        self._channel.settimeout(1.0)

        # Start serialized writer — all sends go through this from now on
        self._writer = ChannelWriter(self._channel)
        self._writer.start()

        self._reader_thread = threading.Thread(
            target=self._reader_loop,
            daemon=True,
            name="ssh-reader",
        )
        self._reader_thread.start()

    def _reader_loop(self) -> None:
        """Background thread: read from SSH, feed FrameReader, resolve futures"""
        log.debug("SSH reader thread started")

        reader = FrameReader(
            on_noise=lambda s: log.debug(f"Noise: {s.strip()[:80]}")
            if s.strip() else None
        )

        try:
            while self._running:
                try:
                    # 32KB recv — matches SSH max packet size, reduces
                    # chunk-boundary splits and FrameReader work
                    chunk = self._channel.recv(32768)
                except socket.timeout:
                    continue
                except Exception as e:
                    if self._running:
                        log.error(f"SSH read error: {e}")
                    break

                if not chunk:
                    if self._running:
                        log.warning("SSH channel closed by remote")
                    break

                text = chunk.decode("utf-8", errors="replace")

                for msg in reader.feed(text):
                    if isinstance(msg, Response):
                        self._resolve_response(msg)
                    elif msg == MsgType.PONG:
                        log.debug("PONG received (keepalive)")
                    else:
                        log.debug(f"Unexpected message in reader: {msg}")

        except Exception as e:
            log.error(f"Reader thread crashed: {e}")
        finally:
            log.debug("SSH reader thread exiting")
            self._fail_all_pending("SSH tunnel closed")

    def _resolve_response(self, rsp: Response) -> None:
        """Resolve a pending future with the response"""
        with self._pending_lock:
            future = self._pending.pop(rsp.msg_id, None)
            sent_at = self._send_times.pop(rsp.msg_id, None)

        rtt_ms = (time.monotonic() - sent_at) * 1000 if sent_at else 0

        if rsp.status == RspStatus.OK:
            trace.info(
                f"RX  {rsp.msg_id} OK {len(rsp.data)}B  rtt={rtt_ms:.1f}ms"
            )
        elif rsp.status == RspStatus.TIMEOUT:
            trace.info(f"RX  {rsp.msg_id} TIMEOUT  rtt={rtt_ms:.1f}ms")
        else:
            trace.info(f"RX  {rsp.msg_id} ERR {rsp.error}  rtt={rtt_ms:.1f}ms")

        if future and self._loop:
            if rsp.status == RspStatus.OK:
                self._loop.call_soon_threadsafe(future.set_result, rsp.data)
            elif rsp.status == RspStatus.TIMEOUT:
                self._loop.call_soon_threadsafe(
                    future.set_exception,
                    TimeoutError("SNMP device timeout"),
                )
            else:
                self._loop.call_soon_threadsafe(
                    future.set_exception,
                    RuntimeError(f"Remote error: {rsp.error}"),
                )
        elif not future:
            log.debug(f"{rsp.msg_id}: no pending future (already timed out?)")

    def _fail_all_pending(self, reason: str) -> None:
        """Fail all in-flight requests when tunnel goes down"""
        with self._pending_lock:
            for mid, fut in self._pending.items():
                if not fut.done() and self._loop:
                    self._loop.call_soon_threadsafe(
                        fut.set_exception,
                        ConnectionError(reason),
                    )
            self._pending.clear()
            self._send_times.clear()

    # ------------------------------------------------------------------
    # Request API — used by UDP listeners
    # ------------------------------------------------------------------

    async def send_request(
        self, remote_host: str, remote_port: int, pdu: bytes,
    ) -> bytes:
        """Send SNMP PDU through tunnel, return response bytes"""
        if not self._writer:
            raise ConnectionError("Writer not started — call start_reader() first")

        msg_id = self.next_msg_id()
        msg = build_request(msg_id, remote_host, remote_port, pdu)

        loop = asyncio.get_running_loop()
        future = loop.create_future()

        with self._pending_lock:
            self._pending[msg_id] = future

        try:
            # Enqueue through serialized writer — never interleaves
            await self._writer.send(msg)
            with self._pending_lock:
                self._send_times[msg_id] = time.monotonic()
            log.debug(f"{msg_id}: REQ → {remote_host}:{remote_port} ({len(pdu)} bytes)")
            trace.info(f"TX  {msg.rstrip()}")
        except Exception as e:
            with self._pending_lock:
                self._pending.pop(msg_id, None)
                self._send_times.pop(msg_id, None)
            raise ConnectionError(f"SSH write failed: {e}")

        try:
            return await asyncio.wait_for(future, timeout=self.cfg.request_timeout)
        except asyncio.TimeoutError:
            with self._pending_lock:
                self._pending.pop(msg_id, None)
                self._send_times.pop(msg_id, None)
            raise TimeoutError(
                f"Request {msg_id} to {remote_host}:{remote_port} "
                f"timed out after {self.cfg.request_timeout}s"
            )

    # ------------------------------------------------------------------
    # Keepalive + shutdown
    # ------------------------------------------------------------------

    async def keepalive_loop(self) -> None:
        """Periodic PING to detect dead tunnels"""
        while self._running:
            await asyncio.sleep(self.cfg.keepalive_interval)
            if not self._running:
                break
            try:
                if self._writer:
                    await self._writer.send(build_ping())
                else:
                    self._channel.sendall(build_ping().encode())
                log.debug("PING sent")
            except Exception as e:
                log.error(f"Keepalive failed: {e}")
                break

    def shutdown(self) -> None:
        """Clean shutdown — stop writer, send QUIT, close SSH"""
        self._running = False

        # Stop the writer first — drain remaining frames
        if self._writer:
            # Can't await in sync context — schedule and give it a moment
            loop = self._loop
            if loop and loop.is_running():
                import concurrent.futures
                future = asyncio.run_coroutine_threadsafe(self._writer.stop(), loop)
                try:
                    future.result(timeout=3.0)
                except (concurrent.futures.TimeoutError, Exception):
                    pass

            # Send QUIT directly — writer is stopped
            self._writer.send_sync(build_quit())
        else:
            try:
                if self._channel:
                    self._channel.sendall(build_quit().encode())
            except Exception:
                pass

        try:
            if self._ssh_client:
                self._ssh_client.disconnect()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# UDP SNMP listener — one per target mapping
# ---------------------------------------------------------------------------

class SNMPListener:
    """
    Real UDP listener on a local port. Receives raw SNMP PDUs from any
    tool (snmpwalk, snmpget, LibreNMS, trafikwatch), relays through
    SSH tunnel, returns response to the caller. Fully transparent.
    """

    def __init__(self, mapping: TargetMapping, tunnel: SSHTunnel, bind: str):
        self.mapping = mapping
        self.tunnel = tunnel
        self.bind = bind
        self._transport: Optional[asyncio.DatagramTransport] = None

    async def start(self, loop: asyncio.AbstractEventLoop) -> None:
        class Protocol(asyncio.DatagramProtocol):
            def __init__(self, listener: SNMPListener):
                self.listener = listener

            def connection_made(self, transport):
                self.listener._transport = transport

            def datagram_received(self, data, addr):
                asyncio.ensure_future(self.listener._handle(data, addr))

            def error_received(self, exc):
                log.warning(f"UDP error on :{self.listener.mapping.local_port}: {exc}")

        await loop.create_datagram_endpoint(
            lambda: Protocol(self),
            local_addr=(self.bind, self.mapping.local_port),
        )

    async def _handle(self, pdu: bytes, client_addr: tuple) -> None:
        t0 = time.monotonic()
        try:
            response = await self.tunnel.send_request(
                self.mapping.remote_host,
                self.mapping.remote_port,
                pdu,
            )
            elapsed = (time.monotonic() - t0) * 1000
            if self._transport and response:
                self._transport.sendto(response, client_addr)
                log.debug(
                    f":{self.mapping.local_port} → {self.mapping.display}: "
                    f"{len(pdu)}B → {len(response)}B → {client_addr}"
                )
                trace.info(
                    f"UDP :{self.mapping.local_port} {self.mapping.display}  "
                    f"{len(pdu)}B → {len(response)}B  {elapsed:.1f}ms"
                )
        except TimeoutError:
            elapsed = (time.monotonic() - t0) * 1000
            log.warning(f":{self.mapping.local_port} → {self.mapping.display}: timeout")
            trace.info(
                f"UDP :{self.mapping.local_port} {self.mapping.display}  "
                f"TIMEOUT  {elapsed:.1f}ms"
            )
        except Exception as e:
            elapsed = (time.monotonic() - t0) * 1000
            log.error(f":{self.mapping.local_port} → {self.mapping.display}: {e}")
            trace.info(
                f"UDP :{self.mapping.local_port} {self.mapping.display}  "
                f"ERR {e}  {elapsed:.1f}ms"
            )


# ---------------------------------------------------------------------------
# Dynamic Target Registry
# ---------------------------------------------------------------------------

@dataclass
class RegisteredTarget:
    """A tracked SNMP target (seed or dynamically registered)"""
    mapping: TargetMapping
    listener: Optional[SNMPListener] = None
    registered_at: float = 0.0
    last_activity: float = 0.0
    request_count: int = 0
    source: str = "api"          # "config" for YAML seeds, "api" for dynamic


class TargetRegistry:
    """
    Manages port allocation, dedup, and hot-add of UDP listeners.

    Used by the REST API to register targets at runtime. YAML seed
    targets are also loaded through here for a unified view.

    Port allocation auto-increments from base_port, skipping any
    ports already claimed by YAML seeds.
    """

    def __init__(
        self,
        tunnel: SSHTunnel,
        bind_address: str = "127.0.0.1",
        base_port: int = 10001,
        max_targets: int = 2000,
    ):
        self.tunnel = tunnel
        self.bind_address = bind_address
        self._base_port = base_port
        self._max_targets = max_targets
        self._next_port = base_port

        # Primary index: "host:port" → RegisteredTarget
        self._targets: dict[str, RegisteredTarget] = {}
        # Secondary index: local_port → remote key
        self._port_index: dict[int, str] = {}

        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._lock = asyncio.Lock()

    @property
    def count(self) -> int:
        return len(self._targets)

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def _make_key(self, host: str, port: int = 161) -> str:
        return f"{host}:{port}"

    def _allocate_port(self) -> int:
        """Allocate next available local port, skipping any in use"""
        while self._next_port in self._port_index:
            self._next_port += 1
            if self._next_port > self._base_port + self._max_targets:
                raise RuntimeError("Port pool exhausted")
        port = self._next_port
        self._next_port += 1
        return port

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    async def register(
        self,
        remote_host: str,
        remote_port: int = 161,
        label: str = "",
        source: str = "api",
    ) -> RegisteredTarget:
        """
        Register a target. Idempotent — returns existing if already mapped.
        Creates and starts a UDP listener immediately.
        """
        key = self._make_key(remote_host, remote_port)

        async with self._lock:
            # Dedup — return existing
            if key in self._targets:
                log.debug(f"Already registered: {key} → :{self._targets[key].mapping.local_port}")
                return self._targets[key]

            if self.count >= self._max_targets:
                raise RuntimeError(f"Max targets ({self._max_targets}) reached")

            local_port = self._allocate_port()
            mapping = TargetMapping(
                local_port=local_port,
                remote_host=remote_host,
                remote_port=remote_port,
                label=label or f"{remote_host}:{remote_port}",
            )

            listener = SNMPListener(mapping, self.tunnel, self.bind_address)
            if self._loop:
                await listener.start(self._loop)

            now = time.monotonic()
            entry = RegisteredTarget(
                mapping=mapping,
                listener=listener,
                registered_at=now,
                last_activity=now,
                source=source,
            )

            self._targets[key] = entry
            self._port_index[local_port] = key

            log.info(
                f"Registered: {self.bind_address}:{local_port} → "
                f"{remote_host}:{remote_port}  [{source}]"
            )
            return entry

    async def unregister(self, remote_host: str, remote_port: int = 161) -> bool:
        """Remove a target and close its UDP listener"""
        key = self._make_key(remote_host, remote_port)

        async with self._lock:
            entry = self._targets.pop(key, None)
            if not entry:
                return False

            self._port_index.pop(entry.mapping.local_port, None)
            if entry.listener and entry.listener._transport:
                entry.listener._transport.close()

            log.info(f"Unregistered: {key} (was :{entry.mapping.local_port})")
            return True

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def lookup(self, remote_host: str, remote_port: int = 161) -> Optional[RegisteredTarget]:
        return self._targets.get(self._make_key(remote_host, remote_port))

    def list_all(self) -> list[RegisteredTarget]:
        return sorted(self._targets.values(), key=lambda t: t.mapping.local_port)

    # ------------------------------------------------------------------
    # Seed from YAML config
    # ------------------------------------------------------------------

    async def seed_from_config(self, config: ProxyConfig) -> None:
        """Load YAML targets as seed entries with their specified ports"""
        for t in config.targets:
            key = self._make_key(t.remote_host, t.remote_port)

            async with self._lock:
                if key in self._targets:
                    continue

                listener = SNMPListener(t, self.tunnel, self.bind_address)
                if self._loop:
                    await listener.start(self._loop)

                now = time.monotonic()
                entry = RegisteredTarget(
                    mapping=t,
                    listener=listener,
                    registered_at=now,
                    last_activity=now,
                    source="config",
                )
                self._targets[key] = entry
                self._port_index[t.local_port] = key

                # Keep auto-allocator above any YAML-specified ports
                if t.local_port >= self._next_port:
                    self._next_port = t.local_port + 1

            log.info(
                f"Seed: {self.bind_address}:{t.local_port} → "
                f"{t.remote_host}:{t.remote_port}"
            )

    # ------------------------------------------------------------------
    # Housekeeping
    # ------------------------------------------------------------------

    async def reap_idle(self, max_idle_seconds: float = 3600.0) -> int:
        """Remove API-registered targets idle > max_idle_seconds. Seeds are never reaped."""
        now = time.monotonic()
        to_remove = [
            (e.mapping.remote_host, e.mapping.remote_port)
            for e in self._targets.values()
            if e.source != "config" and now - e.last_activity > max_idle_seconds
        ]
        for host, port in to_remove:
            await self.unregister(host, port)
        if to_remove:
            log.info(f"Reaped {len(to_remove)} idle targets")
        return len(to_remove)


# ---------------------------------------------------------------------------
# REST API — aiohttp (only imported when --api is used)
# ---------------------------------------------------------------------------

class ProxyAPI:
    """
    Lightweight REST API for dynamic target management.
    Localhost only — no auth needed (same security model as the proxy itself).

    Endpoints:
      POST   /targets              Register a target → get local port
      GET    /targets              List all active mappings
      GET    /targets/{host}       Lookup specific target
      DELETE /targets/{host}       Remove a target
      GET    /health               Tunnel + proxy health check
    """

    def __init__(
        self,
        registry: TargetRegistry,
        api_host: str = "127.0.0.1",
        api_port: int = 8901,
    ):
        self.registry = registry
        self.api_host = api_host
        self.api_port = api_port
        self._runner = None

    async def start(self) -> None:
        from aiohttp import web

        app = web.Application()
        app.router.add_post("/targets", self._handle_register)
        app.router.add_get("/targets", self._handle_list)
        app.router.add_get("/targets/{host}", self._handle_lookup)
        app.router.add_delete("/targets/{host}", self._handle_delete)
        app.router.add_get("/health", self._handle_health)

        self._runner = web.AppRunner(app, access_log=None)
        await self._runner.setup()

        site = web.TCPSite(self._runner, self.api_host, self.api_port)
        await site.start()
        log.info(f"API listening on {self.api_host}:{self.api_port}")

    async def stop(self) -> None:
        if self._runner:
            await self._runner.cleanup()

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    @staticmethod
    def _to_dict(entry: RegisteredTarget) -> dict:
        return {
            "local_port": entry.mapping.local_port,
            "remote_host": entry.mapping.remote_host,
            "remote_port": entry.mapping.remote_port,
            "label": entry.mapping.label,
            "source": entry.source,
            "request_count": entry.request_count,
        }

    # ------------------------------------------------------------------
    # Handlers
    # ------------------------------------------------------------------

    async def _handle_register(self, request) -> "web.Response":
        """
        POST /targets
        {"remote_host": "10.2.1.18", "remote_port": 161, "label": "spine1"}

        201 Created  → new target
        200 OK       → already existed (idempotent)
        """
        from aiohttp import web

        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON"}, status=400)

        remote_host = body.get("remote_host", "").strip()
        if not remote_host:
            return web.json_response({"error": "remote_host is required"}, status=400)

        remote_port = int(body.get("remote_port", 161))
        label = body.get("label", "")

        existing = self.registry.lookup(remote_host, remote_port)

        try:
            entry = await self.registry.register(
                remote_host=remote_host,
                remote_port=remote_port,
                label=label,
            )
        except RuntimeError as e:
            return web.json_response({"error": str(e)}, status=503)

        status = 200 if existing else 201
        return web.json_response(self._to_dict(entry), status=status)

    async def _handle_list(self, request) -> "web.Response":
        """GET /targets  — optional ?source=api|config filter"""
        from aiohttp import web

        source_filter = request.query.get("source")
        targets = self.registry.list_all()
        if source_filter:
            targets = [t for t in targets if t.source == source_filter]

        return web.json_response({
            "count": len(targets),
            "targets": [self._to_dict(t) for t in targets],
        })

    async def _handle_lookup(self, request) -> "web.Response":
        """GET /targets/{host}?port=161"""
        from aiohttp import web

        host = request.match_info["host"]
        port = int(request.query.get("port", 161))

        entry = self.registry.lookup(host, port)
        if not entry:
            return web.json_response({"error": f"No mapping for {host}:{port}"}, status=404)

        return web.json_response(self._to_dict(entry))

    async def _handle_delete(self, request) -> "web.Response":
        """DELETE /targets/{host}?port=161"""
        from aiohttp import web

        host = request.match_info["host"]
        port = int(request.query.get("port", 161))

        entry = self.registry.lookup(host, port)
        if not entry:
            return web.json_response({"error": f"No mapping for {host}:{port}"}, status=404)

        removed = await self.registry.unregister(host, port)
        return web.json_response({"removed": removed, "remote_host": host, "remote_port": port})

    async def _handle_health(self, request) -> "web.Response":
        """GET /health — tunnel status + target count + writer stats"""
        from aiohttp import web

        tunnel = self.registry.tunnel
        tunnel_ok = (
            tunnel._channel is not None
            and tunnel._channel.get_transport() is not None
            and tunnel._channel.get_transport().is_active()
        )

        health = {
            "status": "ok" if tunnel_ok else "degraded",
            "tunnel_active": tunnel_ok,
            "target_count": self.registry.count,
        }

        # Writer metrics — critical for diagnosing throughput issues
        if tunnel._writer:
            w = tunnel._writer
            health["writer"] = {
                "queue_depth": w._queue.qsize(),
                "high_water_mark": w.high_water_mark,
                "frames_queued": w.frames_queued,
                "frames_written": w.frames_written,
                "batches_written": w.batches_written,
                "bytes_written": w.bytes_written,
                "coalesced_frames": w.coalesced_count,
            }

        return web.json_response(health)


# ---------------------------------------------------------------------------
# Run modes
# ---------------------------------------------------------------------------

async def run(cfg: ProxyConfig) -> None:
    """Original static mode — targets from YAML only"""
    if not cfg.targets:
        log.error("No targets defined in config (use --api for dynamic mode)")
        sys.exit(1)

    tunnel = SSHTunnel(cfg)

    try:
        tunnel.connect()
    except Exception as e:
        log.error(f"Connection failed: {e}")
        sys.exit(1)

    loop = asyncio.get_running_loop()
    tunnel.start_reader(loop)

    print(f"\n  snmpproxy — {len(cfg.targets)} targets via {cfg.ssh.host}")
    print()

    for mapping in cfg.targets:
        listener = SNMPListener(mapping, tunnel, cfg.bind_address)
        await listener.start(loop)
        print(
            f"    {cfg.bind_address}:{mapping.local_port:<6} → "
            f"{mapping.remote_addr:<21}  {mapping.display}"
        )

    print(f"\n  Ready. Use any SNMP tool against localhost.\n")

    keepalive_task = asyncio.create_task(tunnel.keepalive_loop())

    stop = asyncio.Event()
    loop.add_signal_handler(signal.SIGINT, stop.set)
    loop.add_signal_handler(signal.SIGTERM, stop.set)

    try:
        await stop.wait()
    finally:
        print("\n  Shutting down...")
        keepalive_task.cancel()
        tunnel.shutdown()


async def run_with_api(
    cfg: ProxyConfig,
    api_port: int = 8901,
    base_port: int = 10001,
) -> None:
    """
    Dynamic mode — REST API for runtime target registration.

    YAML targets (if any) are loaded as seeds. New targets are
    registered via POST /targets and get auto-allocated ports.
    """
    tunnel = SSHTunnel(cfg)

    try:
        tunnel.connect()
    except Exception as e:
        log.error(f"Connection failed: {e}")
        sys.exit(1)

    loop = asyncio.get_running_loop()
    tunnel.start_reader(loop)

    # ── Registry: unified target management ──
    registry = TargetRegistry(
        tunnel=tunnel,
        bind_address=cfg.bind_address,
        base_port=base_port,
    )
    registry.set_loop(loop)

    # Load YAML seeds through the registry
    if cfg.targets:
        await registry.seed_from_config(cfg)

    print(f"\n  snmpproxy — dynamic mode via {cfg.ssh.host}")

    if cfg.targets:
        print(f"  Seed targets: {len(cfg.targets)}")
        print()
        for entry in registry.list_all():
            m = entry.mapping
            print(
                f"    {cfg.bind_address}:{m.local_port:<6} → "
                f"{m.remote_addr:<21}  {m.display}  [seed]"
            )
    else:
        print(f"  No seed targets — register via API")

    # ── API server ──
    api = ProxyAPI(registry, api_port=api_port)
    await api.start()

    print(f"\n  API:   http://127.0.0.1:{api_port}/targets")
    print(f"  Ready. Register new targets dynamically.\n")

    # ── Background tasks ──
    keepalive_task = asyncio.create_task(tunnel.keepalive_loop())

    # Optional idle reaper — check every 5 min, reap after 1 hour
    async def _reaper():
        while True:
            await asyncio.sleep(300)
            try:
                await registry.reap_idle(3600.0)
            except Exception as e:
                log.error(f"Reaper error: {e}")

    reaper_task = asyncio.create_task(_reaper())

    # ── Wait for shutdown ──
    stop = asyncio.Event()
    loop.add_signal_handler(signal.SIGINT, stop.set)
    loop.add_signal_handler(signal.SIGTERM, stop.set)

    try:
        await stop.wait()
    finally:
        print("\n  Shutting down...")
        keepalive_task.cancel()
        reaper_task.cancel()
        await api.stop()
        tunnel.shutdown()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="snmpproxy — transparent SNMP over SSH",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example (static):
  python3 snmpproxy_local.py -c snmpproxy.yaml

Example (dynamic):
  python3 snmpproxy_local.py -c snmpproxy.yaml --api
  curl -X POST http://127.0.0.1:8901/targets \\
       -d '{"remote_host": "10.2.1.42"}'

Then:
  snmpwalk -v2c -c public localhost:10001 1.3.6.1.2.1.1
        """,
    )
    parser.add_argument("-c", "--config", default="snmpproxy.yaml")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="debug logging (noisy)")
    parser.add_argument("-t", "--trace", action="store_true",
                        help="show protocol messages with RTT timing")
    parser.add_argument("-q", "--quiet", action="store_true")

    # Dynamic API options
    parser.add_argument("--api", action="store_true",
                        help="enable REST API for dynamic target registration")
    parser.add_argument("--api-port", type=int, default=8901,
                        help="API listen port (default: 8901)")
    parser.add_argument("--base-port", type=int, default=10001,
                        help="base port for auto-allocated targets (default: 10001)")

    args = parser.parse_args()

    if args.verbose:
        level = logging.DEBUG
    elif args.quiet:
        level = logging.ERROR
    else:
        level = logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s.%(msecs)03d %(name)-16s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )
    if not args.verbose:
        logging.getLogger("paramiko").setLevel(logging.WARNING)

    # Trace logger: protocol messages + RTT timing
    # Enabled by --trace (or --verbose which shows everything)
    if args.trace or args.verbose:
        trace.setLevel(logging.INFO)
    else:
        trace.setLevel(logging.WARNING)

    try:
        cfg = load_config(args.config)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.api:
        asyncio.run(run_with_api(cfg, api_port=args.api_port, base_port=args.base_port))
    else:
        asyncio.run(run(cfg))


if __name__ == "__main__":
    main()