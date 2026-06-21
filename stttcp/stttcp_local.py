#!/usr/bin/env python3
"""
stttcp_local.py — Local transparent TCP-over-SSH proxy

Creates real TCP listeners on localhost. Any tool can connect to
localhost:{port} and the connection is transparently relayed through
an SSH terminal session to the actual host on the remote network.

Routing: port-mapped — each remote target gets a unique local port.

This works even when the SSH server has AllowTcpForwarding disabled.
The data rides an invoke-shell session as framed text — the server
has no idea structured traffic is being carried.

Security posture:
  - No listening ports on the remote network
  - No root/elevated privileges required
  - No daemon or install on the jumpbox (just a python script)
  - All traffic rides an existing SSH session
  - User-level access only
  - Bypasses AllowTcpForwarding=no (feature, not a bug)

Usage:
  python3 stttcp_local.py -c stttcp.yaml
  python3 stttcp_local.py -c stttcp.yaml --trace

Then from any tool:
  curl http://localhost:18080/api/v1/status
  ssh -p 12222 localhost
  psql -h localhost -p 15432 mydb
  redis-cli -p 16379

Requires: paramiko, pyyaml
SSH client: Uses SCNG SSHClient (scng/discovery/ssh/client.py)
"""

from __future__ import annotations

from stttcp.socks5 import Socks5Listener

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
from stttcp.ssh_client import SSHClient, SSHClientConfig

from stttcp.stttcp_protocol import (
    FrameReader,
    OpenRequest,
    Opened,
    OpenError,
    Data,
    Close,
    MsgType,
    DATA_CHUNK_SIZE,
    build_open,
    build_data,
    build_close,
    build_ping,
    build_quit,
    chunk_data,
)

log = logging.getLogger("stttcp")
trace = logging.getLogger("stttcp.trace")


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
    remote_agent: str = "/opt/stttcp/stttcp_remote.py"
    remote_log: str = ""       # stderr redirect on jumpbox (default: /tmp/stttcp_agent.log)
    legacy_mode: bool = False
    connect_timeout: int = 120
    shell_timeout: float = 5.0


@dataclass
class TargetMapping:
    local_port: int = 0
    remote_host: str = ""
    remote_port: int = 0
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
    connect_timeout: float = 15.0
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
        remote_agent=ssh.get("remote_agent", "/opt/stttcp/stttcp_remote.py"),
        remote_log=ssh.get("remote_log", ""),
        legacy_mode=ssh.get("legacy_mode", False),
        connect_timeout=int(ssh.get("connect_timeout", 30)),
        shell_timeout=float(ssh.get("shell_timeout", 5.0)),
    )

    cfg.bind_address = raw.get("bind_address", "127.0.0.1")
    cfg.connect_timeout = float(raw.get("connect_timeout", 15))
    cfg.keepalive_interval = float(raw.get("keepalive_interval", 30))

    for t in raw.get("targets", []):
        cfg.targets.append(TargetMapping(
            local_port=int(t["local_port"]),
            remote_host=t["remote_host"],
            remote_port=int(t["remote_port"]),
            label=t.get("label", ""),
        ))

    if not cfg.ssh.host:
        raise ValueError("ssh.host is required")
    if not cfg.targets:
        raise ValueError("At least one target mapping is required")

    return cfg


# ---------------------------------------------------------------------------
# Serialized channel writer — eliminates frame interleaving
# ---------------------------------------------------------------------------

class ChannelWriter:
    """
    Serialized, coalescing write queue for the SSH channel.

    Problem: Multiple concurrent TCP streams calling channel.sendall()
    can interleave frames on the wire. This is MORE critical for TCP
    than SNMP because interleaved DATA frames corrupt byte streams,
    not just individual request/response pairs.

    Solution: Single drain loop owns all writes. Callers enqueue frames
    via send() and the drain loop coalesces queued frames into single
    sendall() calls.

    The writer is NOT used during the handshake phase (connect/PING/PONG)
    because the event loop isn't running yet.
    """

    def __init__(self, channel, max_batch_bytes: int = 16384):
        self._channel = channel
        self._queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._max_batch = max_batch_bytes
        self._task: Optional[asyncio.Task] = None
        self._running = False

        # Metrics
        self.frames_queued = 0
        self.frames_written = 0
        self.batches_written = 0
        self.bytes_written = 0
        self.coalesced_count = 0
        self.high_water_mark = 0

    def start(self) -> None:
        """Start the drain loop. Call from the asyncio event loop thread."""
        self._running = True
        self._task = asyncio.ensure_future(self._drain_loop())
        log.debug("ChannelWriter started")

    async def send(self, frame: str) -> None:
        """Enqueue a framed message for writing."""
        data = frame.encode()
        await self._queue.put(data)
        self.frames_queued += 1

        qsize = self._queue.qsize()
        if qsize > self.high_water_mark:
            self.high_water_mark = qsize
        if qsize > 40:
            log.warning(f"Write queue depth: {qsize} (high water: {self.high_water_mark})")

    async def _drain_loop(self) -> None:
        """Single writer coroutine. Drains, coalesces, writes atomically."""
        loop = asyncio.get_running_loop()

        while self._running:
            try:
                batch = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

            frames_in_batch = 1

            while not self._queue.empty() and len(batch) < self._max_batch:
                try:
                    batch += self._queue.get_nowait()
                    frames_in_batch += 1
                except asyncio.QueueEmpty:
                    break

            if frames_in_batch > 1:
                self.coalesced_count += frames_in_batch
                log.debug(f"Coalesced {frames_in_batch} frames into {len(batch)}B batch")

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
    switches the channel to raw framed protocol mode for TCP relay.

    Boot sequence:
      1. SSHClient.connect()       → invoke-shell, drain banner
      2. SSHClient.find_prompt()   → confirm shell is ready
      3. stty raw -echo            → disable pty echo + canonical mode
      4. exec python3 -u ...       → start agent (replaces shell)
      5. FrameReader: PING/PONG    → handshake, drain boot noise
      6. ChannelWriter + reader    → protocol is live
    """

    def __init__(self, cfg: ProxyConfig):
        self.cfg = cfg
        self._ssh_client: Optional[SSHClient] = None
        self._channel = None
        self._reader_thread: Optional[threading.Thread] = None
        self._running = False

        # Serialized writer — initialized after channel is established
        self._writer: Optional[ChannelWriter] = None

        # Stream management
        # stream_id → StreamContext (holds asyncio reader/writer or transport)
        self._streams: dict[str, "StreamContext"] = {}
        self._stream_lock = threading.Lock()

        # Pending OPEN requests: stream_id → asyncio.Future[bool]
        self._pending_opens: dict[str, asyncio.Future] = {}
        self._pending_lock = threading.Lock()
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        # Stream ID counter
        self._stream_counter = 0
        self._id_lock = threading.Lock()

    def next_stream_id(self) -> str:
        with self._id_lock:
            self._stream_counter += 1
            return f"{self._stream_counter:06d}"

    def connect(self) -> None:
        """Connect via SCNG SSHClient, launch remote agent, handshake."""
        ssh_cfg = self.cfg.ssh

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
        self._channel = self._ssh_client._shell
        if not self._channel:
            raise ConnectionError("SSHClient shell channel not available")

        # ── Phase 3.5 + 4: Raw mode + launch agent (single command) ──
        # These MUST be a single shell command. If we send "stty raw"
        # first and then the agent command separately, bash is already
        # in raw mode when it tries to read the second command — line
        # discipline is off, \n doesn't terminate input, and bash
        # can't parse it. Result: "-bash: : command not found".
        #
        # By combining them with ";", bash parses the whole line in
        # cooked mode, executes stty raw -echo, then exec replaces bash
        # with the agent process. The agent inherits the raw PTY.
        # exec also eliminates the idle bash parent process.
        #
        # -echo is explicit because stty raw alone doesn't suppress
        # echo on all systems. On Debian 11 (and others), raw mode
        # leaves echo enabled — echoed frames corrupt bidirectional
        # protocols by feeding sent data back as received data.
        #
        # CRITICAL: stderr redirect (2>). In a PTY, stderr shares the
        # same fd as stdout. Under load with multiple TCP streams,
        # agent log lines can splice into the middle of DATA frames,
        # corrupting the base64 payload. Redirect preserves the logs
        # on the jumpbox while keeping the protocol stream clean.
        remote_log = ssh_cfg.remote_log or "/tmp/stttcp_agent.log"
        agent_cmd = (
            f"stty raw -echo; "
            f"exec {ssh_cfg.remote_python} -u {ssh_cfg.remote_agent} "
            f"2>{remote_log}\n"
        )
        log.info(f"Starting remote agent: {agent_cmd.strip()}")
        log.info(f"Remote agent log: {remote_log}")
        self._channel.sendall(agent_cmd.encode())

        time.sleep(0.5)

        # ── Phase 5: Handshake — PING/PONG through FrameReader ──
        log.debug("Sending PING for handshake...")
        self._channel.sendall(build_ping().encode())

        self._wait_for_pong()
        log.info("Remote agent ready — handshake complete")

    def _wait_for_pong(self, timeout: float = 20.0) -> None:
        """Feed channel output through FrameReader until PONG arrives."""
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
        """Background thread: read from SSH, feed FrameReader, dispatch"""
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
                    if isinstance(msg, Opened):
                        self._handle_opened(msg)
                    elif isinstance(msg, OpenError):
                        self._handle_open_error(msg)
                    elif isinstance(msg, Data):
                        self._handle_data(msg)
                    elif isinstance(msg, Close):
                        self._handle_close(msg)
                    elif msg == MsgType.PONG:
                        log.debug("PONG received (keepalive)")
                    else:
                        log.debug(f"Unexpected message in reader: {msg}")

        except Exception as e:
            log.error(f"Reader thread crashed: {e}")
        finally:
            log.debug("SSH reader thread exiting")
            self._fail_all_pending("SSH tunnel closed")
            self._close_all_streams("SSH tunnel closed")

    def _handle_opened(self, msg: Opened) -> None:
        """Remote agent confirmed TCP connection"""
        trace.info(f"RX  OPENED {msg.stream_id}")
        with self._pending_lock:
            future = self._pending_opens.pop(msg.stream_id, None)
        if future and self._loop:
            self._loop.call_soon_threadsafe(future.set_result, True)

    def _handle_open_error(self, msg: OpenError) -> None:
        """Remote agent failed to connect"""
        trace.info(f"RX  OPEN_ERR {msg.stream_id} {msg.error}")
        with self._pending_lock:
            future = self._pending_opens.pop(msg.stream_id, None)
        if future and self._loop:
            self._loop.call_soon_threadsafe(
                future.set_exception,
                ConnectionError(f"Remote connect failed: {msg.error}")
            )

    def _handle_data(self, msg: Data) -> None:
        """Data arrived from remote TCP target — forward to local client"""
        with self._stream_lock:
            ctx = self._streams.get(msg.stream_id)

        if not ctx:
            log.debug(f"{msg.stream_id}: DATA for unknown stream")
            return

        trace.info(
            f"RX  DATA {msg.stream_id} {len(msg.payload)}B"
        )

        if self._loop and ctx.transport and not ctx.transport.is_closing():
            self._loop.call_soon_threadsafe(ctx.transport.write, msg.payload)

    def _handle_close(self, msg: Close) -> None:
        """Remote side closed the stream"""
        trace.info(f"RX  CLOSE {msg.stream_id}")
        with self._stream_lock:
            ctx = self._streams.pop(msg.stream_id, None)

        if ctx and self._loop and ctx.transport and not ctx.transport.is_closing():
            self._loop.call_soon_threadsafe(ctx.transport.close)

    def _fail_all_pending(self, reason: str) -> None:
        """Fail all pending OPEN requests"""
        with self._pending_lock:
            for sid, fut in self._pending_opens.items():
                if not fut.done() and self._loop:
                    self._loop.call_soon_threadsafe(
                        fut.set_exception,
                        ConnectionError(reason),
                    )
            self._pending_opens.clear()

    def _close_all_streams(self, reason: str) -> None:
        """Close all active streams"""
        with self._stream_lock:
            for sid, ctx in self._streams.items():
                if ctx.transport and not ctx.transport.is_closing() and self._loop:
                    self._loop.call_soon_threadsafe(ctx.transport.close)
            self._streams.clear()

    # ------------------------------------------------------------------
    # Stream API — used by TCP listeners
    # ------------------------------------------------------------------

    async def open_stream(
        self, remote_host: str, remote_port: int,
        transport: asyncio.Transport,
    ) -> str:
        """
        Open a TCP stream through the tunnel.
        Returns the stream_id on success.
        Raises ConnectionError on failure.
        """
        if not self._writer:
            raise ConnectionError("Writer not started — call start_reader() first")

        stream_id = self.next_stream_id()
        msg = build_open(stream_id, remote_host, remote_port)

        loop = asyncio.get_running_loop()
        future = loop.create_future()

        # Register the stream context
        ctx = StreamContext(
            stream_id=stream_id,
            remote_host=remote_host,
            remote_port=remote_port,
            transport=transport,
        )

        with self._stream_lock:
            self._streams[stream_id] = ctx
        with self._pending_lock:
            self._pending_opens[stream_id] = future

        try:
            # Enqueue through serialized writer — never interleaves
            await self._writer.send(msg)
            trace.info(f"TX  OPEN {stream_id} → {remote_host}:{remote_port}")
        except Exception as e:
            with self._stream_lock:
                self._streams.pop(stream_id, None)
            with self._pending_lock:
                self._pending_opens.pop(stream_id, None)
            raise ConnectionError(f"SSH write failed: {e}")

        try:
            await asyncio.wait_for(future, timeout=self.cfg.connect_timeout)
            return stream_id
        except asyncio.TimeoutError:
            with self._stream_lock:
                self._streams.pop(stream_id, None)
            with self._pending_lock:
                self._pending_opens.pop(stream_id, None)
            raise ConnectionError(
                f"OPEN {stream_id} to {remote_host}:{remote_port} "
                f"timed out after {self.cfg.connect_timeout}s"
            )

    async def send_data(self, stream_id: str, data: bytes) -> None:
        """Send data through the tunnel for a stream (called from asyncio)"""
        if not self._writer:
            log.error(f"{stream_id}: Writer not started")
            return

        try:
            if len(data) <= DATA_CHUNK_SIZE:
                msg = build_data(stream_id, data)
                await self._writer.send(msg)
                trace.info(f"TX  DATA {stream_id} {len(data)}B")
            else:
                frames = chunk_data(stream_id, data)
                for frame in frames:
                    await self._writer.send(frame)
                trace.info(
                    f"TX  DATA {stream_id} {len(data)}B ({len(frames)} chunks)"
                )
        except Exception as e:
            log.error(f"{stream_id}: SSH write failed: {e}")
            self.close_stream(stream_id)

    async def close_stream(self, stream_id: str) -> None:
        """Close a stream — send CLOSE to remote, clean up locally"""
        with self._stream_lock:
            ctx = self._streams.pop(stream_id, None)

        if ctx and self._writer:
            try:
                await self._writer.send(build_close(stream_id))
                trace.info(f"TX  CLOSE {stream_id}")
            except Exception:
                pass

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
# Stream context — tracks one TCP stream
# ---------------------------------------------------------------------------

@dataclass
class StreamContext:
    stream_id: str
    remote_host: str
    remote_port: int
    transport: Optional[asyncio.Transport] = None


# ---------------------------------------------------------------------------
# TCP listener — one per target mapping
# ---------------------------------------------------------------------------

class TCPListener:
    """
    Real TCP listener on a local port. Each incoming connection opens
    a remote TCP stream through the SSH tunnel. Data flows bidirectionally
    until either side closes.

    Fully transparent — any TCP-based tool works:
      curl, ssh, psql, redis-cli, mysql, REST clients, browsers, etc.
    """

    def __init__(self, mapping: TargetMapping, tunnel: SSHTunnel, bind: str):
        self.mapping = mapping
        self.tunnel = tunnel
        self.bind = bind
        self._server: Optional[asyncio.AbstractServer] = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client,
            host=self.bind,
            port=self.mapping.local_port,
        )

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a single TCP client connection"""
        client_addr = writer.get_extra_info("peername")
        transport = writer.transport

        log.info(
            f":{self.mapping.local_port} ← {client_addr} → "
            f"{self.mapping.display}"
        )

        # Open remote TCP stream through tunnel
        try:
            stream_id = await self.tunnel.open_stream(
                self.mapping.remote_host,
                self.mapping.remote_port,
                transport,
            )
        except Exception as e:
            log.error(
                f":{self.mapping.local_port} → {self.mapping.display}: "
                f"OPEN failed: {e}"
            )
            writer.close()
            return

        log.debug(f":{self.mapping.local_port} stream {stream_id} established")

        # Forward local client data → tunnel
        try:
            while True:
                data = await reader.read(DATA_CHUNK_SIZE)
                if not data:
                    break
                await self.tunnel.send_data(stream_id, data)
        except (ConnectionError, asyncio.CancelledError):
            pass
        except Exception as e:
            log.debug(f"{stream_id}: client read error: {e}")
        finally:
            await self.tunnel.close_stream(stream_id)
            writer.close()
            log.info(f":{self.mapping.local_port} stream {stream_id} closed")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def run(cfg: ProxyConfig, socks_port: Optional[int] = None) -> None:
    tunnel = SSHTunnel(cfg)

    try:
        tunnel.connect()
    except Exception as e:
        log.error(f"Connection failed: {e}")
        sys.exit(1)

    loop = asyncio.get_running_loop()
    tunnel.start_reader(loop)

    print(f"\n  stttcp — via {cfg.ssh.host}")
    print()

    # SOCKS5 mode: one dynamic listener reaches any host:port the
    # client asks for, resolved on the remote side. Coexists with the
    # static map — both share the same tunnel.
    if socks_port is not None:
        socks = Socks5Listener(tunnel, cfg.bind_address, socks_port)
        await socks.start()
        print(
            f"    {cfg.bind_address}:{socks_port:<6} → SOCKS5 "
            f"(dynamic, remote DNS)"
        )

    for mapping in cfg.targets:
        listener = TCPListener(mapping, tunnel, cfg.bind_address)
        await listener.start()
        print(
            f"    {cfg.bind_address}:{mapping.local_port:<6} → "
            f"{mapping.remote_addr:<21}  {mapping.display}"
        )

    if socks_port is not None:
        print(
            f"\n  Ready. SOCKS5 on {cfg.bind_address}:{socks_port} "
            f"(set browser socks_remote_dns=true).\n"
        )
    else:
        print(f"\n  Ready. Any TCP tool can connect to localhost.\n")

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


def main() -> None:
    parser = argparse.ArgumentParser(
        description="stttcp — transparent TCP over SSH terminal",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  python3 stttcp_local.py -c stttcp.yaml
  python3 stttcp_local.py -c stttcp.yaml --trace

Then:
  curl http://localhost:18080/api/v1/status
  ssh -p 12222 user@localhost
  psql -h localhost -p 15432 mydb
        """,
    )
    parser.add_argument("-c", "--config", default="stttcp.yaml")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="debug logging (noisy)")
    parser.add_argument("-t", "--trace", action="store_true",
                        help="show protocol messages and stream lifecycle")
    parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument(
        "--socks", nargs="?", const=1080, type=int, default=None,
        metavar="PORT",
        help="run a SOCKS5 proxy (dynamic targets, remote DNS) on PORT "
             "(default 1080) instead of/alongside static maps",
    )

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

    if args.trace or args.verbose:
        trace.setLevel(logging.INFO)
    else:
        trace.setLevel(logging.WARNING)

    try:
        cfg = load_config(args.config)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    asyncio.run(run(cfg, socks_port=args.socks))


if __name__ == "__main__":
    main()