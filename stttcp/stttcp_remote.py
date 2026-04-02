#!/usr/bin/env python3
"""
stttcp_remote.py — Remote TCP relay agent

Reads framed text protocol from stdin, manages TCP connections to
target hosts, relays data bidirectionally through stdout.

Requires: stttcp_protocol.py in the same directory.
No other external dependencies — runs on any jumpbox with Python 3.7+.

Deployment:
  scp stttcp_protocol.py stttcp_remote.py jumpbox:/opt/stttcp/
  # Local proxy then runs: python3 -u /opt/stttcp/stttcp_remote.py

Stream lifecycle:
  1. Local sends OPEN|{stream_id}|{host}:{port}
  2. Agent connects TCP socket to host:port
  3. Agent sends OPENED|{stream_id} (or OPEN_ERR on failure)
  4. Bidirectional DATA frames flow in both directions
  5. Either side sends CLOSE|{stream_id} to tear down
"""

from __future__ import annotations

import errno
import os
import select
import socket
import sys
import time

from stttcp_protocol import (
    FrameReader,
    OpenRequest,
    Data,
    Close,
    MsgType,
    DATA_CHUNK_SIZE,
    build_opened,
    build_open_error,
    build_data,
    build_close,
    build_pong,
)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
TCP_CONNECT_TIMEOUT = 10.0
TCP_RECV_SIZE = 16384              # Match DATA_CHUNK_SIZE
SELECT_TIMEOUT = 0.05              # 50ms — responsive but not busy
MAX_STREAMS = 128                  # Safety limit


def log(msg: str) -> None:
    """Log to stderr — doesn't interfere with stdout protocol"""
    print(f"[stttcp] {msg}", file=sys.stderr, flush=True)


def write(msg: str) -> None:
    """Write a framed message to stdout"""
    sys.stdout.write(msg)
    sys.stdout.flush()


def write_many(msgs: list[str]) -> None:
    """Write multiple framed messages to stdout (batch for efficiency)"""
    sys.stdout.write("".join(msgs))
    sys.stdout.flush()


# ---------------------------------------------------------------------------
# Stream manager
# ---------------------------------------------------------------------------

class StreamManager:
    """
    Manages multiple concurrent TCP connections. Each stream has a
    stream_id (assigned by local side) and a non-blocking TCP socket.

    The main loop select()s across all stream sockets + stdin.
    Data arriving on any TCP socket is framed and written to stdout.
    DATA messages from stdin are written to the corresponding TCP socket.
    """

    def __init__(self):
        self._streams: dict[str, socket.socket] = {}
        # Outbound write buffers — data waiting to be sent to TCP targets.
        # Buffered because non-blocking sends may not accept all data.
        self._write_buffers: dict[str, bytearray] = {}

    @property
    def sockets(self) -> list[socket.socket]:
        """All active TCP sockets (for select)"""
        return list(self._streams.values())

    @property
    def writable_sockets(self) -> list[socket.socket]:
        """Sockets with pending write data"""
        return [
            self._streams[sid]
            for sid, buf in self._write_buffers.items()
            if buf and sid in self._streams
        ]

    def open_stream(self, req: OpenRequest) -> None:
        """
        Open a TCP connection to the remote target.
        Blocking connect with timeout — acceptable because the agent
        is I/O-bound on select() anyway and connections are infrequent.
        """
        if len(self._streams) >= MAX_STREAMS:
            write(build_open_error(
                req.stream_id,
                f"max streams ({MAX_STREAMS}) exceeded"
            ))
            return

        if req.stream_id in self._streams:
            write(build_open_error(req.stream_id, "stream_id already in use"))
            return

        log(f"{req.stream_id}: OPEN → {req.host}:{req.port}")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TCP_CONNECT_TIMEOUT)
            sock.connect((req.host, req.port))
            sock.setblocking(False)
        except Exception as e:
            log(f"{req.stream_id}: OPEN_ERR → {e}")
            write(build_open_error(req.stream_id, str(e)))
            try:
                sock.close()
            except Exception:
                pass
            return

        self._streams[req.stream_id] = sock
        self._write_buffers[req.stream_id] = bytearray()
        log(f"{req.stream_id}: OPENED → {req.host}:{req.port}")
        write(build_opened(req.stream_id))

    def send_data(self, msg: Data) -> None:
        """Queue data for sending to TCP target"""
        if msg.stream_id not in self._streams:
            log(f"{msg.stream_id}: DATA for unknown stream, sending CLOSE")
            write(build_close(msg.stream_id))
            return

        self._write_buffers[msg.stream_id].extend(msg.payload)

    def close_stream(self, stream_id: str, notify: bool = True) -> None:
        """Close and remove a TCP stream"""
        sock = self._streams.pop(stream_id, None)
        self._write_buffers.pop(stream_id, None)

        if sock:
            try:
                sock.close()
            except Exception:
                pass
            log(f"{stream_id}: CLOSED")
            if notify:
                write(build_close(stream_id))

    def poll_reads(self, readable_socks: list) -> None:
        """Read from TCP sockets and write DATA frames to stdout"""
        # Build reverse lookup: socket → stream_id
        sock_to_id = {sock: sid for sid, sock in self._streams.items()}

        for sock in readable_socks:
            sid = sock_to_id.get(sock)
            if not sid:
                continue

            try:
                data = sock.recv(TCP_RECV_SIZE)
            except (BlockingIOError, InterruptedError):
                continue
            except Exception as e:
                log(f"{sid}: recv error: {e}")
                self.close_stream(sid)
                continue

            if not data:
                # TCP connection closed by remote target
                log(f"{sid}: remote target closed connection")
                self.close_stream(sid)
                continue

            # Frame and send — chunk if needed (rare, recv usually < 16KB)
            if len(data) <= DATA_CHUNK_SIZE:
                write(build_data(sid, data))
            else:
                frames = []
                offset = 0
                while offset < len(data):
                    chunk = data[offset:offset + DATA_CHUNK_SIZE]
                    frames.append(build_data(sid, chunk))
                    offset += DATA_CHUNK_SIZE
                write_many(frames)

    def poll_writes(self, writable_socks: list) -> None:
        """Drain write buffers to TCP sockets"""
        sock_to_id = {sock: sid for sid, sock in self._streams.items()}

        for sock in writable_socks:
            sid = sock_to_id.get(sock)
            if not sid or not self._write_buffers.get(sid):
                continue

            buf = self._write_buffers[sid]
            try:
                sent = sock.send(bytes(buf))
                if sent > 0:
                    del buf[:sent]
            except BlockingIOError:
                continue
            except Exception as e:
                log(f"{sid}: send error: {e}")
                self.close_stream(sid)

    def close_all(self) -> None:
        """Shutdown — close all streams"""
        for sid in list(self._streams.keys()):
            self.close_stream(sid, notify=False)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main() -> None:
    log("starting — listening on stdin")
    mgr = StreamManager()
    reader = FrameReader(
        on_noise=lambda s: log(f"noise: {s.strip()[:80]}") if s.strip() else None
    )
    stdin_fd = sys.stdin.fileno()

    try:
        while True:
            # Build select watch lists
            read_watch = [stdin_fd] + mgr.sockets
            write_watch = mgr.writable_sockets

            try:
                readable, writable, _ = select.select(
                    read_watch, write_watch, [], SELECT_TIMEOUT
                )
            except (OSError, ValueError):
                break

            # Drain writable TCP sockets
            if writable:
                mgr.poll_writes(writable)

            # Read from TCP sockets → DATA frames to stdout
            tcp_readable = [s for s in readable
                            if hasattr(s, 'fileno') and s != sys.stdin
                            and s.fileno() != stdin_fd]
            if tcp_readable:
                mgr.poll_reads(tcp_readable)

            # Check stdin for protocol messages
            stdin_ready = any(
                (r.fileno() if hasattr(r, "fileno") else r) == stdin_fd
                for r in readable
            )

            if stdin_ready:
                # Use os.read() — NOT readline(). readline() blocks until
                # \n arrives, which deadlocks the select loop when large
                # DATA frames (e.g., SSH kex at 2500+ chars) are split
                # across multiple PTY writes. os.read() returns whatever
                # is available. The FrameReader handles partial frames.
                try:
                    raw = os.read(stdin_fd, 65536)
                except OSError:
                    break
                if not raw:
                    log("stdin closed, shutting down")
                    break

                for msg in reader.feed(raw.decode("utf-8", errors="replace")):
                    if isinstance(msg, OpenRequest):
                        mgr.open_stream(msg)
                    elif isinstance(msg, Data):
                        mgr.send_data(msg)
                    elif isinstance(msg, Close):
                        mgr.close_stream(msg.stream_id, notify=False)
                    elif msg == MsgType.PING:
                        write(build_pong())
                    elif msg == MsgType.QUIT:
                        log("received QUIT, shutting down")
                        return

    except KeyboardInterrupt:
        log("interrupted")
    finally:
        mgr.close_all()
        log("shutdown complete")


if __name__ == "__main__":
    main()