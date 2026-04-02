"""
snmpproxy_protocol.py — Framed text protocol for SNMP-over-SSH proxy

Wire format:
  ~##~{message_content}~##~

Message types:
  ~##~REQ|{msg_id}|{host}:{port}|{base64_pdu}~##~
  ~##~RSP|{msg_id}|OK|{base64_response}~##~
  ~##~RSP|{msg_id}|ERR|{error_text}~##~
  ~##~RSP|{msg_id}|TIMEOUT|~##~
  ~##~PING~##~
  ~##~PONG~##~
  ~##~QUIT~##~

The sentinel ~##~ never appears in base64, ANSI escapes, or typical
shell output. The reader state machine ignores everything outside
sentinel pairs — terminal echo, prompts, banners, all invisible.

CRITICAL: The transport channel MUST have pty echo disabled before
entering protocol mode. Echoed REQ frames contain valid sentinels
that corrupt in-progress RSP frames in the FrameReader. The local
proxy handles this with 'stty raw -echo' before launching the agent.

This file has ZERO external dependencies and works on Python 3.7+.
Both local and remote sides use identical parsing logic.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Callable


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SENTINEL = "~##~"
SENTINEL_LEN = len(SENTINEL)


class MsgType(str, Enum):
    REQ = "REQ"
    RSP = "RSP"
    PING = "PING"
    PONG = "PONG"
    QUIT = "QUIT"


class RspStatus(str, Enum):
    OK = "OK"
    ERR = "ERR"
    TIMEOUT = "TIMEOUT"


# ---------------------------------------------------------------------------
# Parsed message types
# ---------------------------------------------------------------------------

@dataclass
class Request:
    """Parsed REQ message"""
    msg_id: str
    host: str
    port: int
    pdu: bytes         # decoded from base64


@dataclass
class Response:
    """Parsed RSP message"""
    msg_id: str
    status: RspStatus
    data: bytes = b""     # decoded payload (OK only)
    error: str = ""       # error text (ERR only)


# ---------------------------------------------------------------------------
# Message builders — produce framed strings ready to write
# ---------------------------------------------------------------------------

def frame(content: str) -> str:
    """Wrap content in sentinels with newline terminator"""
    return f"{SENTINEL}{content}{SENTINEL}\n"


def build_request(msg_id: str, host: str, port: int, pdu: bytes) -> str:
    """Build a framed REQ message"""
    encoded = base64.b64encode(pdu).decode("ascii")
    return frame(f"REQ|{msg_id}|{host}:{port}|{encoded}")


def build_response_ok(msg_id: str, data: bytes) -> str:
    """Build a framed RSP OK message"""
    encoded = base64.b64encode(data).decode("ascii")
    return frame(f"RSP|{msg_id}|OK|{encoded}")


def build_response_error(msg_id: str, error: str) -> str:
    """Build a framed RSP ERR message"""
    # Sanitize — no sentinels, pipes, newlines, or carriage returns in error text
    safe = (error.replace(SENTINEL, "")
            .replace("|", " ")
            .replace("\n", " ")
            .replace("\r", "")
            .strip())
    return frame(f"RSP|{msg_id}|ERR|{safe}")


def build_response_timeout(msg_id: str) -> str:
    """Build a framed RSP TIMEOUT message"""
    return frame(f"RSP|{msg_id}|TIMEOUT|")


def build_ping() -> str:
    return frame("PING")


def build_pong() -> str:
    return frame("PONG")


def build_quit() -> str:
    return frame("QUIT")


# ---------------------------------------------------------------------------
# Parser — extract message content from framed string
# ---------------------------------------------------------------------------

def parse_message(content: str) -> Request | Response | MsgType | None:
    """
    Parse the inner content of a framed message (sentinels already stripped).
    Returns Request, Response, MsgType (PING/PONG/QUIT), or None if malformed.
    """
    content = content.strip()

    if not content:
        return None

    # Simple control messages
    if content == "PING":
        return MsgType.PING
    if content == "PONG":
        return MsgType.PONG
    if content == "QUIT":
        return MsgType.QUIT

    parts = content.split("|", 3)

    if parts[0] == "REQ" and len(parts) == 4:
        try:
            msg_id = parts[1]
            host_port = parts[2]
            if ":" in host_port:
                host, port_str = host_port.rsplit(":", 1)
                port = int(port_str)
            else:
                host = host_port
                port = 161
            pdu = base64.b64decode(parts[3])
            return Request(msg_id=msg_id, host=host, port=port, pdu=pdu)
        except Exception:
            return None

    if parts[0] == "RSP" and len(parts) >= 3:
        msg_id = parts[1]
        status_str = parts[2]
        payload = parts[3] if len(parts) > 3 else ""

        try:
            status = RspStatus(status_str)
        except ValueError:
            return None

        if status == RspStatus.OK:
            try:
                data = base64.b64decode(payload) if payload else b""
                return Response(msg_id=msg_id, status=status, data=data)
            except Exception:
                return None
        elif status == RspStatus.TIMEOUT:
            return Response(msg_id=msg_id, status=status)
        else:  # ERR
            return Response(msg_id=msg_id, status=status, error=payload)

    return None


# ---------------------------------------------------------------------------
# FrameReader — streaming state machine for extracting framed messages
# ---------------------------------------------------------------------------

class FrameReader:
    """
    Streaming frame reader. Feed it chunks of text (lines, partial reads,
    whatever) and it extracts complete framed messages, ignoring all noise.

    Usage:
        reader = FrameReader()

        # Feed data as it arrives
        for msg in reader.feed(line_from_ssh):
            if isinstance(msg, Request):
                handle_request(msg)
            elif isinstance(msg, Response):
                handle_response(msg)
            elif msg == MsgType.PING:
                send_pong()

    The reader handles:
      - Multiple frames in one feed() call
      - Frames split across multiple feed() calls
      - Arbitrary noise between frames (echo, ANSI, prompts)
      - Sentinels split across feed boundaries

    IMPORTANT: The FrameReader treats ALL sentinels as frame boundaries.
    It cannot distinguish "real" sentinels from sentinels that appear in
    echoed content. If the pty echoes REQ frames (which contain sentinels),
    those echoed sentinels will corrupt in-progress RSP frames by being
    misread as end-of-frame markers. The caller MUST disable pty echo
    (stty -echo or stty raw -echo) before entering protocol mode.
    """

    def __init__(self, on_noise: Optional[Callable[[str], None]] = None):
        self._buffer = ""
        self._in_frame = False
        self._frame_buf = ""
        self._on_noise = on_noise   # callback for discarded content (debug)

    def feed(self, data: str) -> list[Request | Response | MsgType]:
        """
        Feed raw text data. Returns list of parsed messages found.
        May return 0, 1, or many messages per call.
        """
        self._buffer += data
        messages = []

        while True:
            if not self._in_frame:
                # Scanning for start sentinel
                idx = self._buffer.find(SENTINEL)
                if idx == -1:
                    # No sentinel found — all noise
                    if self._on_noise and self._buffer:
                        self._on_noise(self._buffer)
                    self._buffer = ""
                    break

                # Discard everything before the sentinel
                if idx > 0 and self._on_noise:
                    self._on_noise(self._buffer[:idx])

                self._buffer = self._buffer[idx + SENTINEL_LEN:]
                self._in_frame = True
                self._frame_buf = ""

            else:
                # Inside a frame — looking for end sentinel
                idx = self._buffer.find(SENTINEL)
                if idx == -1:
                    # End sentinel not yet received — accumulate
                    self._frame_buf += self._buffer
                    self._buffer = ""

                    # Safety: if frame buffer is absurdly large, reset
                    # (corrupt data or stuck state). Normal SNMP PDUs are
                    # well under 64K; base64 inflates ~33%, so 100K is wild.
                    if len(self._frame_buf) > 100_000:
                        if self._on_noise:
                            self._on_noise(f"[frame overflow: {len(self._frame_buf)} bytes, reset]")
                        self._in_frame = False
                        self._frame_buf = ""
                    break

                # Found end sentinel — extract complete frame
                self._frame_buf += self._buffer[:idx]
                self._buffer = self._buffer[idx + SENTINEL_LEN:]
                self._in_frame = False

                # Parse the frame content
                msg = parse_message(self._frame_buf)
                if msg is not None:
                    messages.append(msg)
                elif self._on_noise:
                    self._on_noise(f"[malformed frame: {self._frame_buf[:80]}]")

                self._frame_buf = ""

        return messages

    def reset(self) -> None:
        """Reset reader state (e.g., after reconnect)"""
        self._buffer = ""
        self._in_frame = False
        self._frame_buf = ""