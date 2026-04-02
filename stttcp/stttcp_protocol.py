"""
stttcp_protocol.py — Framed text protocol for TCP-over-SSH transport

Wire format:
  ~##~{message_content}~##~

Message types — stream lifecycle:
  ~##~OPEN|{stream_id}|{host}:{port}~##~
  ~##~OPENED|{stream_id}~##~
  ~##~OPEN_ERR|{stream_id}|{error_text}~##~

Message types — data transfer (bidirectional):
  ~##~DATA|{stream_id}|{base64_chunk}~##~

Message types — stream teardown:
  ~##~CLOSE|{stream_id}~##~

Message types — control:
  ~##~PING~##~
  ~##~PONG~##~
  ~##~QUIT~##~

Stream IDs are assigned by the local side (6-digit zero-padded counter).
The remote side echoes them back in all stream-related messages.

DATA messages flow in both directions:
  - Local → remote: client data to forward to the TCP target
  - Remote → local: response data from the TCP target

Base64 encoding ensures all payloads survive terminal echo, ANSI
injection, and character encoding. Chunk size is configurable but
defaults to 16KB raw (≈21KB base64) per DATA frame.

This file has ZERO external dependencies and works on Python 3.7+.
Both local and remote sides use identical parsing logic.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Callable, Union


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SENTINEL = "~##~"
SENTINEL_LEN = len(SENTINEL)

# Max raw bytes per DATA frame before base64 encoding.
# 16KB raw → ~21KB base64 → well under 100KB frame overflow limit.
DATA_CHUNK_SIZE = 16384


class MsgType(str, Enum):
    OPEN = "OPEN"
    OPENED = "OPENED"
    OPEN_ERR = "OPEN_ERR"
    DATA = "DATA"
    CLOSE = "CLOSE"
    PING = "PING"
    PONG = "PONG"
    QUIT = "QUIT"


# ---------------------------------------------------------------------------
# Parsed message types
# ---------------------------------------------------------------------------

@dataclass
class OpenRequest:
    """Parsed OPEN message — request to connect to remote TCP target"""
    stream_id: str
    host: str
    port: int


@dataclass
class Opened:
    """Parsed OPENED message — remote TCP connection established"""
    stream_id: str


@dataclass
class OpenError:
    """Parsed OPEN_ERR message — remote TCP connection failed"""
    stream_id: str
    error: str


@dataclass
class Data:
    """Parsed DATA message — chunk of TCP stream data (bidirectional)"""
    stream_id: str
    payload: bytes      # decoded from base64


@dataclass
class Close:
    """Parsed CLOSE message — stream teardown (either direction)"""
    stream_id: str


# All possible parsed message types
ParsedMessage = Union[OpenRequest, Opened, OpenError, Data, Close, MsgType]


# ---------------------------------------------------------------------------
# Message builders — produce framed strings ready to write
# ---------------------------------------------------------------------------

def frame(content: str) -> str:
    """Wrap content in sentinels with newline terminator"""
    return f"{SENTINEL}{content}{SENTINEL}\n"


def build_open(stream_id: str, host: str, port: int) -> str:
    """Build a framed OPEN message"""
    return frame(f"OPEN|{stream_id}|{host}:{port}")


def build_opened(stream_id: str) -> str:
    """Build a framed OPENED message"""
    return frame(f"OPENED|{stream_id}")


def build_open_error(stream_id: str, error: str) -> str:
    """Build a framed OPEN_ERR message"""
    safe = error.replace(SENTINEL, "").replace("|", " ").replace("\n", " ").strip()
    return frame(f"OPEN_ERR|{stream_id}|{safe}")


def build_data(stream_id: str, payload: bytes) -> str:
    """Build a framed DATA message"""
    encoded = base64.b64encode(payload).decode("ascii")
    return frame(f"DATA|{stream_id}|{encoded}")


def build_close(stream_id: str) -> str:
    """Build a framed CLOSE message"""
    return frame(f"CLOSE|{stream_id}")


def build_ping() -> str:
    return frame("PING")


def build_pong() -> str:
    return frame("PONG")


def build_quit() -> str:
    return frame("QUIT")


# ---------------------------------------------------------------------------
# Chunker — split large payloads into DATA-sized frames
# ---------------------------------------------------------------------------

def chunk_data(stream_id: str, payload: bytes,
               chunk_size: int = DATA_CHUNK_SIZE) -> list[str]:
    """
    Split a payload into one or more framed DATA messages.

    For most TCP reads (< 16KB), this returns a single frame.
    For large payloads (bulk transfers, HTTP responses), it splits
    into multiple frames to avoid overwhelming the terminal channel.
    """
    if not payload:
        return []

    frames = []
    offset = 0
    while offset < len(payload):
        chunk = payload[offset:offset + chunk_size]
        frames.append(build_data(stream_id, chunk))
        offset += chunk_size
    return frames


# ---------------------------------------------------------------------------
# Parser — extract message content from framed string
# ---------------------------------------------------------------------------

def parse_message(content: str) -> ParsedMessage | None:
    """
    Parse the inner content of a framed message (sentinels already stripped).
    Returns a parsed message object, MsgType enum, or None if malformed.
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

    parts = content.split("|", 2)

    # CLOSE — only needs stream_id
    if parts[0] == "CLOSE" and len(parts) == 2:
        return Close(stream_id=parts[1])

    # OPENED — only needs stream_id
    if parts[0] == "OPENED" and len(parts) == 2:
        return Opened(stream_id=parts[1])

    if len(parts) < 3:
        return None

    msg_type = parts[0]
    stream_id = parts[1]
    payload = parts[2]

    # OPEN — connect to remote host:port
    if msg_type == "OPEN":
        try:
            if ":" in payload:
                host, port_str = payload.rsplit(":", 1)
                port = int(port_str)
            else:
                return None  # port is required for TCP
            return OpenRequest(stream_id=stream_id, host=host, port=port)
        except (ValueError, IndexError):
            return None

    # OPEN_ERR — connection failed
    if msg_type == "OPEN_ERR":
        return OpenError(stream_id=stream_id, error=payload)

    # DATA — stream payload
    if msg_type == "DATA":
        try:
            decoded = base64.b64decode(payload) if payload else b""
            return Data(stream_id=stream_id, payload=decoded)
        except Exception:
            return None

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

        for msg in reader.feed(line_from_ssh):
            if isinstance(msg, OpenRequest):
                connect_to_target(msg)
            elif isinstance(msg, Data):
                forward_data(msg)
            elif isinstance(msg, Close):
                teardown_stream(msg)
            elif msg == MsgType.PING:
                send_pong()

    The reader handles:
      - Multiple frames in one feed() call
      - Frames split across multiple feed() calls
      - Arbitrary noise between frames (echo, ANSI, prompts)
      - Sentinels split across feed boundaries
    """

    def __init__(self, on_noise: Optional[Callable[[str], None]] = None):
        self._buffer = ""
        self._in_frame = False
        self._frame_buf = ""
        self._on_noise = on_noise

    def feed(self, data: str) -> list[ParsedMessage]:
        """
        Feed raw text data. Returns list of parsed messages found.
        May return 0, 1, or many messages per call.
        """
        self._buffer += data
        messages = []

        while True:
            if not self._in_frame:
                idx = self._buffer.find(SENTINEL)
                if idx == -1:
                    if self._on_noise and self._buffer:
                        self._on_noise(self._buffer)
                    self._buffer = ""
                    break

                if idx > 0 and self._on_noise:
                    self._on_noise(self._buffer[:idx])

                self._buffer = self._buffer[idx + SENTINEL_LEN:]
                self._in_frame = True
                self._frame_buf = ""

            else:
                idx = self._buffer.find(SENTINEL)
                if idx == -1:
                    self._frame_buf += self._buffer
                    self._buffer = ""

                    # Safety: TCP DATA frames can be larger than SNMP PDUs
                    # but should still be well under 100KB with 16KB chunks.
                    # 200KB covers even oversized frames with margin.
                    if len(self._frame_buf) > 200_000:
                        if self._on_noise:
                            self._on_noise(
                                f"[frame overflow: {len(self._frame_buf)} bytes, reset]"
                            )
                        self._in_frame = False
                        self._frame_buf = ""
                    break

                self._frame_buf += self._buffer[:idx]
                self._buffer = self._buffer[idx + SENTINEL_LEN:]
                self._in_frame = False

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
