#!/usr/bin/env python3
"""
snmpproxy_remote.py — Hardened remote SNMP relay agent

Reads framed text protocol from stdin, relays raw SNMP PDUs via UDP
to target devices, writes framed responses to stdout.

Requires: snmpproxy_protocol.py in the same directory.
No other external dependencies — runs on any jumpbox with Python 3.7+.

Hardening over v1:
  - SNMP request-id extraction for correct concurrent response matching
    (fixes table walk / snmpwalk cross-wiring under concurrent load)
  - Periodic stats to stderr for remote visibility
  - Exception armor on all code paths
  - Pending request cap to prevent memory blowout
  - Stdin watchdog to detect dead local side
  - Malformed frame / bad base64 / truncated PDU defense

Deployment:
  scp snmpproxy_protocol.py snmpproxy_remote.py jumpbox:/opt/snmpproxy/
  # Local proxy then runs: python3 -u /opt/snmpproxy/snmpproxy_remote.py
"""

from __future__ import annotations

import os
import select
import socket
import sys
import time
import threading

from snmpproxy_protocol import (
    FrameReader,
    Request,
    MsgType,
    build_response_ok,
    build_response_error,
    build_response_timeout,
    build_pong,
)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
SNMP_TIMEOUT = 5.0          # Per-request UDP timeout (seconds)
SNMP_RETRIES = 1            # Retry count before declaring timeout
MAX_PDU_SIZE = 65535         # Max UDP datagram size
SELECT_TIMEOUT = 0.1        # Main loop select granularity
MAX_PENDING = 500           # Cap in-flight requests (memory safety)
STATS_INTERVAL = 60.0       # Periodic stats dump interval (seconds)
STDIN_WATCHDOG = 120.0      # Seconds of stdin silence before alarm
MIN_SNMP_PDU = 10           # Minimum plausible SNMP PDU size (bytes)


# ---------------------------------------------------------------------------
# Logging — always to stderr, never interferes with stdout protocol
# ---------------------------------------------------------------------------

def log(msg: str) -> None:
    print(f"[snmpproxy] {msg}", file=sys.stderr, flush=True)


def log_warn(msg: str) -> None:
    print(f"[snmpproxy] WARN  {msg}", file=sys.stderr, flush=True)


def log_error(msg: str) -> None:
    print(f"[snmpproxy] ERROR {msg}", file=sys.stderr, flush=True)


def write(msg: str) -> None:
    """Write a framed message to stdout immediately"""
    try:
        sys.stdout.write(msg)
        sys.stdout.flush()
    except (BrokenPipeError, OSError) as e:
        log_error(f"stdout write failed: {e}")


def write_batch(messages: list[str]) -> None:
    """
    Write multiple framed messages to stdout in a single flush.

    Coalesces RSP frames into one stdout write + flush, reducing
    pty buffer round-trips and SSH packet fragmentation. Called by
    poll_responses() when multiple UDP responses arrive at once.
    """
    if not messages:
        return
    try:
        batch = "".join(messages)
        sys.stdout.write(batch)
        sys.stdout.flush()
    except (BrokenPipeError, OSError) as e:
        log_error(f"stdout batch write failed ({len(messages)} msgs): {e}")


# ---------------------------------------------------------------------------
# SNMP request-id extraction (BER/ASN.1 — stdlib only)
# ---------------------------------------------------------------------------

def extract_snmp_request_id(pdu: bytes) -> int | None:
    """
    Extract the SNMP request-id from a raw PDU without any SNMP library.

    SNMP v1/v2c PDU structure (BER):
      SEQUENCE {                    -- outer wrapper
        INTEGER (version)           -- 0=v1, 1=v2c
        OCTET STRING (community)    -- community string
        [context] SEQUENCE {        -- PDU type (GetRequest=0xA0, GetNext=0xA1, etc.)
          INTEGER (request-id)      -- ← this is what we want
          ...
        }
      }

    Returns the request-id integer, or None if parsing fails.
    This is defensive — malformed PDUs return None, never raise.
    """
    try:
        pos = 0

        # Outer SEQUENCE (tag 0x30)
        if len(pdu) < 2 or pdu[pos] != 0x30:
            return None
        pos, _ = _ber_read_tl(pdu, pos)
        if pos is None:
            return None

        # INTEGER — version
        pos = _ber_skip_tlv(pdu, pos)
        if pos is None:
            return None

        # OCTET STRING — community
        pos = _ber_skip_tlv(pdu, pos)
        if pos is None:
            return None

        # Context-tagged PDU (0xA0-0xA5 for SNMPv1/v2c PDU types)
        if pos >= len(pdu) or (pdu[pos] & 0xE0) != 0xA0:
            return None
        pos, _ = _ber_read_tl(pdu, pos)
        if pos is None:
            return None

        # First element inside PDU: INTEGER — request-id
        if pos >= len(pdu) or pdu[pos] != 0x02:
            return None
        pos, length = _ber_read_tl(pdu, pos)
        if pos is None or length is None:
            return None
        if pos + length > len(pdu) or length > 4 or length < 1:
            return None

        # Decode request-id as signed integer (big-endian)
        rid = int.from_bytes(pdu[pos:pos + length], byteorder='big', signed=True)
        return rid

    except Exception:
        return None


def _ber_read_tl(data: bytes, pos: int):
    """Read BER tag + length, return (offset_after_TL, length) or (None, None)."""
    try:
        if pos >= len(data):
            return None, None
        pos += 1  # skip tag byte

        if pos >= len(data):
            return None, None

        first = data[pos]
        if first < 0x80:
            return pos + 1, first
        elif first == 0x80:
            # Indefinite length — not used in SNMP, bail
            return None, None
        else:
            num_bytes = first & 0x7F
            if num_bytes > 4 or pos + 1 + num_bytes > len(data):
                return None, None
            length = int.from_bytes(data[pos + 1: pos + 1 + num_bytes], 'big')
            return pos + 1 + num_bytes, length
    except Exception:
        return None, None


def _ber_skip_tlv(data: bytes, pos: int):
    """Skip one complete TLV element, return position after it or None."""
    try:
        pos_after_tl, length = _ber_read_tl(data, pos)
        if pos_after_tl is None or length is None:
            return None
        end = pos_after_tl + length
        if end > len(data):
            return None
        return end
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Stats tracker
# ---------------------------------------------------------------------------

class Stats:
    """Counters for remote visibility — dumped periodically to stderr"""

    def __init__(self):
        self.requests = 0
        self.responses_ok = 0
        self.responses_timeout = 0
        self.responses_error = 0
        self.retries = 0
        self.bad_frames = 0
        self.bad_pdus = 0
        self.pongs = 0
        self.request_id_misses = 0      # Responses we matched by addr fallback
        self.request_id_matches = 0     # Responses matched by request-id
        self.dropped_cap = 0            # Requests dropped due to pending cap
        self.stale_flushed = 0          # Pending entries flushed on PING
        self.stdin_lines = 0
        self._started = time.monotonic()
        self._last_dump = time.monotonic()
        self._lock = threading.Lock()

    def dump(self, force: bool = False) -> None:
        """Dump stats to stderr if interval has elapsed (or forced)"""
        now = time.monotonic()
        with self._lock:
            if not force and (now - self._last_dump) < STATS_INTERVAL:
                return
            self._last_dump = now
            uptime = now - self._started

        hours = int(uptime // 3600)
        mins = int((uptime % 3600) // 60)
        secs = int(uptime % 60)

        log(
            f"STATS  uptime={hours:02d}:{mins:02d}:{secs:02d}  "
            f"req={self.requests}  ok={self.responses_ok}  "
            f"timeout={self.responses_timeout}  err={self.responses_error}  "
            f"retry={self.retries}  "
            f"rid_match={self.request_id_matches}  rid_fallback={self.request_id_misses}  "
            f"bad_frame={self.bad_frames}  bad_pdu={self.bad_pdus}  "
            f"dropped={self.dropped_cap}  flushed={self.stale_flushed}"
        )


# ---------------------------------------------------------------------------
# UDP socket pool — hardened with request-id correlation
# ---------------------------------------------------------------------------

class SocketPool:
    """
    Single UDP socket for all SNMP relay, with pending request tracking.

    Response matching priority:
      1. (addr, snmp_request_id) — exact match, handles concurrent walks
      2. (addr) fallback — for PDUs where request-id extraction failed

    This fixes the v1 bug where concurrent requests to the same target
    (table walks) would cross-wire responses.
    """

    def __init__(self, stats: Stats):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setblocking(False)
        self._pending: dict[str, dict] = {}     # msg_id → context
        self._lock = threading.Lock()
        self._stats = stats

    @property
    def socket(self):
        return self._sock

    def send_request(self, msg_id: str, host: str, port: int, pdu: bytes) -> None:
        """Send SNMP PDU to target device"""
        # Validate PDU minimally
        if len(pdu) < MIN_SNMP_PDU:
            self._stats.bad_pdus += 1
            write(build_response_error(msg_id, f"PDU too small ({len(pdu)}B)"))
            return

        # Cap check
        with self._lock:
            if len(self._pending) >= MAX_PENDING:
                self._stats.dropped_cap += 1
                log_warn(f"{msg_id}: dropped — {MAX_PENDING} requests pending")
                write(build_response_error(msg_id, "agent overloaded"))
                return

        target = (host, port)
        snmp_rid = extract_snmp_request_id(pdu)

        with self._lock:
            self._pending[msg_id] = {
                "target": target,
                "sent_at": time.monotonic(),
                "retries_left": SNMP_RETRIES,
                "pdu": pdu,
                "snmp_rid": snmp_rid,
            }

        try:
            self._sock.sendto(pdu, target)
        except OSError as e:
            with self._lock:
                self._pending.pop(msg_id, None)
            self._stats.responses_error += 1
            write(build_response_error(msg_id, f"sendto failed: {e}"))

    def poll_responses(self) -> None:
        """Check for UDP responses and timeouts, write framed responses"""
        # Collect response frames for batch write — one flush at the end
        # instead of one per response. Under load with 20 concurrent
        # requests, this can coalesce 10+ RSP frames into a single
        # stdout write + flush, dramatically reducing pty round-trips.
        out_batch: list[str] = []

        # ── Drain available UDP responses ──
        while True:
            try:
                ready, _, _ = select.select([self._sock], [], [], 0)
                if not ready:
                    break
                data, addr = self._sock.recvfrom(MAX_PDU_SIZE)
            except (BlockingIOError, OSError):
                break

            # Extract request-id from response PDU for matching
            resp_rid = extract_snmp_request_id(data)

            with self._lock:
                matched_id = self._match_response(addr, resp_rid)
                if matched_id:
                    del self._pending[matched_id]

            if matched_id:
                self._stats.responses_ok += 1
                out_batch.append(build_response_ok(matched_id, data))
            else:
                # Orphan response — device replied to something we already
                # timed out or never sent. Log it but don't crash.
                log(f"orphan response from {addr[0]}:{addr[1]} ({len(data)}B)")

        # ── Check timeouts / retries ──
        now = time.monotonic()
        retry_actions: list[tuple[str, tuple, bytes]] = []
        timeout_ids: list[str] = []

        with self._lock:
            for mid, ctx in list(self._pending.items()):
                elapsed = now - ctx["sent_at"]
                if elapsed >= SNMP_TIMEOUT:
                    if ctx["retries_left"] > 0:
                        ctx["retries_left"] -= 1
                        ctx["sent_at"] = now
                        retry_actions.append((mid, ctx["target"], ctx["pdu"]))
                    else:
                        timeout_ids.append(mid)

            for mid in timeout_ids:
                self._pending.pop(mid, None)

        for mid, target, pdu in retry_actions:
            self._stats.retries += 1
            try:
                self._sock.sendto(pdu, target)
                log(f"{mid}: retry → {target[0]}:{target[1]}")
            except OSError as e:
                with self._lock:
                    self._pending.pop(mid, None)
                self._stats.responses_error += 1
                out_batch.append(build_response_error(mid, f"retry failed: {e}"))

        for mid in timeout_ids:
            self._stats.responses_timeout += 1
            out_batch.append(build_response_timeout(mid))

        # ── Single flush — all RSP frames in one stdout write ──
        if out_batch:
            write_batch(out_batch)

    def _match_response(self, addr: tuple, resp_rid: int | None) -> str | None:
        """
        Match a UDP response to a pending request.

        Priority:
          1. Exact match on (addr, snmp_request_id) — concurrent-safe
          2. Fallback to addr-only if request-id unavailable — v1 behavior

        Must be called with self._lock held.
        """
        # Pass 1: exact match on address + SNMP request-id
        if resp_rid is not None:
            for mid, ctx in self._pending.items():
                if (ctx["target"][0] == addr[0]
                        and ctx["target"][1] == addr[1]
                        and ctx["snmp_rid"] == resp_rid):
                    self._stats.request_id_matches += 1
                    return mid

        # Pass 2: address-only fallback (for PDUs where RID extraction failed)
        for mid, ctx in self._pending.items():
            if ctx["target"][0] == addr[0] and ctx["target"][1] == addr[1]:
                self._stats.request_id_misses += 1
                return mid

        return None

    def flush_pending(self, reason: str = "flush") -> int:
        """
        Clear all pending requests. Returns count of flushed entries.

        Called on PING reception — any pending requests that pre-date
        a PING are stale (local side is either doing keepalive or
        re-handshaking after a crash). Either way, those requests will
        never be resolved on the local side.
        """
        with self._lock:
            count = len(self._pending)
            if count > 0:
                log(f"flushing {count} pending requests ({reason})")
                self._pending.clear()
            return count

    @property
    def pending_count(self) -> int:
        with self._lock:
            return len(self._pending)

    def close(self):
        try:
            self._sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Main loop — hardened
# ---------------------------------------------------------------------------

def main() -> None:
    log("starting (hardened) — listening on stdin")
    stats = Stats()
    pool = SocketPool(stats)
    reader = FrameReader(
        on_noise=lambda s: log(f"noise: {s.strip()[:80]}") if s.strip() else None
    )
    stdin_fd = sys.stdin.fileno()
    last_stdin_activity = time.monotonic()
    last_stats_check = time.monotonic()

    try:
        while True:
            # ── select on stdin + UDP socket ──
            try:
                watch = [stdin_fd, pool.socket]
                readable, _, _ = select.select(watch, [], [], SELECT_TIMEOUT)
            except (OSError, ValueError) as e:
                log_error(f"select failed: {e}")
                break

            # ── Always poll UDP (responses + timeouts) ──
            try:
                pool.poll_responses()
            except Exception as e:
                log_error(f"poll_responses exception: {e}")
                # Don't break — try to keep going

            # ── Check stdin ──
            stdin_ready = any(
                (r.fileno() if hasattr(r, "fileno") else r) == stdin_fd
                for r in readable
            )

            if stdin_ready:
                # Read raw bytes — NOT readline(). os.read() returns
                # whatever is available in the pty buffer right now,
                # up to 32KB. No blocking until \n.
                #
                # This matters because the local ChannelWriter coalesces
                # multiple REQ frames into a single SSH packet. readline()
                # would peel them off one at a time (one select cycle per
                # line), starving UDP response processing between each.
                # os.read() grabs the entire batch in one shot and feeds
                # it all to FrameReader, which extracts every frame.
                try:
                    raw_bytes = os.read(stdin_fd, 32768)
                except Exception as e:
                    log_error(f"stdin read error: {e}")
                    break

                if not raw_bytes:
                    log("stdin closed, shutting down")
                    break

                last_stdin_activity = time.monotonic()
                stats.stdin_lines += 1  # legacy name — now counts reads, not lines

                # Decode and feed to FrameReader — handles partial frames,
                # multiple frames, noise, all of it
                try:
                    raw = raw_bytes.decode("utf-8", errors="replace")
                    messages = reader.feed(raw)
                except Exception as e:
                    log_error(f"FrameReader.feed() exception: {e}")
                    stats.bad_frames += 1
                    messages = []

                for msg in messages:
                    try:
                        if isinstance(msg, Request):
                            stats.requests += 1
                            log(f"{msg.msg_id}: REQ → {msg.host}:{msg.port} ({len(msg.pdu)} bytes)")
                            pool.send_request(msg.msg_id, msg.host, msg.port, msg.pdu)
                        elif msg == MsgType.PING:
                            # Flush stale pending before PONG — any in-flight
                            # requests pre-dating a PING are unreachable on
                            # the local side (keepalive or re-handshake)
                            flushed = pool.flush_pending("PING received")
                            if flushed:
                                stats.stale_flushed += flushed
                            stats.pongs += 1
                            write(build_pong())
                        elif msg == MsgType.QUIT:
                            log("received QUIT, shutting down")
                            stats.dump(force=True)
                            return
                        else:
                            log(f"unhandled message type: {msg}")
                    except Exception as e:
                        log_error(f"message handler exception: {e}")

            # ── Periodic stats ──
            now = time.monotonic()
            if now - last_stats_check >= STATS_INTERVAL:
                last_stats_check = now
                stats.dump(force=True)

            # ── Stdin watchdog ──
            if now - last_stdin_activity > STDIN_WATCHDOG:
                log_warn(
                    f"no stdin activity for {STDIN_WATCHDOG:.0f}s — "
                    f"local side may be dead (pending={pool.pending_count})"
                )
                # Reset timer so we warn periodically, not every loop
                last_stdin_activity = now

    except KeyboardInterrupt:
        log("interrupted")
    except Exception as e:
        log_error(f"main loop exception: {e}")
    finally:
        stats.dump(force=True)
        pool.close()
        log("shutdown complete")


if __name__ == "__main__":
    main()