"""
socks5.py — SOCKS5 front-end for stt-tcp

Drop-in alternative to the static TCPListener. Instead of a fixed
local_port → remote host:port mapping, it speaks SOCKS5 to the local
client, extracts the target host:port from the CONNECT request, and
opens a tunnel stream to it dynamically.

The target HOSTNAME is passed through unresolved (ATYP 0x03) so DNS
resolution happens on the remote/jumpbox side — the whole point.

Reuses SSHTunnel.open_stream(host, port, transport) verbatim:
  - returns stream_id on success
  - raises ConnectionError("Remote connect failed: ...") on OPEN_ERR

Pure asyncio stdlib. No new dependencies.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import struct

log = logging.getLogger("stttcp.socks5")

SOCKS_VERSION = 0x05

# Auth methods
M_NO_AUTH = 0x00
M_NO_ACCEPTABLE = 0xFF

# Commands
CMD_CONNECT = 0x01
CMD_BIND = 0x02
CMD_UDP = 0x03

# Address types
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04

# Reply codes (REP field)
REP_OK = 0x00
REP_GENERAL_FAIL = 0x01
REP_NET_UNREACH = 0x03
REP_HOST_UNREACH = 0x04
REP_CONN_REFUSED = 0x05
REP_CMD_UNSUPPORTED = 0x07
REP_ATYP_UNSUPPORTED = 0x08


class Socks5Error(Exception):
    """Raised during negotiation; carries the REP code to send back."""
    def __init__(self, rep: int, detail: str = ""):
        self.rep = rep
        super().__init__(detail or f"SOCKS5 error rep={rep}")


def build_reply(rep: int, bind_host: str = "0.0.0.0", bind_port: int = 0) -> bytes:
    """
    Encode a SOCKS5 reply. We always answer with an IPv4 BND.ADDR of
    0.0.0.0:0 — browsers and proxychains don't care what bind address
    we claim, only that the reply is well-formed.
        VER REP RSV ATYP BND.ADDR BND.PORT
    """
    return struct.pack(
        "!BBBB4sH",
        SOCKS_VERSION, rep, 0x00, ATYP_IPV4,
        socket.inet_aton(bind_host), bind_port,
    )


def map_error_to_rep(err: str) -> int:
    """
    Translate the remote agent's OPEN_ERR text into the closest SOCKS5
    REP code so the browser fails fast with a real error instead of
    hanging until its own timeout.
    """
    e = err.lower()
    if "refused" in e:
        return REP_CONN_REFUSED
    if "timed out" in e or "timeout" in e:
        return REP_HOST_UNREACH
    if "no route" in e or "unreachable" in e or "network is" in e:
        return REP_NET_UNREACH
    if "name or service" in e or "not known" in e or "resolve" in e:
        return REP_HOST_UNREACH
    return REP_GENERAL_FAIL


async def negotiate_method(reader: asyncio.StreamReader,
                           writer: asyncio.StreamWriter) -> None:
    """
    Method-selection handshake.
        Client: VER NMETHODS METHODS...
        Server: VER METHOD
    We only accept no-auth (0x00).
    """
    header = await reader.readexactly(2)
    ver, nmethods = header[0], header[1]
    if ver != SOCKS_VERSION:
        raise Socks5Error(REP_GENERAL_FAIL, f"bad version {ver}")
    methods = await reader.readexactly(nmethods)
    if M_NO_AUTH not in methods:
        writer.write(bytes([SOCKS_VERSION, M_NO_ACCEPTABLE]))
        await writer.drain()
        raise Socks5Error(REP_GENERAL_FAIL, "no acceptable auth method")
    writer.write(bytes([SOCKS_VERSION, M_NO_AUTH]))
    await writer.drain()


async def read_request(reader: asyncio.StreamReader) -> tuple[str, int]:
    """
    Read the CONNECT request and return (host, port).
        VER CMD RSV ATYP DST.ADDR DST.PORT
    Hostnames (ATYP 0x03) are returned as-is, unresolved.
    """
    head = await reader.readexactly(4)
    ver, cmd, _rsv, atyp = head[0], head[1], head[2], head[3]
    if ver != SOCKS_VERSION:
        raise Socks5Error(REP_GENERAL_FAIL, f"bad version {ver}")
    if cmd != CMD_CONNECT:
        raise Socks5Error(REP_CMD_UNSUPPORTED, f"unsupported cmd {cmd}")

    if atyp == ATYP_IPV4:
        host = socket.inet_ntoa(await reader.readexactly(4))
    elif atyp == ATYP_IPV6:
        host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
    elif atyp == ATYP_DOMAIN:
        dlen = (await reader.readexactly(1))[0]
        host = (await reader.readexactly(dlen)).decode("ascii", errors="replace")
    else:
        raise Socks5Error(REP_ATYP_UNSUPPORTED, f"bad atyp {atyp}")

    port = struct.unpack("!H", await reader.readexactly(2))[0]
    return host, port


class Socks5Listener:
    """
    SOCKS5 proxy on a single local port. Replaces the static port map:
    one listener reaches any host:port the client asks for, resolved
    on the remote side.
    """

    def __init__(self, tunnel, bind: str, port: int = 1080):
        self.tunnel = tunnel
        self.bind = bind
        self.port = port
        self._server = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client, host=self.bind, port=self.port,
        )

    async def _handle_client(self, reader: asyncio.StreamReader,
                             writer: asyncio.StreamWriter) -> None:
        client_addr = writer.get_extra_info("peername")
        transport = writer.transport

        # --- SOCKS5 negotiation ---
        try:
            await negotiate_method(reader, writer)
            host, port = await read_request(reader)
        except asyncio.IncompleteReadError:
            writer.close()
            return
        except Socks5Error as e:
            try:
                writer.write(build_reply(e.rep))
                await writer.drain()
            except Exception:
                pass
            writer.close()
            return

        log.info(f"SOCKS5 {client_addr} → CONNECT {host}:{port}")

        # --- open the tunnel stream (reply gated on the round-trip) ---
        try:
            stream_id = await self.tunnel.open_stream(host, port, transport)
        except ConnectionError as e:
            rep = map_error_to_rep(str(e))
            log.info(f"SOCKS5 CONNECT {host}:{port} failed (rep={rep}): {e}")
            try:
                writer.write(build_reply(rep))
                await writer.drain()
            except Exception:
                pass
            writer.close()
            return

        # success reply — only now may application data flow
        writer.write(build_reply(REP_OK))
        await writer.drain()

        # --- identical forward loop to TCPListener ---
        from stttcp.stttcp_protocol import DATA_CHUNK_SIZE
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
            log.info(f"SOCKS5 stream {stream_id} closed")