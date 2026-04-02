"""
sttsnmp.discover.transport — Pluggable device access layer.

Architecture:
  ProxyWalker wraps DirectWalker, redirecting target IPs to
  localhost:{proxy_port}. This lets the existing netaudit
  collectors (CDP, LLDP, system info) work UNCHANGED through
  the STT proxy — they call walker.walk("10.2.1.18", oid, auth)
  and ProxyWalker transparently sends it to 127.0.0.1:10002.

  No reimplemented collectors. No reimplemented pysnmp.
  Proven code top to bottom.

Transport modes:
  SNMPTransport (working): proxy API + ProxyWalker + netaudit collectors
  SSHTransport (future):   stt-tcp API + paramiko + CLI parsing
"""

from __future__ import annotations

import asyncio
import logging
import re
from abc import ABC, abstractmethod
from typing import Optional, Any, Dict, List, Tuple

import aiohttp

from pysnmp.hlapi.v3arch.asyncio import (
    SnmpEngine, CommunityData,
)

from .models import DeviceInfo, Neighbor, Interface

log = logging.getLogger("sttsnmp.discover")


# ---------------------------------------------------------------------------
# Transport base
# ---------------------------------------------------------------------------

class Transport(ABC):
    @abstractmethod
    async def register(self, remote_host: str, remote_port: int = 0) -> int:
        ...

    @abstractmethod
    async def get_system_info(self, target: str) -> Optional[DeviceInfo]:
        ...

    @abstractmethod
    async def get_neighbors(self, target: str, vendor: str = "") -> list[Neighbor]:
        ...

    @abstractmethod
    async def health(self) -> bool:
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        ...


# ---------------------------------------------------------------------------
# ProxyWalker — makes existing collectors work through the proxy
# ---------------------------------------------------------------------------

class ProxyWalker:
    """
    Wraps a DirectWalker, intercepting target IPs and redirecting
    them to localhost:{proxy_port}.

    The existing netaudit collectors call:
        walker.walk("10.2.1.18", oid, auth)

    ProxyWalker translates to:
        inner_walker.walk("127.0.0.1", oid, auth, port=10002)

    The collectors have no idea they're going through a tunnel.
    """

    def __init__(self, inner_walker, port_map: Dict[str, int]):
        """
        Args:
            inner_walker: DirectWalker instance
            port_map: {remote_ip: local_port} from proxy registrations
        """
        self._inner = inner_walker
        self._port_map = port_map

    def _resolve(self, target: str) -> Tuple[str, int]:
        """Map target IP to localhost:port."""
        port = self._port_map.get(target, 161)
        return ("127.0.0.1", port)

    async def walk(self, target: str, oid: str, auth: Any = None,
                   port: int = 161, timeout: float = None, **kwargs):
        host, mapped_port = self._resolve(target)
        return await self._inner.walk(
            host, oid, auth, port=mapped_port, timeout=timeout, **kwargs,
        )

    async def get(self, target: str, oid: str, auth: Any = None,
                  port: int = 161, timeout: float = None, **kwargs):
        host, mapped_port = self._resolve(target)
        return await self._inner.get(
            host, oid, auth, port=mapped_port, timeout=timeout, **kwargs,
        )

    async def get_multiple(self, target: str, oids: list, auth: Any = None,
                           port: int = 161, timeout: float = None, **kwargs):
        host, mapped_port = self._resolve(target)
        return await self._inner.get_multiple(
            host, oids, auth, port=mapped_port, timeout=timeout, **kwargs,
        )


# ---------------------------------------------------------------------------
# Import collectors — netaudit if available, basic fallback if not
# ---------------------------------------------------------------------------

from .collectors import (
    get_system_info as _na_get_system_info,
    get_cdp_neighbors as _na_get_cdp_neighbors,
    get_lldp_neighbors as _na_get_lldp_neighbors,
    get_interface_table as _na_get_interface_table,
    get_interface_table_extended as _na_get_interface_table_extended,
)
HAS_NETAUDIT = True
log.debug("Using netaudit collectors")
# except ImportError:
#
#     HAS_NETAUDIT = False
#     log.debug("netaudit not available — using basic collectors")


# ---------------------------------------------------------------------------
# System OIDs (for basic fallback)
# ---------------------------------------------------------------------------

OID_SYS_DESCR    = "1.3.6.1.2.1.1.1.0"
OID_SYS_OBJECTID = "1.3.6.1.2.1.1.2.0"
OID_SYS_UPTIME   = "1.3.6.1.2.1.1.3.0"
OID_SYS_NAME     = "1.3.6.1.2.1.1.5.0"
OID_SYS_LOCATION = "1.3.6.1.2.1.1.6.0"
OID_SYS_CONTACT  = "1.3.6.1.2.1.1.4.0"


# ---------------------------------------------------------------------------
# SNMP Transport
# ---------------------------------------------------------------------------

class SNMPTransport(Transport):
    """
    SNMP transport via stt-snmp dynamic proxy.

    Registers targets with proxy API, then uses ProxyWalker +
    netaudit's proven collectors for data collection. If netaudit
    isn't installed, falls back to basic system info collection.
    """

    def __init__(
        self,
        walker,          # DirectWalker instance
        api_url: str = "http://127.0.0.1:8901",
        community: str = "public",
        timeout: float = 5.0,
        verbose: bool = False,
    ):
        self._inner_walker = walker
        self.api_url = api_url.rstrip("/")
        self.community = community
        self.timeout = timeout
        self.verbose = verbose
        self._auth = CommunityData(community, mpModel=1)

        # Port map: remote_host → local_port
        self._port_map: Dict[str, int] = {}

        # ProxyWalker wraps the DirectWalker with port redirection
        self._proxy_walker = ProxyWalker(walker, self._port_map)

        self._session: Optional[aiohttp.ClientSession] = None

    @property
    def name(self) -> str:
        return "snmp"

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    async def health(self) -> bool:
        try:
            session = await self._get_session()
            async with session.get(f"{self.api_url}/health") as resp:
                data = await resp.json()
                return data.get("status") == "ok"
        except Exception:
            return False

    async def register(self, remote_host: str, remote_port: int = 161) -> int:
        """Register with proxy API, update port map, return local port."""
        if remote_host in self._port_map:
            return self._port_map[remote_host]

        session = await self._get_session()
        async with session.post(
            f"{self.api_url}/targets",
            json={"remote_host": remote_host, "remote_port": remote_port},
        ) as resp:
            if resp.status not in (200, 201):
                body = await resp.json()
                raise RuntimeError(
                    f"Registration failed for {remote_host}: "
                    f"{body.get('error', resp.status)}"
                )
            data = await resp.json()

        port = data["local_port"]
        # Update the port map — ProxyWalker sees this immediately
        # because it holds a reference to the same dict
        self._port_map[remote_host] = port
        log.debug(f"Registered {remote_host} → localhost:{port}")
        return port

    # ------------------------------------------------------------------
    # System info
    # ------------------------------------------------------------------

    async def get_system_info(self, target: str) -> Optional[DeviceInfo]:
        await self.register(target)

        if HAS_NETAUDIT:
            # Use netaudit's collector — full vendor detection, proper parsing
            info = await _na_get_system_info(
                target, self._auth, self._proxy_walker,
                timeout=self.timeout, verbose=self.verbose,
            )
            if not info:
                return None

            sys_name = info.get("sys_name", "")
            sys_descr = info.get("sys_descr", "")
            if not sys_name and not sys_descr:
                return None

            vendor = info.get("vendor", "unknown")
            if hasattr(vendor, "value"):
                vendor = vendor.value

            # Preserve uptime_ticks as integer
            raw_ticks = info.get("uptime_ticks")
            uptime_ticks = int(raw_ticks) if raw_ticks is not None else None

            return DeviceInfo(
                sys_name=(sys_name or "").strip().rstrip("."),
                sys_descr=sys_descr or "",
                sys_object_id=info.get("sys_object_id", ""),
                uptime=str(raw_ticks) if raw_ticks is not None else "",
                uptime_ticks=uptime_ticks,
                sys_location=info.get("sys_location", ""),
                sys_contact=info.get("sys_contact", ""),
                vendor=vendor,
                model=info.get("model"),
                os_version=info.get("os_version"),
                serial=info.get("serial"),
                discovered_via="snmp",
            )
        else:
            # Basic fallback — just system OIDs via get_multiple
            return await self._basic_system_info(target)

    async def _basic_system_info(self, target: str) -> Optional[DeviceInfo]:
        """Fallback system info when netaudit isn't available."""
        values = await self._proxy_walker.get_multiple(
            target,
            [OID_SYS_NAME, OID_SYS_DESCR, OID_SYS_OBJECTID,
             OID_SYS_UPTIME, OID_SYS_LOCATION, OID_SYS_CONTACT],
            auth=self._auth, timeout=self.timeout,
        )

        sys_name = _val_str(values[0])
        sys_descr = _val_str(values[1])
        if not sys_name and not sys_descr:
            return None

        return DeviceInfo(
            sys_name=sys_name.strip().rstrip("."),
            sys_descr=sys_descr,
            sys_object_id=_val_str(values[2]),
            uptime=_val_str(values[3]),
            sys_location=_val_str(values[4]),
            sys_contact=_val_str(values[5]),
            vendor=_detect_vendor(sys_descr, _val_str(values[2])),
            discovered_via="snmp",
        )

    # ------------------------------------------------------------------
    # Interfaces
    # ------------------------------------------------------------------

    async def get_interfaces(self, target: str) -> list[Interface]:
        """Collect full interface table via IF-MIB + IP-MIB."""
        await self.register(target)

        interfaces_by_index = await _na_get_interface_table_extended(
            target, self._auth, self._proxy_walker,
            timeout=self.timeout, verbose=self.verbose,
        )
        return list(interfaces_by_index.values())

    # ------------------------------------------------------------------
    # Neighbors
    # ------------------------------------------------------------------

    async def get_neighbors(self, target: str, vendor: str = "") -> list[Neighbor]:
        await self.register(target)

        if HAS_NETAUDIT:
            return await self._netaudit_neighbors(target, vendor)
        else:
            # Without netaudit, no neighbor collection — return empty
            # The basic walker can't parse CDP/LLDP properly
            log.warning(
                "netaudit not installed — neighbor collection unavailable. "
                "Install netaudit for CDP/LLDP support."
            )
            return []

    async def _netaudit_neighbors(self, target: str, vendor: str) -> list[Neighbor]:
        """Use netaudit's proven CDP + LLDP collectors."""
        neighbors = []

        # Get interface table for local port resolution
        interface_table = {}
        try:
            interface_table = await _na_get_interface_table(
                target, self._auth, self._proxy_walker,
                timeout=self.timeout, verbose=self.verbose,
            )
        except Exception as e:
            log.debug(f"Interface table collection failed: {e}")

        # CDP
        try:
            cdp_results = await _na_get_cdp_neighbors(
                target, self._auth, self._proxy_walker,
                interface_table=interface_table,
                timeout=self.timeout, verbose=self.verbose,
            )
            for n in cdp_results:
                neighbors.append(Neighbor(
                    protocol="cdp",
                    local_interface=n.local_interface or "",
                    remote_device=n.remote_device or "",
                    remote_interface=n.remote_interface or "",
                    remote_ip=n.remote_ip or "",
                    remote_description=getattr(n, "remote_description", ""),
                ))
        except Exception as e:
            log.debug(f"CDP collection failed: {e}")

        # LLDP
        try:
            lldp_results = await _na_get_lldp_neighbors(
                target, self._auth, self._proxy_walker,
                interface_table=interface_table,
                timeout=self.timeout * 2,  # LLDP walks can be slow
                verbose=self.verbose,
            )
            for n in lldp_results:
                neighbors.append(Neighbor(
                    protocol="lldp",
                    local_interface=n.local_interface or "",
                    remote_device=n.remote_device or "",
                    remote_interface=n.remote_interface or "",
                    remote_ip=n.remote_ip or "",
                    remote_description=getattr(n, "remote_description", ""),
                ))
        except Exception as e:
            log.debug(f"LLDP collection failed: {e}")

        return neighbors


# ---------------------------------------------------------------------------
# SSH Transport — future, uses stt-tcp
# ---------------------------------------------------------------------------

class SSHTransport(Transport):
    """
    SSH transport via stt-tcp tunnel (STUB).

    Future: register target:22 with stt-tcp, SSH to localhost:{port},
    run show commands (show cdp neighbors detail, show lldp neighbors
    detail, show version), parse per-vendor CLI output.
    """

    def __init__(self, api_url: str = "http://127.0.0.1:8902"):
        self.api_url = api_url

    @property
    def name(self) -> str:
        return "ssh"

    async def register(self, remote_host: str, remote_port: int = 22) -> int:
        raise NotImplementedError("SSH transport not yet implemented — use SNMP")

    async def get_system_info(self, target: str) -> Optional[DeviceInfo]:
        raise NotImplementedError("SSH transport not yet implemented")

    async def get_neighbors(self, target: str, vendor: str = "") -> list[Neighbor]:
        raise NotImplementedError("SSH transport not yet implemented")

    async def health(self) -> bool:
        return False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _val_str(val: Any) -> str:
    if val is None:
        return ""
    s = val.prettyPrint() if hasattr(val, "prettyPrint") else str(val)
    if s.startswith("0x"):
        try:
            return bytes.fromhex(s[2:]).decode("utf-8", errors="replace")
        except Exception:
            pass
    return s


def _detect_vendor(sys_descr: str, sys_oid: str = "") -> str:
    sd = sys_descr.lower()
    if "cisco" in sd or "ios" in sd:
        return "cisco"
    if "arista" in sd:
        return "arista"
    if "juniper" in sd or "junos" in sd:
        return "juniper"
    if "linux" in sd:
        return "linux"
    return "unknown"