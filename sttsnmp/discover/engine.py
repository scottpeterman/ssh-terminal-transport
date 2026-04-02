"""
sttsnmp.discover.engine — Recursive network discovery engine.

Crawls a network from seed devices using pluggable transports.
SNMP-first today, SSH fallback tomorrow — the engine doesn't care
which transport found the data.

Features:
  - Single device discovery (test/discover)
  - Recursive breadth-first crawl with depth limits
  - Concurrent discovery within each depth level
  - Deduplication by hostname/IP/sysName
  - Pluggable transport (SNMP via proxy, SSH via stt-tcp)
  - Produces sc-js.app compatible map.json
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import socket
import time
from pathlib import Path
from typing import Optional

from .models import Device, DeviceInfo, Neighbor, build_topology_map
from .transport import Transport, SNMPTransport

log = logging.getLogger("sttsnmp.discover")

MAC_RE = re.compile(
    r"^([0-9a-fA-F]{2}[:\-.]?){5}[0-9a-fA-F]{2}$|"
    r"^([0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}$"
)


def _is_mac(val: str) -> bool:
    return bool(val and MAC_RE.match(val))


def _is_ip(val: str) -> bool:
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", val or ""))


class DiscoveryEngine:
    """
    Recursive network discovery engine.

    Transport-agnostic: takes a list of Transport objects and tries
    them in order. SNMP is the primary transport. SSH is the future
    fallback for devices where SNMP fails.
    """

    def __init__(
        self,
        transports: list[Transport],
        max_depth: int = 10,
        max_concurrent: int = 20,
        domains: list[str] | None = None,
        exclude_patterns: list[str] | None = None,
        verbose: bool = False,
    ):
        self.transports = transports
        self.max_depth = max_depth
        self.max_concurrent = max_concurrent
        self.domains = domains or []
        self.exclude_patterns = [p.lower() for p in (exclude_patterns or [])]
        self.verbose = verbose

        # Dedup state
        self._claimed: set[str] = set()
        self._discovered_sysnames: set[str] = set()

    def _vprint(self, msg: str, depth: int = 0):
        if self.verbose:
            indent = "  " * (depth + 1)
            print(f"{indent}[discover] {msg}")

    def _normalize(self, name: str) -> str:
        return name.lower().rstrip(".") if name else ""

    def _claim(self, name: str) -> bool:
        n = self._normalize(name)
        if not n or n in self._claimed:
            return False
        self._claimed.add(n)
        return True

    def _register(self, device: Device):
        for ident in [device.ip_address, device.hostname, device.sys_name]:
            if ident:
                self._claimed.add(self._normalize(ident))

    def _should_exclude(self, device: Device) -> bool:
        if not self.exclude_patterns:
            return False
        fields = [
            self._normalize(device.sys_descr),
            self._normalize(device.hostname),
            self._normalize(device.sys_name),
        ]
        return any(
            p in f for p in self.exclude_patterns for f in fields if f
        )

    # ------------------------------------------------------------------
    # Single device discovery
    # ------------------------------------------------------------------

    async def discover_device(
        self, target: str, depth: int = 0,
    ) -> Device:
        """
        Discover a single device. Tries transports in order until
        one succeeds at collecting system info.
        """
        t0 = time.monotonic()
        device = Device(ip_address=target, hostname=target, depth=depth)

        for transport in self.transports:
            try:
                info = await transport.get_system_info(target)
                if info and (info.sys_name or info.sys_descr):
                    # Merge all DeviceInfo fields into Device
                    device.apply_info(info)

                    if info.sys_name and _is_ip(target):
                        device.hostname = _strip_domain(info.sys_name, self.domains)

                    self._vprint(
                        f"OK: {device.hostname} ({device.vendor}) via {transport.name}",
                        depth,
                    )

                    # Collect interfaces
                    if hasattr(transport, "get_interfaces"):
                        try:
                            interfaces = await transport.get_interfaces(target)
                            device.interfaces = interfaces or []
                            self._vprint(
                                f"  {len(device.interfaces)} interfaces",
                                depth,
                            )
                        except Exception as e:
                            device.errors.append(f"Interface collection failed: {e}")
                            self._vprint(f"  Interface collection failed: {e}", depth)

                    # Collect neighbors
                    try:
                        neighbors = await transport.get_neighbors(target, device.vendor)
                        device.neighbors = neighbors
                        self._vprint(
                            f"  {len(neighbors)} neighbors "
                            f"(CDP:{sum(1 for n in neighbors if n.protocol=='cdp')}, "
                            f"LLDP:{sum(1 for n in neighbors if n.protocol=='lldp')})",
                            depth,
                        )
                    except Exception as e:
                        device.errors.append(f"Neighbor collection failed: {e}")
                        self._vprint(f"  Neighbor collection failed: {e}", depth)

                    device.success = True
                    device.duration_ms = int((time.monotonic() - t0) * 1000)
                    return device

            except Exception as e:
                self._vprint(
                    f"FAIL: {target} via {transport.name}: {e}", depth,
                )
                device.errors.append(f"{transport.name}: {e}")

        device.duration_ms = int((time.monotonic() - t0) * 1000)
        return device

    # ------------------------------------------------------------------
    # Recursive crawl
    # ------------------------------------------------------------------

    async def crawl(
        self,
        seeds: list[str],
        output_dir: Optional[str | Path] = None,
    ) -> dict:
        """
        Recursive breadth-first discovery from seed devices.

        Returns a summary dict. Writes map.json to output_dir if specified.
        """
        self._claimed.clear()
        self._discovered_sysnames.clear()

        t0 = time.monotonic()
        all_devices: list[Device] = []
        total_attempted = 0
        total_failed = 0

        # Queue seeds
        current_batch: list[tuple[str, int]] = []
        for seed in seeds:
            if self._claim(seed):
                current_batch.append((seed, 0))

        # Breadth-first crawl
        while current_batch:
            depth = current_batch[0][1]
            batch_size = len(current_batch)

            print(f"\n  Depth {depth}: {batch_size} device{'s' if batch_size != 1 else ''}")

            # Discover all devices at this depth, with concurrency limit
            sem = asyncio.Semaphore(self.max_concurrent)

            async def _discover(target, d):
                async with sem:
                    return await self.discover_device(target, d)

            tasks = [_discover(t, d) for t, d in current_batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            next_batch: list[tuple[str, int]] = []

            for i, result in enumerate(results):
                target = current_batch[i][0]
                total_attempted += 1

                if isinstance(result, Exception):
                    total_failed += 1
                    print(f"    FAIL  {target}: {result}")
                    continue

                device = result
                self._register(device)

                if not device.success:
                    total_failed += 1
                    error = "; ".join(device.errors) or "No SNMP response"
                    print(f"    FAIL  {target}: {error}")
                    continue

                # Post-discovery sysName dedup
                if device.sys_name:
                    norm_sn = self._normalize(device.sys_name)
                    if norm_sn in self._discovered_sysnames:
                        self._vprint(f"Dedup: {target} is {device.sys_name} (already found)", depth)
                        continue
                    self._discovered_sysnames.add(norm_sn)

                # Exclusion check
                if self._should_exclude(device):
                    self._vprint(f"Excluded: {device.hostname}", depth)
                    continue

                all_devices.append(device)
                n_count = len(device.neighbors)
                via = device.discovered_via
                print(
                    f"    OK    {device.ip_address:<16} "
                    f"{device.hostname:<30} "
                    f"{device.vendor:<10} "
                    f"neighbors:{n_count}  "
                    f"[{via}] {device.duration_ms}ms"
                )

                # Queue neighbors for next depth
                if depth < self.max_depth:
                    for neighbor in device.neighbors:
                        n_device = neighbor.remote_device
                        n_ip = neighbor.remote_ip
                        mgmt_ips = getattr(neighbor, "mgmt_ips", None)

                        # Dump raw neighbor fields for debugging
                        self._vprint(
                            f"Neighbor: device={n_device!r} ip={n_ip!r} "
                            f"mgmt_ips={mgmt_ips!r} proto={neighbor.protocol} "
                            f"local_if={neighbor.local_interface!r} "
                            f"remote_if={neighbor.remote_interface!r}",
                            depth,
                        )

                        # Skip MAC-only neighbors without any IP path
                        if _is_mac(n_device or "") and not n_ip and not mgmt_ips:
                            self._vprint(f"  → SKIP: MAC-only, no IP path", depth)
                            continue
                        if n_ip and _is_mac(n_ip):
                            n_ip = ""

                        # Demote MAC chassis IDs — if n_device is a MAC
                        # address, move it aside so hostnames and IPs take
                        # priority for dedup and display.
                        n_mac = ""
                        if _is_mac(n_device or ""):
                            n_mac = n_device
                            n_device = ""
                            self._vprint(f"  → MAC demoted: {n_mac}", depth)

                        # Clean hostname
                        if n_device:
                            n_device = _strip_domain(n_device, self.domains)

                        # Resolution chain: mgmt IP → reported IP → DNS → hostname
                        crawl_target = _resolve_crawl_target(n_ip, n_device, mgmt_ips)
                        # Dedup prefers hostname over IP over MAC
                        dedup_key = n_device or n_ip or crawl_target or n_mac
                        if not crawl_target or not dedup_key:
                            self._vprint(f"  → SKIP: no crawl target resolved", depth)
                            continue

                        self._vprint(
                            f"  → crawl_target={crawl_target!r} "
                            f"dedup_key={dedup_key!r}",
                            depth,
                        )

                        # Check the actual crawl target FIRST — prevents
                        # duplicate crawls when multiple neighbors report
                        # the same IP with different hostnames
                        crawl_norm = self._normalize(crawl_target)
                        if crawl_norm in self._claimed:
                            continue

                        if self._claim(dedup_key):
                            # Claim ALL identifiers BEFORE adding to batch
                            if n_ip and n_ip != dedup_key:
                                self._claim(n_ip)
                            if n_device and n_device != dedup_key:
                                self._claim(n_device)
                            if n_mac and n_mac != dedup_key:
                                self._claim(n_mac)
                            if crawl_target != dedup_key:
                                self._claim(crawl_target)
                            # Claim any mgmt IPs too
                            for mip in (mgmt_ips or []):
                                if mip:
                                    self._claim(mip)
                            next_batch.append((crawl_target, depth + 1))

            current_batch = next_batch

        # Summary
        elapsed = time.monotonic() - t0
        ok = len(all_devices)

        print(f"\n{'='*60}")
        print(f"  Discovery complete")
        print(f"{'='*60}")
        print(f"  Devices:   {ok} discovered, {total_failed} failed")
        print(f"  Duration:  {elapsed:.1f}s")

        # Build and save topology map
        topology = build_topology_map(all_devices)

        if output_dir:
            out = Path(output_dir)
            out.mkdir(parents=True, exist_ok=True)
            map_file = out / "map.json"
            with open(map_file, "w") as f:
                json.dump(topology, f, indent=2)
            print(f"  Map:       {map_file} ({len(topology)} devices)")

            # Also save per-device JSON
            for device in all_devices:
                dev_dir = out / (device.hostname or device.ip_address)
                dev_dir.mkdir(parents=True, exist_ok=True)
                with open(dev_dir / "device.json", "w") as f:
                    json.dump(device.to_dict(), f, indent=2)

        return {
            "success": True,
            "devices": all_devices,
            "topology": topology,
            "discovered": ok,
            "failed": total_failed,
            "duration_seconds": round(elapsed, 1),
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _strip_domain(hostname: str, domains: list[str]) -> str:
    """Strip domain suffix from hostname if it matches configured domains."""
    if not hostname:
        return ""
    hostname = hostname.strip().rstrip(".")
    for domain in domains:
        suffix = f".{domain}"
        if hostname.lower().endswith(suffix.lower()):
            return hostname[:-len(suffix)]
    return hostname


def _is_bogon_target(val: str) -> bool:
    """
    Filter targets that should never be crawled.

    These waste 10+ seconds each on guaranteed timeouts:
      - Docker/container bridges (172.17.0.x)
      - Loopback, link-local, multicast
      - RFC6598 shared address space (100.64.0.0/10 — Tailscale, CGNAT)
      - Broadcast, unspecified

    We do NOT filter all RFC1918 (10.x, 172.16-31.x, 192.168.x) —
    those are management plane IPs you actually want to crawl.
    """
    if not val or not _is_ip(val):
        return False

    try:
        addr = ipaddress.ip_address(val)
    except ValueError:
        return False

    # Always skip
    if addr.is_loopback:        # 127.0.0.0/8
        return True
    if addr.is_link_local:      # 169.254.0.0/16
        return True
    if addr.is_multicast:       # 224.0.0.0/4
        return True
    if addr.is_unspecified:     # 0.0.0.0
        return True

    return False


def _dns_resolve(hostname: str) -> str:
    """
    Try DNS resolution of a hostname. Returns IP string or empty.

    Synchronous, but fast — typical DNS timeout is 2-5s, and most
    internal hostnames resolve in <10ms. Called only when the neighbor
    has a hostname but no IP, which is common in LLDP-only environments.
    """
    if not hostname or _is_ip(hostname):
        return hostname  # already an IP

    try:
        result = socket.getaddrinfo(hostname, None, socket.AF_INET)
        if result:
            return result[0][4][0]  # first IPv4 address
    except (socket.gaierror, OSError):
        pass
    return ""


def _resolve_crawl_target(
    n_ip: str,
    n_device: str,
    mgmt_ips: list[str] | None = None,
) -> str:
    """
    Neighbor resolution chain — try the best reachable address.

    Priority:
      1. LLDP management IP (from lldpRemManAddrTable) — most likely
         to be the actual management plane address
      2. Neighbor-reported IP (CDP address, LLDP chassis IP) — often
         a peering interface IP, not the management IP
      3. DNS resolution of hostname — works when the network has DNS
         entries matching device hostnames (common in enterprise)
      4. Hostname as-is — last resort, relies on the OS resolver

    Returns the best available crawl target, or empty string if
    all options are exhausted or filtered as bogons.
    """
    # 1. LLDP management IP — best candidate
    for mip in (mgmt_ips or []):
        if mip and _is_ip(mip) and not _is_bogon_target(mip):
            return mip

    # 2. Neighbor-reported IP
    if n_ip and _is_ip(n_ip) and not _is_bogon_target(n_ip):
        return n_ip

    # 3. DNS resolution of hostname
    if n_device and not _is_ip(n_device):
        resolved = _dns_resolve(n_device)
        if resolved and not _is_bogon_target(resolved):
            return resolved

    # 4. Hostname as-is (will fail if DNS can't resolve on the proxy side)
    if n_device and not _is_bogon_target(n_device):
        return n_device

    return ""