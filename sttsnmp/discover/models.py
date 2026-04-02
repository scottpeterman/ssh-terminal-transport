"""
sttsnmp.discover.models — Discovery data models.

Lightweight models for device info, neighbors, and topology output.
Compatible with sc-js.app map viewer JSON format.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional, Dict, Any


# ---------------------------------------------------------------------------
# Enums (each defined once)
# ---------------------------------------------------------------------------

class NeighborProtocol(str, Enum):
    """Neighbor discovery protocol."""
    CDP = "cdp"
    LLDP = "lldp"


class DeviceVendor(str, Enum):
    """Known device vendors."""
    CISCO = "cisco"
    ARISTA = "arista"
    JUNIPER = "juniper"
    PALOALTO = "paloalto"
    FORTINET = "fortinet"
    HUAWEI = "huawei"
    HP = "hp"
    LINUX = "linux"
    UNKNOWN = "unknown"


class InterfaceStatus(str, Enum):
    """Interface operational status."""
    UP = "up"
    DOWN = "down"
    ADMIN_DOWN = "admin_down"
    UNKNOWN = "unknown"


class Platform(str, Enum):
    JUNIPER = "juniper"
    ARISTA = "arista"

    @classmethod
    def from_string(cls, value: str) -> "Platform":
        normalized = value.strip().lower()
        for member in cls:
            if member.value == normalized:
                return member
        raise ValueError(f"Unknown platform: {value!r}")


PLATFORM_COMMANDS: dict[Platform, dict[str, str]] = {
    Platform.JUNIPER: {
        "config": "show configuration | display set",
        "version": "show version",
        "pagination": "set cli screen-length 0",
    },
    Platform.ARISTA: {
        "config": "show running-config",
        "version": "show version",
        "pagination": "terminal length 0",
    },
}


# ---------------------------------------------------------------------------
# Transport-level result: what the transport hands back
# ---------------------------------------------------------------------------

@dataclass
class DeviceInfo:
    """System identification from SNMP or SSH."""
    sys_name: str = ""
    sys_descr: str = ""
    sys_object_id: str = ""
    uptime: str = ""
    uptime_ticks: Optional[int] = None
    sys_location: str = ""
    sys_contact: str = ""
    vendor: str = "unknown"
    model: Optional[str] = None
    os_version: Optional[str] = None
    serial: Optional[str] = None
    discovered_via: str = ""  # "snmp" or "ssh"


# ---------------------------------------------------------------------------
# Interface
# ---------------------------------------------------------------------------

@dataclass
class Interface:
    """
    Network interface on a device.

    Populated from IF-MIB walks (ifName, ifDescr, ifAlias).
    Used for resolving ifIndex references in CDP/LLDP tables.
    """
    name: str                                    # ifName (e.g., "Gi0/1", "et-0/0/0")
    if_index: Optional[int] = None               # SNMP ifIndex
    description: Optional[str] = None            # ifDescr (often same as name)
    alias: Optional[str] = None                  # ifAlias (user-configured description)
    ip_address: Optional[str] = None             # Primary IP if assigned
    mac_address: Optional[str] = None            # Interface MAC
    speed_mbps: Optional[int] = None             # Speed in Mbps
    mtu: Optional[int] = None                    # MTU
    status: InterfaceStatus = InterfaceStatus.UNKNOWN

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        d = asdict(self)
        d["status"] = getattr(self.status, "value", self.status)
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Interface":
        """Create from dictionary."""
        data = dict(data)  # shallow copy
        if "status" in data and isinstance(data["status"], str):
            data["status"] = InterfaceStatus(data["status"])
        return cls(**data)


# ---------------------------------------------------------------------------
# Neighbor
# ---------------------------------------------------------------------------

@dataclass
class Neighbor:
    """
    Discovered neighbor from CDP or LLDP.

    Normalizes the different field names and encodings between
    CDP and LLDP into a common format.

    CDP fields: device_id, platform, device_port, ip_address
    LLDP fields: chassis_id, system_name, port_id, management_address
    """
    # Local side (our interface)
    local_interface: str                         # Our interface name
    local_interface_index: Optional[int] = None  # ifIndex if known

    # Remote side identification
    remote_device: str = ""                      # Hostname/device_id/chassis_id
    remote_interface: str = ""                   # Remote port name
    remote_ip: Optional[str] = None              # Management IP (CDP ip_address / LLDP mgmt_address)

    # Additional remote info
    remote_platform: Optional[str] = None        # Platform/model string
    remote_description: Optional[str] = None     # System description
    remote_capabilities: Optional[str] = None    # LLDP capabilities

    # Discovery metadata
    protocol: NeighborProtocol = NeighborProtocol.CDP
    chassis_id: Optional[str] = None             # LLDP chassis ID (often MAC)
    chassis_id_subtype: Optional[int] = None     # LLDP chassis ID subtype
    port_id_subtype: Optional[int] = None        # LLDP port ID subtype

    # Raw data for debugging
    raw_index: Optional[str] = None              # Original SNMP table index

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        d = asdict(self)
        d["protocol"] = getattr(self.protocol, "value", self.protocol)
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Neighbor":
        """Create from dictionary."""
        data = dict(data)  # shallow copy
        if "protocol" in data and isinstance(data["protocol"], str):
            data["protocol"] = NeighborProtocol(data["protocol"])
        return cls(**data)

    @classmethod
    def from_cdp(
        cls,
        local_interface: str,
        device_id: str,
        remote_port: str,
        ip_address: Optional[str] = None,
        platform: Optional[str] = None,
        local_if_index: Optional[int] = None,
        raw_index: Optional[str] = None,
    ) -> "Neighbor":
        """Create Neighbor from CDP data."""
        return cls(
            local_interface=local_interface,
            local_interface_index=local_if_index,
            remote_device=device_id,
            remote_interface=remote_port,
            remote_ip=ip_address,
            remote_platform=platform,
            protocol=NeighborProtocol.CDP,
            raw_index=raw_index,
        )

    @classmethod
    def from_lldp(
        cls,
        local_interface: str,
        system_name: Optional[str] = None,
        port_id: Optional[str] = None,
        management_address: Optional[str] = None,
        chassis_id: Optional[str] = None,
        port_description: Optional[str] = None,
        system_description: Optional[str] = None,
        capabilities: Optional[str] = None,
        chassis_id_subtype: Optional[int] = None,
        port_id_subtype: Optional[int] = None,
        local_if_index: Optional[int] = None,
        raw_index: Optional[str] = None,
    ) -> "Neighbor":
        """Create Neighbor from LLDP data."""
        remote_device = system_name or chassis_id or ""

        return cls(
            local_interface=local_interface,
            local_interface_index=local_if_index,
            remote_device=remote_device,
            remote_interface=port_id or "",
            remote_ip=management_address,
            remote_description=system_description,
            remote_capabilities=capabilities,
            protocol=NeighborProtocol.LLDP,
            chassis_id=chassis_id,
            chassis_id_subtype=chassis_id_subtype,
            port_id_subtype=port_id_subtype,
            raw_index=raw_index,
        )


# ---------------------------------------------------------------------------
# Device — the full discovered record
# ---------------------------------------------------------------------------

@dataclass
class Device:
    """A fully discovered device."""
    # Identity — matches target JSON schema
    hostname: str = ""
    ip_address: str = ""
    sys_name: str = ""
    sys_descr: str = ""
    sys_location: str = ""
    sys_contact: Optional[str] = None
    sys_object_id: str = ""
    uptime_ticks: Optional[int] = None
    vendor: str = "unknown"
    model: Optional[str] = None
    os_version: Optional[str] = None
    serial: Optional[str] = None

    # Collections
    interfaces: list[Interface] = field(default_factory=list)
    neighbors: list[Neighbor] = field(default_factory=list)

    # Discovery metadata (not part of device identity, but useful)
    discovered_via: str = "snmp"
    depth: int = 0
    success: bool = False
    errors: list[str] = field(default_factory=list)
    duration_ms: int = 0

    def to_dict(self) -> dict:
        """
        Serialize to dict matching the target JSON schema.

        Device identity and collections come first; discovery
        metadata trails at the end for tooling that doesn't need it.
        """
        return {
            # Identity
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "sys_name": self.sys_name,
            "sys_descr": self.sys_descr,
            "sys_location": self.sys_location,
            "sys_contact": self.sys_contact,
            "sys_object_id": self.sys_object_id,
            "uptime_ticks": self.uptime_ticks,
            "vendor": self.vendor,
            "model": self.model,
            "os_version": self.os_version,
            "serial": self.serial,
            # Collections
            "interfaces": [iface.to_dict() for iface in self.interfaces],
            "neighbors": [n.to_dict() for n in self.neighbors],
            # Discovery metadata
            "discovered_via": self.discovered_via,
            "depth": self.depth,
            "success": self.success,
            "errors": self.errors,
            "duration_ms": self.duration_ms,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Device":
        """Create Device from dictionary (round-trip support)."""
        data = dict(data)  # shallow copy
        if "interfaces" in data:
            data["interfaces"] = [
                Interface.from_dict(i) if isinstance(i, dict) else i
                for i in data["interfaces"]
            ]
        if "neighbors" in data:
            data["neighbors"] = [
                Neighbor.from_dict(n) if isinstance(n, dict) else n
                for n in data["neighbors"]
            ]
        # Drop unknown keys gracefully
        known = {f.name for f in cls.__dataclass_fields__.values()}
        data = {k: v for k, v in data.items() if k in known}
        return cls(**data)

    def apply_info(self, info: DeviceInfo):
        """
        Merge a DeviceInfo result into this Device.

        Called by the engine after a transport returns system info.
        Keeps Device as the single authoritative record.
        """
        self.sys_name = info.sys_name
        self.sys_descr = info.sys_descr
        self.sys_object_id = info.sys_object_id
        self.uptime_ticks = info.uptime_ticks
        self.sys_location = info.sys_location
        self.sys_contact = info.sys_contact
        self.vendor = info.vendor
        self.model = info.model
        self.os_version = info.os_version
        self.serial = info.serial
        self.discovered_via = info.discovered_via


# ---------------------------------------------------------------------------
# Interface normalization (for topology map)
# ---------------------------------------------------------------------------

_CISCO_REPLACEMENTS = [
    ("GigabitEthernet", "Gi"),
    ("TenGigabitEthernet", "Te"),
    ("TenGigE", "Te"),
    ("FortyGigabitEthernet", "Fo"),
    ("FortyGigE", "Fo"),
    ("HundredGigE", "Hu"),
    ("HundredGigabitEthernet", "Hu"),
    ("TwentyFiveGigE", "Twe"),
    ("FastEthernet", "Fa"),
    ("Ethernet", "Eth"),
]


def normalize_interface(iface: str) -> str:
    if not iface:
        return ""
    result = iface.strip()
    for long, short in _CISCO_REPLACEMENTS:
        if result.startswith(long):
            result = short + result[len(long):]
            break
    # Port-channel
    m = re.match(r"^[Pp]ort-[Cc]hannel(\d+.*)$", result)
    if m:
        result = f"Po{m.group(1)}"
    # VLAN
    m = re.match(r"^[Vv][Ll][Aa][Nn]-?(\d+.*)$", result)
    if m:
        result = f"Vl{m.group(1)}"
    if result.startswith("Null"):
        result = "Nu" + result[4:]
    if result.startswith("Loopback"):
        result = "Lo" + result[8:]
    # Juniper .0 suffix
    result = re.sub(
        r"^((?:xe|ge|et|ae|irb|em|me|fxp)-?\d+(?:/\d+)*)\.0$",
        r"\1", result, flags=re.IGNORECASE,
    )
    return result


def extract_platform(sys_descr: str, vendor: str = "") -> str:
    """Extract concise platform string from sysDescr."""
    if not sys_descr:
        return "Unknown"
    if "Arista" in sys_descr:
        model = "Arista"
        if "vEOS-lab" in sys_descr:
            model = "Arista vEOS-lab"
        m = re.search(r"EOS version (\S+)", sys_descr)
        return f"{model} EOS {m.group(1)}" if m else model
    if "Cisco" in sys_descr:
        model = "Cisco"
        if "IOSv" in sys_descr:
            model = "Cisco IOSv"
        elif "7200" in sys_descr:
            model = "Cisco 7200"
        m = re.search(r"Version (\S+),", sys_descr)
        return f"{model} IOS {m.group(1)}" if m else model
    if "Juniper" in sys_descr or "JUNOS" in sys_descr:
        m = re.search(r"JUNOS (\S+)", sys_descr)
        return f"Juniper JUNOS {m.group(1)}" if m else "Juniper"
    return sys_descr[:50].strip()


# ---------------------------------------------------------------------------
# Topology map builder — sc-js.app compatible JSON
# ---------------------------------------------------------------------------

def build_topology_map(devices: list[Device]) -> dict:
    """
    Build topology map from discovered devices.

    Output format matches sc-js.app Map Viewer expectations:
    {
      "device-hostname": {
        "node_details": {"ip": "10.2.1.1", "platform": "Cisco IOS 15.2"},
        "peers": {
          "peer-hostname": {
            "ip": "10.2.1.2",
            "platform": "Cisco IOS 15.2",
            "connections": [["Gi0/0", "Gi0/1"]]
          }
        }
      }
    }
    """
    # Build device lookup
    device_info: dict[str, Device] = {}
    for d in devices:
        if d.hostname:
            device_info[d.hostname] = d
        if d.sys_name and d.sys_name != d.hostname:
            device_info[d.sys_name] = d
        if d.ip_address:
            device_info[d.ip_address] = d

    def canonical(dev: Device) -> str:
        return dev.sys_name or dev.hostname or dev.ip_address

    discovered_names = set()
    for d in devices:
        cn = canonical(d)
        if cn:
            discovered_names.add(cn)
            if d.sys_name:
                discovered_names.add(d.sys_name)
            if d.hostname:
                discovered_names.add(d.hostname)

    topology = {}
    seen = set()

    for device in devices:
        name = canonical(device)
        if not name or name in seen:
            continue
        seen.add(name)

        node = {
            "node_details": {
                "ip": device.ip_address,
                "platform": extract_platform(device.sys_descr, device.vendor),
            },
            "peers": {},
        }

        peer_conns: dict[str, dict] = {}
        used_local: set[str] = set()

        for neighbor in device.neighbors:
            if not neighbor.remote_device:
                continue

            local_if = normalize_interface(neighbor.local_interface)
            remote_if = normalize_interface(neighbor.remote_interface)
            if not local_if or not remote_if:
                continue
            if local_if in used_local:
                continue

            peer_name = neighbor.remote_device
            canonical_peer = peer_name
            if peer_name in device_info:
                canonical_peer = canonical(device_info[peer_name])

            # Peer platform
            peer_platform = "Unknown"
            if neighbor.remote_description:
                peer_platform = extract_platform(neighbor.remote_description)
            if peer_name in device_info:
                pd = device_info[peer_name]
                peer_platform = extract_platform(pd.sys_descr, pd.vendor)

            if canonical_peer not in peer_conns:
                peer_conns[canonical_peer] = {
                    "ip": neighbor.remote_ip,
                    "platform": peer_platform,
                    "connections": [],
                }

            peer_conns[canonical_peer]["connections"].append([local_if, remote_if])
            used_local.add(local_if)

        node["peers"] = peer_conns
        topology[name] = node

    return topology