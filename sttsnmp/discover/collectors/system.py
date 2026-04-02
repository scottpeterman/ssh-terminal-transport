"""
map_pioneer — System Info Collector.

Collects system MIB information (sysDescr, sysName, etc.).
Lifted from Secure Cartography with walker injection.
"""

from typing import Optional, Dict, Any

from ..oids import SYSTEM
from ..models import DeviceVendor
from ..parsers import decode_string, decode_int, detect_vendor


async def get_system_info(
    target: str,
    auth: Any,
    walker,
    timeout: float = 5.0,
    verbose: bool = False,
) -> Dict[str, Any]:
    """
    Get system MIB information from device.

    Args:
        target: Device IP address
        auth: SNMP authentication data
        walker: WalkerProtocol implementation
        timeout: Request timeout
        verbose: Enable debug output

    Returns:
        Dictionary with sys_descr, sys_name, sys_location,
        sys_contact, sys_object_id, uptime_ticks, vendor
    """
    # Get all system scalars in one request
    oids = [
        SYSTEM.SYS_DESCR,
        SYSTEM.SYS_NAME,
        SYSTEM.SYS_LOCATION,
        SYSTEM.SYS_CONTACT,
        SYSTEM.SYS_OBJECT_ID,
        SYSTEM.SYS_UPTIME,
    ]

    values = await walker.get_multiple(target, oids, auth, timeout=timeout)

    result = {
        'sys_descr': None,
        'sys_name': None,
        'sys_location': None,
        'sys_contact': None,
        'sys_object_id': None,
        'uptime_ticks': None,
        'vendor': DeviceVendor.UNKNOWN,
    }

    if values[0]:
        result['sys_descr'] = decode_string(values[0])
        result['vendor'] = detect_vendor(result['sys_descr'])

    if values[1]:
        result['sys_name'] = decode_string(values[1])

    if values[2]:
        result['sys_location'] = decode_string(values[2])

    if values[3]:
        result['sys_contact'] = decode_string(values[3])

    if values[4]:
        result['sys_object_id'] = decode_string(values[4])

    if values[5]:
        result['uptime_ticks'] = decode_int(values[5])

    return result


async def get_sys_name(
    target: str,
    auth: Any,
    walker,
    timeout: float = 3.0,
) -> Optional[str]:
    """Quick sysName lookup."""
    value = await walker.get(target, SYSTEM.SYS_NAME, auth, timeout=timeout)

    if value:
        return decode_string(value)
    return None


async def get_sys_descr(
    target: str,
    auth: Any,
    walker,
    timeout: float = 3.0,
) -> Optional[str]:
    """Quick sysDescr lookup."""
    value = await walker.get(target, SYSTEM.SYS_DESCR, auth, timeout=timeout)

    if value:
        return decode_string(value)
    return None


async def detect_device_vendor(
    target: str,
    auth: Any,
    walker,
    timeout: float = 3.0,
) -> tuple[DeviceVendor, Optional[str]]:
    """
    Detect device vendor from sysDescr.

    Returns:
        Tuple of (DeviceVendor, sysDescr string or None)
    """
    sys_descr = await get_sys_descr(target, auth, walker, timeout)
    vendor = detect_vendor(sys_descr)
    return vendor, sys_descr
