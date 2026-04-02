"""
map_pioneer — ARP Table Collector.

Collects ARP table (MAC to IP mapping) from devices.
Used as fallback for LLDP neighbors without management addresses.
Lifted from Secure Cartography with walker injection.
"""

from typing import Optional, Dict, Any

from ..oids import ARP
from ..parsers import decode_mac, is_valid_ipv4


async def get_arp_table(
    target: str,
    auth: Any,
    walker,
    timeout: float = 5.0,
    verbose: bool = False,
) -> Dict[str, str]:
    """
    Get ARP table from device.

    Queries ipNetToMediaPhysAddress for MAC-to-IP mappings.

    Args:
        target: Device IP address
        auth: SNMP authentication data
        walker: WalkerProtocol implementation
        timeout: Request timeout
        verbose: Enable debug output

    Returns:
        Dict mapping MAC addresses (lowercase, colon-separated) to IP addresses
    """
    def _vprint(msg: str):
        if verbose:
            print(f"  [arp] {msg}")

    mac_to_ip: Dict[str, str] = {}

    _vprint(f"Querying ARP table: {ARP.NET_TO_MEDIA_PHYS_ADDRESS}")

    results = await walker.walk(target, ARP.NET_TO_MEDIA_PHYS_ADDRESS, auth, timeout=timeout)

    for oid, value in results:
        try:
            # Extract IP from OID (last 4 octets)
            parts = oid.split('.')
            if len(parts) >= 4:
                ip_parts = parts[-4:]

                if all(0 <= int(p) <= 255 for p in ip_parts):
                    ip_addr = '.'.join(ip_parts)

                    mac = decode_mac(value)

                    if mac and ':' in mac:
                        mac_lower = mac.lower()
                        mac_to_ip[mac_lower] = ip_addr

                        if verbose:
                            _vprint(f"  {mac_lower} -> {ip_addr}")

        except (ValueError, IndexError):
            continue

    _vprint(f"Found {len(mac_to_ip)} ARP entries")
    return mac_to_ip


def lookup_ip_by_mac(
    mac: str,
    arp_table: Dict[str, str],
) -> Optional[str]:
    """
    Look up IP address by MAC address.

    Normalizes MAC format before lookup.
    """
    if not mac or not arp_table:
        return None

    mac_clean = mac.replace('-', ':').replace('.', '').lower()

    if ':' not in mac_clean and len(mac_clean) == 12:
        mac_clean = ':'.join(mac_clean[i:i+2] for i in range(0, 12, 2))

    return arp_table.get(mac_clean)
