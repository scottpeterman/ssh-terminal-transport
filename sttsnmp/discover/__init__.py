"""
sttsnmp.discover — Self-contained network discovery over STT tunnels.

Bundled with STT to provide zero-infrastructure topology mapping.
One SSH session, one seed IP, the network maps itself.

Transport modes:
  - SNMP via stt-snmp dynamic proxy (working)
  - SSH via stt-tcp (future — transport abstraction ready)

Usage:
  python -m sttsnmp.discover test 10.255.255.1 -c snmpproxy.yaml --community public
  python -m sttsnmp.discover crawl 10.255.255.1 -c snmpproxy.yaml --community public
"""

__version__ = "0.1.0"
