#!/usr/bin/env python3
"""
sttsnmp.discover — Self-contained network discovery over STT tunnels.

Single process runs SSH tunnel + dynamic proxy API + recursive
SNMP discovery. One command, one SSH session, one seed IP.

Commands:
  test      Quick SNMP reachability check through tunnel
  discover  Single device, full collection (sysInfo + neighbors)
  crawl     Recursive neighbor-walk discovery → map.json

Usage:
  python -m sttsnmp.discover test 10.255.255.1 \\
      -c snmpproxy.yaml --community public

  python -m sttsnmp.discover crawl 10.255.255.1 \\
      -c snmpproxy.yaml --community public \\
      --max-depth 10 -o ./output

Transport design:
  Current:  SNMP via stt-snmp proxy + pysnmp (DirectWalker)
  Future:   SSH via stt-tcp (transport abstraction ready)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

from sttsnmp.snmpproxy_local import (
    SSHTunnel,
    ProxyConfig,
    TargetRegistry,
    ProxyAPI,
    load_config,
)

from .transport import SNMPTransport, SSHTransport
from .engine import DiscoveryEngine

try:
    from netaudit.transport.direct import DirectWalker
except ImportError:
    from .walker import DirectWalker

log = logging.getLogger("sttsnmp.discover")


# ---------------------------------------------------------------------------
# Proxy lifecycle
# ---------------------------------------------------------------------------

async def start_proxy(
    cfg: ProxyConfig,
    api_port: int = 8901,
    base_port: int = 10001,
) -> tuple[SSHTunnel, TargetRegistry, ProxyAPI]:
    """Start SSH tunnel + dynamic API. Returns (tunnel, registry, api)."""
    tunnel = SSHTunnel(cfg)

    try:
        tunnel.connect()
    except Exception as e:
        print(f"  Connection failed: {e}", file=sys.stderr)
        sys.exit(1)

    loop = asyncio.get_running_loop()
    tunnel.start_reader(loop)

    registry = TargetRegistry(
        tunnel=tunnel,
        bind_address=cfg.bind_address,
        base_port=base_port,
    )
    registry.set_loop(loop)

    if cfg.targets:
        await registry.seed_from_config(cfg)

    api = ProxyAPI(registry, api_port=api_port)
    await api.start()

    asyncio.create_task(tunnel.keepalive_loop())

    return tunnel, registry, api


async def shutdown(transport: SNMPTransport, tunnel: SSHTunnel, api: ProxyAPI):
    """Clean shutdown — close HTTP session, SSH tunnel, API server."""
    try:
        await transport.close()
    except Exception:
        pass
    try:
        tunnel.shutdown()
    except Exception:
        pass
    try:
        await api.stop()
    except Exception:
        pass


def build_transport(args: argparse.Namespace) -> SNMPTransport:
    """Build SNMPTransport with DirectWalker from CLI args."""
    return SNMPTransport(
        walker=DirectWalker(default_timeout=args.timeout, verbose=args.verbose),
        api_url=f"http://127.0.0.1:{args.api_port}",
        community=args.community,
        timeout=args.timeout,
        verbose=args.verbose,
    )


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

async def cmd_test(args: argparse.Namespace) -> int:
    """Quick SNMP reachability check through the tunnel."""
    cfg = load_config(args.config)
    tunnel, registry, api = await start_proxy(cfg, args.api_port)
    transport = build_transport(args)

    print(f"\n  Testing {args.target} via STT tunnel to {cfg.ssh.host}\n")

    try:
        info = await transport.get_system_info(args.target)

        if not info or (not info.sys_name and not info.sys_descr):
            print(f"  No SNMP response from {args.target}")
            return 1

        print(f"  sysName:     {info.sys_name or 'N/A'}")
        descr = (info.sys_descr or "N/A").split("\n")[0]
        if len(descr) > 80:
            descr = descr[:77] + "..."
        print(f"  sysDescr:    {descr}")
        print(f"  Vendor:      {info.vendor}")
        print(f"  sysLocation: {info.sys_location or 'N/A'}")
        if info.uptime:
            print(f"  Uptime:      {info.uptime}")
        print(f"\n  SNMP reachable.")

        if args.json:
            print(json.dumps({
                "target": args.target,
                "success": True,
                "sys_name": info.sys_name,
                "sys_descr": info.sys_descr,
                "vendor": info.vendor,
            }, indent=2))

        return 0

    finally:
        await shutdown(transport, tunnel, api)


async def cmd_discover(args: argparse.Namespace) -> int:
    """Single device, full collection."""
    cfg = load_config(args.config)
    tunnel, registry, api = await start_proxy(cfg, args.api_port)
    transport = build_transport(args)

    engine = DiscoveryEngine(
        transports=[transport],
        domains=args.domains or [],
        verbose=args.verbose,
    )

    print(f"\n  Discovering {args.target} via STT tunnel to {cfg.ssh.host}")

    try:
        device = await engine.discover_device(args.target)

        if not device.success:
            print(f"\n  Discovery failed: {'; '.join(device.errors)}")
            return 1

        print(f"\n  {'='*55}")
        print(f"  {device.hostname}  [OK]")
        print(f"  {'='*55}")
        print(f"  IP:        {device.ip_address}")
        print(f"  sysName:   {device.sys_name}")
        print(f"  Vendor:    {device.vendor}")
        if device.sys_descr:
            line = device.sys_descr.split("\n")[0][:77]
            print(f"  sysDescr:  {line}")
        if device.sys_location:
            print(f"  Location:  {device.sys_location}")
        if device.model:
            print(f"  Model:     {device.model}")
        if device.serial:
            print(f"  Serial:    {device.serial}")
        print(f"  Interfaces:{len(device.interfaces)}")
        print(f"  Neighbors: {len(device.neighbors)}")
        for n in device.neighbors:
            print(
                f"    {getattr(n.protocol, 'value', n.protocol).upper():4} {n.local_interface:<20} → "
                f"{n.remote_device:<30} {n.remote_interface}"
            )
        print(f"  Duration:  {device.duration_ms}ms")

        if args.json:
            print(json.dumps(device.to_dict(), indent=2))

        if args.output_dir:
            out = Path(args.output_dir)
            out.mkdir(parents=True, exist_ok=True)
            dev_file = out / f"{device.hostname or device.ip_address}.json"
            with open(dev_file, "w") as f:
                json.dump(device.to_dict(), f, indent=2)
            print(f"\n  Saved: {dev_file}")

        return 0

    finally:
        await shutdown(transport, tunnel, api)


async def cmd_crawl(args: argparse.Namespace) -> int:
    """Recursive neighbor-walk discovery."""
    cfg = load_config(args.config)
    tunnel, registry, api = await start_proxy(cfg, args.api_port)
    transport = build_transport(args)

    engine = DiscoveryEngine(
        transports=[transport],
        max_depth=args.max_depth,
        max_concurrent=args.max_concurrent,
        domains=args.domains or [],
        exclude_patterns=args.exclude or [],
        verbose=args.verbose,
    )

    print(f"\n  STT Discover — crawl via {cfg.ssh.host}")
    print(f"  Seeds: {', '.join(args.seeds)}")
    print(f"  Max depth: {args.max_depth}, concurrent: {args.max_concurrent}")
    print(f"  Community: {args.community}")

    try:
        result = await engine.crawl(
            seeds=args.seeds,
            output_dir=args.output_dir,
        )

        if args.json:
            summary = {
                "seeds": args.seeds,
                "discovered": result["discovered"],
                "failed": result["failed"],
                "duration_seconds": result["duration_seconds"],
                "topology": result["topology"],
            }
            print(json.dumps(summary, indent=2))

        print(f"\n  Proxy targets registered: {registry.count}")

        return 0 if result["discovered"] > 0 else 1

    finally:
        await shutdown(transport, tunnel, api)


# ---------------------------------------------------------------------------
# CLI parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument("-c", "--config", required=True,
                        help="STT proxy YAML config file")
    shared.add_argument("--community", default="public",
                        help="SNMP community string (default: public)")
    shared.add_argument("-v", "--verbose", action="store_true",
                        help="Debug output")
    shared.add_argument("--json", action="store_true",
                        help="JSON output")
    shared.add_argument("-t", "--timeout", type=int, default=5,
                        help="SNMP timeout in seconds (default: 5)")
    shared.add_argument("--api-port", type=int, default=8901,
                        help="Proxy API port (default: 8901)")

    parser = argparse.ArgumentParser(
        prog="sttsnmp.discover",
        description="STT Discover — network discovery over SSH terminal tunnels",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m sttsnmp.discover test 10.255.255.1 \\
      -c snmpproxy.yaml --community public

  python -m sttsnmp.discover discover 10.255.255.1 \\
      -c snmpproxy.yaml --community public -d lab.local

  python -m sttsnmp.discover crawl 10.255.255.1 \\
      -c snmpproxy.yaml --community public \\
      --max-depth 10 -d lab.local -o ./output
        """,
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # --- test ---
    test_p = sub.add_parser("test", parents=[shared],
                            help="Quick SNMP reachability check")
    test_p.add_argument("target", help="Device IP to test")

    # --- discover ---
    disc_p = sub.add_parser("discover", parents=[shared],
                            help="Single device discovery")
    disc_p.add_argument("target", help="Device IP to discover")
    disc_p.add_argument("-d", "--domains", action="append",
                        help="Domain suffix (repeatable)")
    disc_p.add_argument("-o", "--output-dir",
                        help="Output directory for device JSON")

    # --- crawl ---
    crawl_p = sub.add_parser("crawl", parents=[shared],
                             help="Recursive discovery → map.json")
    crawl_p.add_argument("seeds", nargs="+", help="Seed device IPs")
    crawl_p.add_argument("-o", "--output-dir",
                         help="Output directory for map.json + device files")
    crawl_p.add_argument("--max-depth", type=int, default=10,
                         help="Max recursion depth (default: 10)")
    crawl_p.add_argument("--max-concurrent", type=int, default=20,
                         help="Max concurrent discoveries (default: 20)")
    crawl_p.add_argument("-d", "--domains", action="append",
                         help="Domain suffix (repeatable)")
    crawl_p.add_argument("-x", "--exclude", action="append",
                         help="Exclude pattern (repeatable)")

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = build_parser()
    args = parser.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s.%(msecs)03d %(name)-20s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )
    if not args.verbose:
        logging.getLogger("paramiko").setLevel(logging.WARNING)
        logging.getLogger("snmpproxy").setLevel(logging.WARNING)
        logging.getLogger("snmpproxy.api").setLevel(logging.INFO)

    handler = {
        "test": cmd_test,
        "discover": cmd_discover,
        "crawl": cmd_crawl,
    }[args.command]

    try:
        sys.exit(asyncio.run(handler(args)))
    except KeyboardInterrupt:
        print("\n  Interrupted.")
        sys.exit(130)
    except Exception as e:
        print(f"\n  Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()