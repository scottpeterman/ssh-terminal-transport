"""
map_pioneer — Direct Walker.

pysnmp async SNMP walker — local machine sends UDP directly
to device:161. This is the SC SNMPWalker lifted and wrapped
to satisfy WalkerProtocol.

This is the default strategy when you have direct route to
the management plane.

Usage:
    walker = DirectWalker(timeout=5.0, verbose=True)
    results = await walker.walk(target, oid, auth)
"""

import asyncio
from datetime import datetime
from typing import List, Tuple, Optional, Any, Union

from pysnmp.hlapi.v3arch.asyncio import (
    bulk_cmd, get_cmd,
    SnmpEngine, CommunityData, UsmUserData,
    UdpTransportTarget, ContextData,
    ObjectType, ObjectIdentity,
)

# Standalone — no base protocol dependency needed.
# DirectWalker is duck-typed; walk()/get()/get_multiple() is the interface.
WalkResult = List[Tuple[str, Any]]

# Type alias
AuthData = Union[CommunityData, UsmUserData]


class DirectWalker:
    """
    Async SNMP walker using pysnmp — direct UDP to device.

    Lifted from SC's SNMPWalker. Implements WalkerProtocol so it's
    interchangeable with JumpHostWalker and STTWalker.
    """

    def __init__(
        self,
        engine: Optional[SnmpEngine] = None,
        default_timeout: float = 3.0,
        default_retries: int = 1,
        bulk_size: int = 25,
        max_iterations: int = 1500,
        verbose: bool = False,
    ):
        self.engine = engine or SnmpEngine()
        self.default_timeout = default_timeout
        self.default_retries = default_retries
        self.bulk_size = bulk_size
        self.max_iterations = max_iterations
        self.verbose = verbose

    def _vprint(self, message: str, level: int = 1):
        if self.verbose:
            indent = "  " * level
            print(f"{indent}[snmp-direct] {message}")

    async def walk(
        self,
        target: str,
        oid: str,
        auth: Optional[Any] = None,
        port: int = 161,
        timeout: Optional[float] = None,
        retries: Optional[int] = None,
        max_iterations: Optional[int] = None,
        **kwargs,
    ) -> WalkResult:
        """
        Walk an SNMP table using GETBULK.

        Walks all OIDs under the given base OID until leaving
        the table (OID no longer starts with base).
        """
        if not auth:
            raise ValueError("No auth data provided")

        timeout = timeout or self.default_timeout
        retries = retries if retries is not None else self.default_retries
        max_iterations = max_iterations or self.max_iterations

        results: WalkResult = []
        base_oid = oid if isinstance(oid, str) else str(oid)

        self._vprint(f"Walking OID: {base_oid} on {target}", 1)
        start_time = datetime.now()

        last_oid = oid
        iteration = 0

        for iteration in range(max_iterations):
            try:
                if isinstance(last_oid, str):
                    last_oid_obj = ObjectIdentity(last_oid)
                else:
                    last_oid_obj = last_oid

                transport = await UdpTransportTarget.create(
                    (target, port),
                    timeout=timeout,
                    retries=retries,
                )

                error_indication, error_status, error_index, var_binds = (
                    await asyncio.wait_for(
                        bulk_cmd(
                            self.engine,
                            auth,
                            transport,
                            ContextData(),
                            0,
                            self.bulk_size,
                            ObjectType(last_oid_obj),
                            lexicographicMode=False,
                        ),
                        timeout=timeout + 2,
                    )
                )

                if error_indication:
                    if iteration == 0:
                        self._vprint(f"Error on {base_oid}: {error_indication}", 1)
                    break

                if error_status:
                    if iteration == 0:
                        self._vprint(
                            f"Status error on {base_oid}: "
                            f"{error_status.prettyPrint()}",
                            1,
                        )
                    break

                if not var_binds:
                    break

                in_table = False
                count_in_table = 0

                for var_bind in var_binds:
                    oid_str = str(var_bind[0])
                    if oid_str.startswith(base_oid):
                        results.append((oid_str, var_bind[1]))
                        last_oid = var_bind[0]
                        in_table = True
                        count_in_table += 1

                if not in_table:
                    break

                if len(var_binds) < self.bulk_size:
                    break

            except asyncio.TimeoutError:
                if iteration == 0:
                    self._vprint(f"Timeout on {base_oid}", 1)
                break

            except Exception as e:
                if iteration == 0:
                    self._vprint(
                        f"Exception on {base_oid}: {type(e).__name__}: {e}",
                        1,
                    )
                break

        elapsed = (datetime.now() - start_time).total_seconds()
        self._vprint(
            f"Walk complete: {len(results)} results in {elapsed:.2f}s "
            f"({iteration + 1} iterations)",
            1,
        )

        return results

    async def get(
        self,
        target: str,
        oid: str,
        auth: Optional[Any] = None,
        port: int = 161,
        timeout: Optional[float] = None,
        retries: Optional[int] = None,
        **kwargs,
    ) -> Optional[Any]:
        """Get a single SNMP value."""
        if not auth:
            raise ValueError("No auth data provided")

        timeout = timeout or self.default_timeout
        retries = retries if retries is not None else self.default_retries

        if isinstance(oid, str):
            oid_obj = ObjectIdentity(oid)
        else:
            oid_obj = oid

        try:
            transport = await UdpTransportTarget.create(
                (target, port),
                timeout=timeout,
                retries=retries,
            )

            error_indication, error_status, error_index, var_binds = (
                await asyncio.wait_for(
                    get_cmd(
                        self.engine,
                        auth,
                        transport,
                        ContextData(),
                        ObjectType(oid_obj),
                    ),
                    timeout=timeout + 2,
                )
            )

            if error_indication or error_status:
                return None

            if var_binds:
                return var_binds[0][1]

            return None

        except Exception:
            return None

    async def get_multiple(
        self,
        target: str,
        oids: List[str],
        auth: Optional[Any] = None,
        port: int = 161,
        timeout: Optional[float] = None,
        **kwargs,
    ) -> List[Optional[Any]]:
        """Get multiple SNMP values in one request."""
        if not auth:
            raise ValueError("No auth data provided")

        timeout = timeout or self.default_timeout

        object_types = []
        for oid in oids:
            if isinstance(oid, str):
                object_types.append(ObjectType(ObjectIdentity(oid)))
            else:
                object_types.append(ObjectType(oid))

        try:
            transport = await UdpTransportTarget.create(
                (target, port),
                timeout=timeout,
                retries=self.default_retries,
            )

            error_indication, error_status, error_index, var_binds = (
                await asyncio.wait_for(
                    get_cmd(
                        self.engine,
                        auth,
                        transport,
                        ContextData(),
                        *object_types,
                    ),
                    timeout=timeout + 2,
                )
            )

            if error_indication or error_status:
                return [None] * len(oids)

            return [vb[1] if vb else None for vb in var_binds]

        except Exception:
            return [None] * len(oids)
