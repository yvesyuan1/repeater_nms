from __future__ import annotations

import asyncio
from datetime import timezone
from datetime import datetime

from pysnmp.hlapi.v1arch.asyncio import CommunityData, SnmpDispatcher, UdpTransportTarget, get_cmd
from pysnmp.smi.rfc1902 import ObjectIdentity, ObjectType

from repeater_nms.collector.schemas import PollResult, PollTarget


class SnmpV2cClient:
    def __init__(self, timeout: float = 2.0, retries: int = 1) -> None:
        self.timeout = timeout
        self.retries = retries

    async def get_value(self, host: str, port: int, community: str, target: PollTarget) -> PollResult:
        collected_at = datetime.now(timezone.utc)
        dispatcher = SnmpDispatcher()
        try:
            transport = await UdpTransportTarget.create(
                (host, port),
                timeout=self.timeout,
                retries=self.retries,
            )
            error_indication, error_status, error_index, varbinds = await get_cmd(
                dispatcher,
                CommunityData(community, mpModel=1),
                transport,
                ObjectType(ObjectIdentity(target.request_oid)),
                lookupMib=False,
            )

            if error_indication:
                return PollResult(
                    device_id=0,
                    device_name="",
                    oid=target.oid,
                    oid_name=target.name,
                    request_oid=target.request_oid,
                    poll_status="error",
                    collected_at=collected_at,
                    error_message=str(error_indication),
                )
            if int(error_status or 0) != 0:
                message = f"error_status={error_status} error_index={error_index}"
                return PollResult(
                    device_id=0,
                    device_name="",
                    oid=target.oid,
                    oid_name=target.name,
                    request_oid=target.request_oid,
                    poll_status="error",
                    collected_at=collected_at,
                    error_message=message,
                )

            oid_text, value_obj = varbinds[0]
            value_text = getattr(value_obj, "prettyPrint", lambda: str(value_obj))()
            value_num: float | None = None
            try:
                value_num = float(value_text)
            except (TypeError, ValueError):
                value_num = None
            return PollResult(
                device_id=0,
                device_name="",
                oid=str(oid_text),
                oid_name=target.name,
                request_oid=target.request_oid,
                poll_status="ok",
                collected_at=collected_at,
                value_raw=value_text,
                value_text=value_text,
                value_num=value_num,
            )
        finally:
            dispatcher.transport_dispatcher.close_dispatcher()

    async def poll_device(self, device_id: int, device_name: str, host: str, port: int, community: str, targets: list[PollTarget]) -> list[PollResult]:
        results: list[PollResult] = []
        for target in targets:
            result = await self.get_value(host, port, community, target)
            result.device_id = device_id
            result.device_name = device_name
            results.append(result)
        return results

    def poll_device_sync(self, device_id: int, device_name: str, host: str, port: int, community: str, targets: list[PollTarget]) -> list[PollResult]:
        return asyncio.run(self.poll_device(device_id, device_name, host, port, community, targets))

