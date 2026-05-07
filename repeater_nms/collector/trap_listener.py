from __future__ import annotations

import logging
import threading
from datetime import timezone
from datetime import datetime
from typing import Callable

from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity import config
from pysnmp.entity.engine import SnmpEngine
from pysnmp.entity.rfc3413 import ntfrcv

from repeater_nms.collector.schemas import TrapPdu, TrapVarBind
from repeater_nms.collector.trap_parser import build_pdu_id


LOGGER = logging.getLogger("repeater_nms.collector.trap_listener")


class PysnmpTrapListener:
    def __init__(
        self,
        bind_host: str,
        bind_port: int,
        communities: list[str],
        handler: Callable[[TrapPdu], None],
    ) -> None:
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.communities = communities
        self.handler = handler
        self.snmp_engine: SnmpEngine | None = None
        self.thread: threading.Thread | None = None
        self.started = threading.Event()
        self.last_community: str | None = None

    def start(self) -> None:
        self.snmp_engine = SnmpEngine()
        transport = udp.UdpTransport().open_server_mode((self.bind_host, self.bind_port))
        config.add_transport(self.snmp_engine, udp.SNMP_UDP_DOMAIN, transport)

        community_names = self.communities or ["public"]
        for index, community in enumerate(dict.fromkeys(community_names)):
            config.add_v1_system(self.snmp_engine, f"repeater-community-{index}", community)

        def remember_community(snmp_engine, execpoint, variables, cbCtx) -> None:
            self.last_community = variables.get("communityName")

        self.snmp_engine.observer.register_observer(remember_community, "rfc2576.processIncomingMsg")
        ntfrcv.NotificationReceiver(self.snmp_engine, self._callback)
        self.thread = threading.Thread(target=self._run_dispatcher, name="repeater-nms-trap-listener", daemon=True)
        self.thread.start()
        self.started.wait(timeout=5)

    def stop(self) -> None:
        if self.snmp_engine is not None:
            try:
                self.snmp_engine.close_dispatcher()
            except Exception:
                LOGGER.exception("failed to close trap listener dispatcher")
        if self.thread is not None:
            self.thread.join(timeout=5)

    def _run_dispatcher(self) -> None:
        assert self.snmp_engine is not None
        self.snmp_engine.transport_dispatcher.job_started(id(self))
        self.started.set()
        try:
            self.snmp_engine.open_dispatcher()
        except Exception:
            LOGGER.exception("trap listener dispatcher crashed")
            raise
        finally:
            try:
                self.snmp_engine.transport_dispatcher.job_finished(id(self))
            except Exception:
                pass

    def _callback(self, snmp_engine, state_reference, context_engine_id, context_name, var_binds, cb_ctx) -> None:
        exec_ctx = snmp_engine.observer.get_execution_context("rfc3412.receiveMessage:request")
        transport_address = exec_ctx.get("transportAddress")
        source_ip, source_port = transport_address[0], int(transport_address[1])
        local_ip, local_port = self.bind_host, self.bind_port
        try:
            local_address = transport_address.get_local_address()
            if local_address:
                local_ip, local_port = local_address[0], int(local_address[1])
        except Exception:
            pass

        normalized_varbinds = [
            TrapVarBind(
                oid=name.prettyPrint(),
                value=int(value) if getattr(value, "isSameTypeWith", None) is None and str(value).isdigit() else value.prettyPrint(),
            )
            for name, value in var_binds
        ]
        meta = {
            "source_ip": source_ip,
            "source_port": str(source_port),
            "local_ip": local_ip,
            "local_port": str(local_port),
            "trap_oid": "",
            "sys_uptime": "",
        }
        pdu = TrapPdu(
            pdu_id=build_pdu_id(meta, normalized_varbinds),
            source_ip=source_ip,
            source_port=source_port,
            local_ip=local_ip,
            local_port=local_port,
            snmp_version="v2c",
            community=self.last_community,
            sys_uptime=next((str(item.value) for item in normalized_varbinds if item.oid == "1.3.6.1.2.1.1.3.0"), None),
            trap_oid=next((str(item.value) for item in normalized_varbinds if item.oid == "1.3.6.1.6.3.1.1.4.1.0"), None),
            received_at=datetime.now(timezone.utc),
            varbinds=normalized_varbinds,
        )
        self.handler(pdu)

