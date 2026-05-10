from __future__ import annotations

import argparse
import logging
import os
import signal
import tempfile
import time
from pathlib import Path

from sqlalchemy import select

from repeater_nms.config import Config
from repeater_nms.collector.locks import CollectorInstanceLock
from repeater_nms.collector.program_analysis import ProgramAnalysisProcessor, UdpProgramAnalysisListener
from repeater_nms.collector.publisher import InMemoryEventPublisher
from repeater_nms.collector.realtime_status import RealtimeStatusProcessor, UdpRealtimeStatusListener
from repeater_nms.collector.runtime import CollectorPipeline
from repeater_nms.collector.trap_listener import PysnmpTrapListener
from repeater_nms.collector.trap_parser import load_fixture_pdus
from repeater_nms.db.models import Device
from repeater_nms.db.session import session_scope

LOGGER = logging.getLogger("repeater_nms.collector")


def configure_logging() -> None:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def _load_trap_communities(database_url: str) -> list[str]:
    communities = set(filter(None, [item.strip() for item in os.getenv("SNMP_TRAP_COMMUNITIES", "").split(",") if item.strip()]))
    with session_scope(database_url) as session:
        rows = session.execute(
            select(Device.read_community).where(Device.is_enabled.is_(True))
        ).all()
    communities.update(value for (value,) in rows if value)
    return sorted(communities)


class CollectorService:
    def __init__(self) -> None:
        self.pipeline = CollectorPipeline(
            Config.DATABASE_URL,
            Config.REDIS_URL,
            Config.REDIS_CHANNEL_PREFIX,
        )
        self.poll_interval = int(os.getenv("POLL_INTERVAL_SECONDS", "60"))
        self.auto_recovery_interval = int(os.getenv("AUTO_RECOVERY_CHECK_INTERVAL_SECONDS", "60"))
        self.enable_periodic_polling = os.getenv("ENABLE_PERIODIC_SNMP_POLLING", "0") == "1"
        self.bind_host = os.getenv("TRAP_BIND_HOST", "0.0.0.0")
        self.bind_port = int(os.getenv("TRAP_BIND_PORT", "1162"))
        self.realtime_bind_host = os.getenv("REALTIME_STATUS_BIND_HOST", "0.0.0.0")
        self.realtime_bind_port = int(os.getenv("REALTIME_STATUS_BIND_PORT", "2000"))
        self.program_bind_host = os.getenv("PROGRAM_ANALYSIS_BIND_HOST", "0.0.0.0")
        self.program_port_ens7f0 = int(os.getenv("PROGRAM_ANALYSIS_ENS7F0_PORT", "2001"))
        self.program_port_ens7f1 = int(os.getenv("PROGRAM_ANALYSIS_ENS7F1_PORT", "2002"))
        self.lock_path = Path(os.getenv("COLLECTOR_LOCK_PATH", Path(tempfile.gettempdir()) / "repeater-nms-collector.lock"))
        self._running = True

    def stop(self, *_args) -> None:
        self._running = False

    def run(self) -> int:
        signal.signal(signal.SIGTERM, self.stop)
        signal.signal(signal.SIGINT, self.stop)
        communities = _load_trap_communities(Config.DATABASE_URL)
        listener = PysnmpTrapListener(
            self.bind_host,
            self.bind_port,
            communities,
            self.pipeline.ingest_pdu,
        )
        realtime_processor = RealtimeStatusProcessor(Config.DATABASE_URL, Config.REDIS_URL)
        realtime_listener = UdpRealtimeStatusListener(
            self.realtime_bind_host,
            self.realtime_bind_port,
            realtime_processor.process_datagram,
        )
        program_processor = ProgramAnalysisProcessor(Config.DATABASE_URL, Config.REDIS_URL)
        program_listeners = [
            UdpProgramAnalysisListener(self.program_bind_host, self.program_port_ens7f0, "ens7f0", program_processor),
            UdpProgramAnalysisListener(self.program_bind_host, self.program_port_ens7f1, "ens7f1", program_processor),
        ]
        with CollectorInstanceLock(self.lock_path):
            listener.start()
            realtime_listener.start()
            for program_listener in program_listeners:
                program_listener.start()
            LOGGER.info(
                "collector started service=%s trap_bind=%s:%s realtime_bind=%s:%s program_bind=%s:%s,%s communities=%s periodic_polling=%s",
                "repeater-nms-collector",
                self.bind_host,
                self.bind_port,
                self.realtime_bind_host,
                self.realtime_bind_port,
                self.program_bind_host,
                self.program_port_ens7f0,
                self.program_port_ens7f1,
                len(communities),
                self.enable_periodic_polling,
            )
            next_poll = 0.0
            next_auto_recovery_check = 0.0
            try:
                while self._running:
                    now = time.time()
                    if self.enable_periodic_polling and now >= next_poll:
                        summary = self.pipeline.poll_enabled_devices_once()
                        LOGGER.info("poll cycle completed devices=%s results=%s", summary.get("devices", 0), summary.get("results", 0))
                        next_poll = now + self.poll_interval
                    if now >= next_auto_recovery_check:
                        summary = self.pipeline.run_auto_recovery_checks()
                        if summary.get("checked", 0):
                            LOGGER.info(
                                "auto recovery check completed checked=%s recovered=%s skipped=%s errored=%s",
                                summary.get("checked", 0),
                                summary.get("recovered", 0),
                                summary.get("skipped", 0),
                                summary.get("errored", 0),
                            )
                        next_auto_recovery_check = now + self.auto_recovery_interval
                    time.sleep(1)
            finally:
                listener.stop()
                realtime_listener.stop()
                for program_listener in program_listeners:
                    program_listener.stop()
        return 0


def main() -> int:
    configure_logging()
    parser = argparse.ArgumentParser(description="repeater-nms collector")
    parser.add_argument("command", nargs="?", default="run", choices=["run", "parse-fixture", "poll-once"])
    parser.add_argument("--fixture", help="Path to sample trap fixture")
    args = parser.parse_args()

    if args.command == "parse-fixture":
        if not args.fixture:
            raise SystemExit("--fixture is required for parse-fixture")
        pipeline = CollectorPipeline(
            Config.DATABASE_URL,
            Config.REDIS_URL,
            Config.REDIS_CHANNEL_PREFIX,
            publisher=InMemoryEventPublisher(),
        )
        pdus = load_fixture_pdus(args.fixture)
        total_events = 0
        for pdu in pdus:
            total_events += len(pipeline.ingest_pdu(pdu))
        LOGGER.info("fixture parsed pdus=%s published_events=%s", len(pdus), total_events)
        return 0

    if args.command == "poll-once":
        pipeline = CollectorPipeline(
            Config.DATABASE_URL,
            Config.REDIS_URL,
            Config.REDIS_CHANNEL_PREFIX,
            publisher=InMemoryEventPublisher(),
        )
        summary = pipeline.poll_enabled_devices_once()
        LOGGER.info("poll once summary=%s", summary)
        return 0

    return CollectorService().run()
