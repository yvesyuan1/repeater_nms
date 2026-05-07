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
from repeater_nms.collector.publisher import InMemoryEventPublisher
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
        self.bind_host = os.getenv("TRAP_BIND_HOST", "0.0.0.0")
        self.bind_port = int(os.getenv("TRAP_BIND_PORT", "1162"))
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
        with CollectorInstanceLock(self.lock_path):
            listener.start()
            LOGGER.info(
                "collector started service=%s bind=%s:%s communities=%s",
                "repeater-nms-collector",
                self.bind_host,
                self.bind_port,
                len(communities),
            )
            next_poll = 0.0
            try:
                while self._running:
                    now = time.time()
                    if now >= next_poll:
                        summary = self.pipeline.poll_enabled_devices_once()
                        LOGGER.info("poll cycle completed devices=%s results=%s", summary.get("devices", 0), summary.get("results", 0))
                        next_poll = now + self.poll_interval
                    time.sleep(1)
            finally:
                listener.stop()
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
