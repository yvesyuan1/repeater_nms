from __future__ import annotations

from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from repeater_nms.collector.mib import MibResolver
from repeater_nms.collector.publisher import InMemoryEventPublisher
from repeater_nms.collector.runtime import CollectorPipeline
from repeater_nms.collector.trap_parser import TrapParser, load_fixture_pdus
from repeater_nms.db.init_db import initialize_database
from repeater_nms.db.models import ActiveAlarm, Device, PopupNotification, TrapEvent
from repeater_nms.db.session import reset_engine_cache


FIXTURE_PATH = Path("tests/fixtures/rx10_almchg_tcpdump_sample.txt")


def _prepare_pipeline(tmp_path: Path, with_device: bool = True) -> tuple[str, CollectorPipeline]:
    database_path = tmp_path / "stage3.sqlite"
    database_url = f"sqlite:///{database_path.as_posix()}"
    reset_engine_cache()
    initialize_database(database_url, admin_username="admin", admin_password="Stage3-Admin-Password")
    if with_device:
        from repeater_nms.db.session import session_scope

        with session_scope(database_url) as session:
            session.add(
                Device(
                    name="RX10-A",
                    ip="172.31.3.239",
                    snmp_port=161,
                    trap_port=1162,
                    snmp_version="v2c",
                    read_community="CSXT",
                    write_community="CSXT",
                    is_enabled=True,
                )
            )
    pipeline = CollectorPipeline(
        database_url,
        "redis://127.0.0.1:6379/15",
        "repeater_nms",
        publisher=InMemoryEventPublisher(),
    )
    return database_url, pipeline


def test_fixture_parser_splits_alarm_groups() -> None:
    pdus = load_fixture_pdus(FIXTURE_PATH)
    parser = TrapParser(MibResolver())

    parsed0 = parser.parse_pdu(pdus[0])
    assert parsed0.parse_status == "parsed"
    assert len(parsed0.events) == 1
    assert parsed0.events[0].alarm_obj == "xg.1.10"
    assert parsed0.events[0].alarm_id == "LOS"
    assert parsed0.events[0].severity == "critical"
    assert parsed0.events[0].status == "report"
    assert parsed0.events[0].is_active_alarm is True
    assert parsed0.events[0].should_popup is True

    parsed2 = parser.parse_pdu(pdus[2])
    assert len(parsed2.events) == 3
    assert {item.alarm_id for item in parsed2.events} == {"IOP_24L", "IOP_15L", "LOS"}
    assert all(item.severity == "cleared" for item in parsed2.events)
    assert all(item.status == "close" for item in parsed2.events)

    parsed3 = parser.parse_pdu(pdus[3])
    assert len(parsed3.events) == 4
    assert {item.alarm_obj for item in parsed3.events} == {"xg.1.10", "xg.1.9"}
    assert all(item.severity == "warning" for item in parsed3.events)
    assert all(item.should_popup is False for item in parsed3.events)


def test_pipeline_persists_and_publishes_unknown_device(tmp_path: Path) -> None:
    database_url, pipeline = _prepare_pipeline(tmp_path, with_device=False)
    publisher = pipeline.publisher
    pdus = load_fixture_pdus(FIXTURE_PATH)

    published = pipeline.ingest_pdu(pdus[0])
    assert len(published) == 1
    assert publisher.events[0]["device_name"] == "未知设备"
    assert publisher.events[0]["severity"] == "critical"

    session = Session(bind=__import__("sqlalchemy").create_engine(database_url))
    try:
        trap_event = session.scalar(select(TrapEvent))
        assert trap_event is not None
        assert trap_event.device_id is None
    finally:
        session.close()


def test_pipeline_handles_active_alarm_lifecycle_and_popup_rules(tmp_path: Path) -> None:
    database_url, pipeline = _prepare_pipeline(tmp_path, with_device=True)
    publisher = pipeline.publisher
    pdus = load_fixture_pdus(FIXTURE_PATH)

    pipeline.ingest_pdu(pdus[0])
    pipeline.ingest_pdu(pdus[1])
    pipeline.ingest_pdu(pdus[3])
    pipeline.ingest_pdu(pdus[2])

    engine = __import__("sqlalchemy").create_engine(database_url)
    with Session(engine) as session:
        trap_events = session.execute(select(TrapEvent).order_by(TrapEvent.id)).scalars().all()
        assert len(trap_events) == 1 + 1 + 4 + 3

        active_alarms = session.execute(select(ActiveAlarm)).scalars().all()
        indexed = {(item.alarm_obj, item.alarm_id): item for item in active_alarms}
        assert indexed[("xg.1.10", "LOS")].is_open is True
        assert indexed[("xg.1.10", "LsrOffline")].is_open is True
        assert indexed[("xg.1.10", "IOP_15L")].is_open is False
        assert ("xg.1.10", "IOP_24L") not in indexed
        assert ("xg.1.9", "LOS") not in indexed
        assert indexed[("xg.1.9", "IOP_24L")].is_open is True
        assert indexed[("xg.1.9", "LB_24L")].is_open is True

        popups = session.execute(select(PopupNotification)).scalars().all()
        popup_keys = {item.popup_key for item in popups}
        assert any("xg.1.10::LOS" in key for key in popup_keys)
        assert any("xg.1.10::LsrOffline" in key for key in popup_keys)
        assert all("IOP_15L" not in key for key in popup_keys)

    assert len(publisher.events) == len(trap_events)
    warning_events = [item for item in publisher.events if item["severity"] == "warning"]
    assert len(warning_events) == 4
    assert all(item["device_name"] == "RX10-A" for item in publisher.events)
