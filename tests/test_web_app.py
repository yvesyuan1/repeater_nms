from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from repeater_nms.db.init_db import initialize_database
from repeater_nms.db.models import ActiveAlarm, AlarmEvent, Device, OperationLog, PopupNotification, TrapEvent
from repeater_nms.db.session import reset_engine_cache, session_scope
from repeater_nms.web import create_app


def _build_app(tmp_path: Path):
    database_path = tmp_path / "web.sqlite"
    database_url = f"sqlite:///{database_path.as_posix()}"
    reset_engine_cache()
    initialize_database(database_url, admin_username="admin", admin_password="Admin-Password-123")
    with session_scope(database_url) as session:
        device = Device(
            name="RX10-WEB",
            ip="172.31.3.239",
            snmp_port=161,
            trap_port=1162,
            snmp_version="v2c",
            read_community="CSXT",
            write_community="CSXT",
            is_enabled=True,
            last_poll_status="error",
            last_poll_message="timeout",
        )
        session.add(device)
        session.flush()
        trap = TrapEvent(
            device_id=device.id,
            pdu_id="web-pdu-1",
            source_ip=device.ip,
            source_port=162,
            local_ip="172.25.22.2",
            local_port=1162,
            snmp_version="v2c",
            community_masked="C**T",
            trap_oid="1.3.6.1.4.1.42669.1.1.0.1",
            trap_name="almchg",
            trap_type="alarm",
            sys_uptime="395525258",
            alarm_index="135463178.30",
            alarm_obj="xg.1.10",
            alarm_id="LOS",
            severity_code=5,
            severity="critical",
            status_code=43,
            status="report",
            device_alarm_time_raw="686523786",
            is_active_alarm=True,
            should_popup=True,
            raw_summary="almchg obj=xg.1.10 alarm=LOS",
            raw_json={"source_ip": device.ip},
            translated_json={"alarm_id": "LOS"},
            received_at=datetime.now(timezone.utc),
        )
        session.add(trap)
        session.flush()
        alarm = ActiveAlarm(
            device_id=device.id,
            dedupe_key=f"{device.id}::xg.1.10::LOS",
            alarm_obj="xg.1.10",
            alarm_id="LOS",
            severity_code=5,
            severity="critical",
            status="report",
            first_seen_at=datetime.now(timezone.utc),
            last_seen_at=datetime.now(timezone.utc),
            last_trap_event_id=trap.id,
            occurrence_count=2,
            is_open=True,
        )
        session.add(alarm)
        session.flush()
        session.add(
            AlarmEvent(
                active_alarm_id=alarm.id,
                trap_event_id=trap.id,
                device_id=device.id,
                alarm_obj="xg.1.10",
                alarm_id="LOS",
                severity_code=5,
                severity="critical",
                status_code=43,
                status="report",
                event_type="trap",
                message="almchg obj=xg.1.10 alarm=LOS",
                occurred_at=datetime.now(timezone.utc),
            )
        )
        session.add(
            PopupNotification(
                popup_key=f"{device.id}::xg.1.10::LOS",
                trap_event_id=trap.id,
                active_alarm_id=alarm.id,
                device_id=device.id,
                severity="critical",
                alarm_obj="xg.1.10",
                alarm_id="LOS",
                status="pending",
                is_acknowledged=False,
            )
        )

    app = create_app()
    app.config.update(
        TESTING=True,
        DATABASE_URL=database_url,
        REDIS_URL="redis://127.0.0.1:6399/0",
        SSE_HEARTBEAT_SECONDS=1,
        SECRET_KEY="test-secret",
    )
    return app, database_url


def _login(client):
    return client.post("/login", data={"username": "admin", "password": "Admin-Password-123"}, follow_redirects=True)


def test_login_and_main_pages(tmp_path: Path) -> None:
    app, _database_url = _build_app(tmp_path)
    client = app.test_client()

    response = _login(client)
    assert response.status_code == 200
    assert "活动告警数".encode("utf-8") in response.data

    for path in ["/devices", "/mib-nodes", "/traps", "/alarms", "/logs"]:
        page = client.get(path)
        assert page.status_code == 200


def test_device_and_popup_actions(tmp_path: Path) -> None:
    app, database_url = _build_app(tmp_path)
    client = app.test_client()
    _login(client)

    create_response = client.post(
        "/devices",
        data={
            "name": "RX10-B",
            "ip": "172.31.3.240",
            "snmp_port": "161",
            "trap_port": "1162",
            "snmp_version": "v2c",
            "read_community": "READ1",
            "write_community": "WRITE1",
            "is_enabled": "on",
            "notes": "new device",
        },
        follow_redirects=True,
    )
    assert create_response.status_code == 200

    popup_response = client.get("/api/popup-notifications")
    assert popup_response.status_code == 200
    popups = popup_response.get_json()
    assert len(popups) == 1

    ack_response = client.post(f"/api/popup-notifications/{popups[0]['id']}/ack")
    assert ack_response.status_code == 200
    assert ack_response.get_json()["ok"] is True

    engine = create_engine(database_url)
    with Session(engine) as session:
        assert session.scalar(select(Device).where(Device.name == "RX10-B")) is not None
        popup = session.scalar(select(PopupNotification))
        assert popup is not None
        assert popup.is_acknowledged is True
        logs = session.execute(select(OperationLog).order_by(OperationLog.id.asc())).scalars().all()
        assert any(item.action == "create_device" for item in logs)
        assert any(item.action == "ack_popup" for item in logs)


def test_sse_endpoint_headers(tmp_path: Path) -> None:
    app, _database_url = _build_app(tmp_path)
    client = app.test_client()
    _login(client)

    response = client.get("/api/events/stream", buffered=False)
    first_chunk = next(response.response)
    assert response.status_code == 200
    assert response.mimetype == "text/event-stream"
    assert b"retry:" in first_chunk
