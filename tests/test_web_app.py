from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from repeater_nms.collector.schemas import PublishedTrapEvent
from repeater_nms.db.init_db import initialize_database
from repeater_nms.db.models import (
    ActiveAlarm,
    AlarmEvent,
    AlarmRule,
    Device,
    DeviceProfile,
    MibEnum,
    MibNode,
    OperationLog,
    PollingStrategy,
    PopupNotification,
    TrapEvent,
)
from repeater_nms.db.session import reset_engine_cache, session_scope
from repeater_nms.web import create_app
from repeater_nms.web.utils import alarm_description_label, format_dt


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
            received_at=datetime(2026, 5, 8, 10, 8, 44, tzinfo=timezone.utc),
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
                occurred_at=datetime(2026, 5, 8, 10, 8, 44, tzinfo=timezone.utc),
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
    client.get("/login")
    with client.session_transaction() as session:
        session["captcha_code"] = "ABCD"
    return client.post(
        "/login",
        data={"username": "admin", "password": "Admin-Password-123", "captcha": "ABCD"},
        follow_redirects=True,
    )


def test_login_and_main_pages(tmp_path: Path) -> None:
    app, _database_url = _build_app(tmp_path)
    client = app.test_client()

    response = _login(client)
    assert response.status_code == 200
    assert b"RX10-WEB" in response.data

    for path in ["/devices", "/mib-nodes", "/traps", "/alarms", "/logs", "/traps/1"]:
        page = client.get(path)
        assert page.status_code == 200


def test_alarm_page_contains_chinese_description(tmp_path: Path) -> None:
    app, _database_url = _build_app(tmp_path)
    client = app.test_client()
    _login(client)

    response = client.get("/alarms")
    assert response.status_code == 200
    assert "接口光信号丢失".encode("utf-8") in response.data


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


def test_published_trap_event_payload_has_detail_fields() -> None:
    payload = PublishedTrapEvent(
        trap_event_id=12,
        pdu_id="pdu-1",
        received_at="2026-05-08T10:08:44+00:00",
        received_at_display="2026-05-08 10:08:44",
        source_ip="172.25.22.6",
        device_id=1,
        device_name="RX10-WEB",
        trap_type="alarm",
        trap_type_label="告警 Trap",
        trap_name="almchg",
        trap_name_label="告警变更",
        alarm_obj="xg.1.10",
        alarm_id="LOS",
        severity="critical",
        severity_label="严重",
        status="report",
        status_label="上报",
        device_alarm_time_raw="686523786",
        raw_summary="almchg obj=xg.1.10 alarm=LOS",
        summary_zh="告警变更：设备 RX10-WEB，对象 xg.1.10，告警 LOS",
        translated_json={"alarm_id": "LOS"},
    ).to_dict()

    assert payload["id"] == 12
    assert payload["received_at_display"] == "2026-05-08 10:08:44"
    assert payload["summary_zh"]


def test_format_and_alarm_description_helpers() -> None:
    assert format_dt(datetime(2026, 5, 8, 10, 8, 44, tzinfo=timezone.utc)) == "2026-05-08 10:08:44"
    assert alarm_description_label("LOS") == "接口光信号丢失"
    assert alarm_description_label("CPU_24H") == "24小时CPU利用率高于阈值"


def test_template_crud_actions(tmp_path: Path) -> None:
    app, database_url = _build_app(tmp_path)
    client = app.test_client()
    _login(client)

    create_profile = client.post(
        "/mib-nodes/profiles",
        data={
            "profile_code": "custom_demo",
            "vendor": "演示厂家",
            "model": "演示型号",
            "category": "中继器",
            "parser_key": "bohui_rx10",
            "description": "模板说明",
        },
        follow_redirects=True,
    )
    assert create_profile.status_code == 200
    assert b"custom_demo" in create_profile.data

    create_node = client.post(
        "/mib-nodes/nodes",
        data={
            "profile_code": "custom_demo",
            "oid": "1.3.6.1.4.1.42669.9.1",
            "name": "demoNode",
            "name_zh": "演示节点",
            "category": "demo",
            "category_zh": "演示",
            "access": "read-only",
            "data_type": "Integer",
            "enum_name": "DEMO_ENUM",
            "unit": "%",
            "overview_order": "10",
            "is_pollable": "on",
            "description": "演示节点说明",
        },
        follow_redirects=True,
    )
    assert create_node.status_code == 200

    create_enum = client.post(
        "/mib-nodes/enums",
        data={
            "profile_code": "custom_demo",
            "enum_name": "DEMO_ENUM",
            "code": "1",
            "label": "ok",
            "description": "正常",
        },
        follow_redirects=True,
    )
    assert create_enum.status_code == 200

    create_strategy = client.post(
        "/mib-nodes/strategies",
        data={
            "profile_code": "custom_demo",
            "node_name": "demoNode",
            "node_name_zh": "演示节点",
            "oid": "1.3.6.1.4.1.42669.9.1",
            "category": "demo",
            "poll_interval_seconds": "30",
            "display_order": "5",
            "is_enabled": "on",
            "save_history": "on",
            "show_in_overview": "on",
            "judge_type": "value_equals",
            "expected_value_text": "1",
            "health_on_mismatch": "major",
            "notes": "首页核心指标",
        },
        follow_redirects=True,
    )
    assert create_strategy.status_code == 200

    create_rule = client.post(
        "/mib-nodes/alarm-rules",
        data={
            "profile_code": "custom_demo",
            "alarm_id": "DEMO_ALARM",
            "default_severity": "major",
            "category": "Demo",
            "should_create_active": "on",
            "should_popup": "on",
            "description": "演示告警",
        },
        follow_redirects=True,
    )
    assert create_rule.status_code == 200

    engine = create_engine(database_url)
    with Session(engine) as session:
        profile = session.scalar(select(DeviceProfile).where(DeviceProfile.profile_code == "custom_demo"))
        node = session.scalar(select(MibNode).where(MibNode.profile_code == "custom_demo", MibNode.name == "demoNode"))
        enum_item = session.scalar(select(MibEnum).where(MibEnum.profile_code == "custom_demo", MibEnum.enum_name == "DEMO_ENUM"))
        strategy = session.scalar(
            select(PollingStrategy).where(PollingStrategy.profile_code == "custom_demo", PollingStrategy.node_name == "demoNode")
        )
        rule = session.scalar(select(AlarmRule).where(AlarmRule.profile_code == "custom_demo", AlarmRule.alarm_id == "DEMO_ALARM"))
        assert profile is not None
        assert node is not None
        assert enum_item is not None
        assert strategy is not None
        assert rule is not None
        node_id = node.id
        enum_id = enum_item.id
        strategy_id = strategy.id
        rule_id = rule.id

    update_profile = client.post(
        "/mib-nodes/profiles/custom_demo",
        data={
            "vendor": "修改厂家",
            "model": "修改型号",
            "category": "综合网管",
            "parser_key": "custom_demo",
            "description": "更新说明",
        },
        follow_redirects=True,
    )
    assert update_profile.status_code == 200

    update_node = client.post(
        f"/mib-nodes/nodes/{node_id}",
        data={
            "oid": "1.3.6.1.4.1.42669.9.2",
            "name": "demoNodeRenamed",
            "name_zh": "演示节点已更新",
            "category": "demo",
            "category_zh": "演示",
            "access": "read-write",
            "data_type": "String",
            "enum_name": "DEMO_ENUM",
            "unit": "ms",
            "overview_order": "12",
            "description": "更新后的节点说明",
            "scalar_suffix_zero": "on",
        },
        follow_redirects=True,
    )
    assert update_node.status_code == 200

    update_enum = client.post(
        f"/mib-nodes/enums/{enum_id}",
        data={
            "enum_name": "DEMO_ENUM",
            "code": "2",
            "label": "warn",
            "description": "告警",
        },
        follow_redirects=True,
    )
    assert update_enum.status_code == 200

    update_strategy = client.post(
        f"/mib-nodes/strategies/{strategy_id}",
        data={
            "node_name": "demoMetric",
            "node_name_zh": "演示指标",
            "oid": "1.3.6.1.4.1.42669.9.3",
            "category": "demo",
            "poll_interval_seconds": "45",
            "display_order": "8",
            "is_enabled": "on",
            "show_in_overview": "on",
            "show_in_device_card": "on",
            "judge_type": "enum_equals",
            "expected_value_text": "ok",
            "health_on_mismatch": "critical",
            "notes": "更新后的策略",
        },
        follow_redirects=True,
    )
    assert update_strategy.status_code == 200

    update_rule = client.post(
        f"/mib-nodes/alarm-rules/{rule_id}",
        data={
            "alarm_id": "DEMO_ALARM_2",
            "default_severity": "critical",
            "category": "Demo2",
            "should_popup": "on",
            "description": "更新后的告警",
        },
        follow_redirects=True,
    )
    assert update_rule.status_code == 200

    delete_strategy = client.post(f"/mib-nodes/strategies/{strategy_id}/delete", follow_redirects=True)
    delete_rule = client.post(f"/mib-nodes/alarm-rules/{rule_id}/delete", follow_redirects=True)
    delete_node = client.post(f"/mib-nodes/nodes/{node_id}/delete", follow_redirects=True)
    delete_enum = client.post(f"/mib-nodes/enums/{enum_id}/delete", follow_redirects=True)
    delete_profile = client.post("/mib-nodes/profiles/custom_demo/delete", follow_redirects=True)

    assert delete_strategy.status_code == 200
    assert delete_rule.status_code == 200
    assert delete_node.status_code == 200
    assert delete_enum.status_code == 200
    assert delete_profile.status_code == 200

    with Session(engine) as session:
        assert session.scalar(select(DeviceProfile).where(DeviceProfile.profile_code == "custom_demo")) is None
        assert session.scalar(select(MibNode).where(MibNode.id == node_id)) is None
        assert session.scalar(select(MibEnum).where(MibEnum.id == enum_id)) is None
        assert session.scalar(select(PollingStrategy).where(PollingStrategy.id == strategy_id)) is None
        assert session.scalar(select(AlarmRule).where(AlarmRule.id == rule_id)) is None
