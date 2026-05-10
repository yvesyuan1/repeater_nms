from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from repeater_nms.collector.program_analysis import ProgramAnalysisProcessor
from repeater_nms.collector.realtime_status import RealtimeStatusProcessor
from repeater_nms.collector.runtime import CollectorPipeline
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
from repeater_nms.db.seed_data import DEFAULT_PROFILE_CODE
from repeater_nms.db.session import reset_engine_cache, session_scope
from repeater_nms.web import create_app
from repeater_nms.web.routes import _effective_event_severity, _event_is_current_open
from repeater_nms.web.utils import alarm_description_label, format_dt


class FakeSnmpClient:
    def __init__(self) -> None:
        self.values = {
            "1.3.6.1.4.1.42669.2.1.0": "1",
            "1.3.6.1.4.1.42669.2.2.0": "work-port-1",
            "1.3.6.1.4.1.42669.2.3.0": "prt-port-1",
            "1.3.6.1.4.1.42669.2.4.0": "1",
            "1.3.6.1.4.1.42669.2.5.0": "30",
            "1.3.6.1.4.1.42669.2.6.0": "150",
            "1.3.6.1.4.1.42669.2.7.0": "20",
            "1.3.6.1.4.1.42669.2.8.0": "7",
            "1.3.6.1.4.1.42669.2.9.0": "work",
            "1.3.6.1.4.1.42669.2.10.0": "0",
            "1.3.6.1.4.1.42669.3.1.0": "1",
            "1.3.6.1.4.1.42669.3.2.0": "172.25.22.7",
            "1.3.6.1.4.1.42669.3.3.0": "0",
            "1.3.6.1.4.1.42669.3.4.0": "self",
        }

    def get_oid_sync(self, host, port, community, oid):
        value = self.values.get(oid)
        if value is None:
            return {"ok": False, "error": "timeout"}
        value_num = None
        try:
            value_num = float(value)
        except ValueError:
            value_num = None
        return {"ok": True, "oid": oid, "value_raw": value, "value_text": value, "value_num": value_num}

    def set_oid_sync(self, host, port, community, oid, data_type, value):
        self.values[oid] = str(value)
        return {"ok": True, "oid": oid, "value_text": str(value)}


class FakeRedis:
    def __init__(self) -> None:
        self.values: dict[str, object] = {}
        self.lists: dict[str, list[str]] = {}
        self.pipeline_commands: list[tuple[str, tuple]] = []

    def setex(self, key: str, ttl: int, value: str) -> None:
        self.values[key] = value

    def expire(self, key: str, ttl: int) -> None:
        return None

    def get(self, key: str) -> str | None:
        return self.values.get(key)

    def hset(self, key: str, field: str, value: str) -> None:
        self.values.setdefault(key, {})
        self.values[key][field] = value

    def hgetall(self, key: str) -> dict[str, str]:
        value = self.values.get(key, {})
        return value if isinstance(value, dict) else {}

    def rpush(self, key: str, value: str) -> None:
        self.lists.setdefault(key, []).append(value)

    def ltrim(self, key: str, start: int, end: int) -> None:
        rows = self.lists.get(key, [])
        if start < 0:
            start = max(len(rows) + start, 0)
        if end < 0:
            end = len(rows) + end
        self.lists[key] = rows[start : end + 1]

    def lrange(self, key: str, start: int, end: int) -> list[str]:
        rows = self.lists.get(key, [])
        if start < 0:
            start = max(len(rows) + start, 0)
        if end < 0:
            end = len(rows) + end
        return rows[start : end + 1]

    def pipeline(self):
        return self

    def execute(self) -> None:
        return None


def _build_app(tmp_path: Path):
    database_path = tmp_path / "web.sqlite"
    database_url = f"sqlite:///{database_path.as_posix()}"
    reset_engine_cache()
    initialize_database(database_url, admin_username="admin", admin_password="Admin-Password-123")
    with session_scope(database_url) as session:
        device = Device(
            name="RX10-WEB",
            ip="172.31.3.239",
            device_profile_code=DEFAULT_PROFILE_CODE,
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
        SNMP_CLIENT=FakeSnmpClient(),
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


def test_device_snmp_control_api_and_write_log(tmp_path: Path) -> None:
    app, database_url = _build_app(tmp_path)
    client = app.test_client()
    _login(client)

    detail_response = client.get("/api/devices/1")
    assert detail_response.status_code == 200
    assert detail_response.get_json()["ok"] is True

    controls_response = client.get("/api/devices/1/snmp-controls")
    assert controls_response.status_code == 200
    controls_payload = controls_response.get_json()
    assert controls_payload["ok"] is True
    assert len(controls_payload["controls"]) == 14
    aps_en = next(item for item in controls_payload["controls"] if item["oid_name"] == "apsEn")
    assert aps_en["display_name"] == "APS 使能开关"

    set_response = client.post(
        f"/api/devices/1/snmp-controls/{aps_en['id']}/set",
        json={"value": "0"},
    )
    assert set_response.status_code == 200
    set_payload = set_response.get_json()
    assert set_payload["ok"] is True
    assert set_payload["verify"]["current_value_raw"] == "0"

    events_response = client.get("/api/devices/1/events")
    assert events_response.status_code == 200
    assert events_response.get_json()["ok"] is True

    engine = create_engine(database_url)
    with Session(engine) as session:
        logs = session.execute(select(OperationLog).order_by(OperationLog.id.asc())).scalars().all()
        assert any(item.action == "snmp_set_control" for item in logs)


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
    assert format_dt(datetime(2026, 5, 8, 10, 8, 44, tzinfo=timezone.utc)) == "2026-05-08 18:08:44"
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
            "parser_key": DEFAULT_PROFILE_CODE,
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


def test_trap_page_supports_multi_filters_and_pagination(tmp_path: Path) -> None:
    app, database_url = _build_app(tmp_path)
    engine = create_engine(database_url)
    with Session(engine) as session:
        device = session.scalar(select(Device).where(Device.name == "RX10-WEB"))
        assert device is not None
        for index in range(2, 38):
            session.add(
                TrapEvent(
                    device_id=device.id,
                    pdu_id=f"web-pdu-{index}",
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
                    alarm_index=f"135463178.{index}",
                    alarm_obj="xg.1.10",
                    alarm_id="LOS",
                    severity_code=5,
                    severity="critical",
                    status_code=43,
                    status="report",
                    device_alarm_time_raw="686523786",
                    is_active_alarm=True,
                    should_popup=True,
                    raw_summary=f"almchg obj=xg.1.10 alarm=LOS #{index}",
                    raw_json={"source_ip": device.ip},
                    translated_json={"alarm_id": "LOS"},
                    received_at=datetime(2026, 5, 8, 10, 8, 44, tzinfo=timezone.utc) + timedelta(seconds=index),
                )
            )
        session.commit()

    client = app.test_client()
    _login(client)
    response = client.get("/traps?severity=critical&trap_type=alarm&device_id=1&page=2")
    text = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "上一页" in text
    assert '<span class="current">2</span>' in text
    assert 'value="critical"' in text


def test_alarm_page_supports_pagination(tmp_path: Path) -> None:
    app, database_url = _build_app(tmp_path)
    engine = create_engine(database_url)
    with Session(engine) as session:
        device = session.scalar(select(Device).where(Device.name == "RX10-WEB"))
        active_alarm = session.scalar(select(ActiveAlarm))
        trap = session.scalar(select(TrapEvent))
        assert device is not None and active_alarm is not None and trap is not None
        for index in range(2, 38):
            session.add(
                AlarmEvent(
                    active_alarm_id=active_alarm.id,
                    trap_event_id=trap.id,
                    device_id=device.id,
                    alarm_obj="xg.1.10",
                    alarm_id="LOS",
                    severity_code=5,
                    severity="critical",
                    status_code=43,
                    status="report",
                    event_type="trap",
                    message=f"alarm event #{index}",
                    occurred_at=datetime(2026, 5, 8, 10, 8, 44, tzinfo=timezone.utc) + timedelta(seconds=index),
                )
            )
        session.commit()

    client = app.test_client()
    _login(client)
    response = client.get("/alarms?open_state=all&page=2")
    text = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "上一页" in text
    assert '<span class="current">2</span>' in text
    assert "查看原始日志" in text


def test_numeric_poll_judge_and_alarm_rule_override() -> None:
    pipeline = CollectorPipeline("sqlite:///:memory:", "redis://127.0.0.1:6399/0", "test")
    result = SimpleNamespace(poll_status="ok", value_raw="12", value_text="12", value_num=12.0)
    strategy = SimpleNamespace(
        judge_type="number_gt",
        expected_values_json=["10"],
        expected_value_text="10",
        health_on_mismatch="major",
    )
    interpreted = pipeline._interpret_poll_result(resolver=None, result=result, node=None, strategy=strategy)
    assert interpreted["health_status"] == "normal"

    event = SimpleNamespace(
        severity="critical",
        status="report",
        is_active_alarm=True,
        should_popup=True,
        extra={},
    )
    rule = AlarmRule(
        profile_code=DEFAULT_PROFILE_CODE,
        alarm_id="LOS",
        default_severity="critical",
        should_create_active=False,
        should_popup=False,
        description="接口光信号丢失",
    )
    CollectorPipeline._apply_alarm_rule(event, rule)
    assert event.is_active_alarm is False
    assert event.should_popup is False


def test_effective_event_severity_keeps_critical_for_cleared_close_events() -> None:
    event = AlarmEvent(
        alarm_id="LOS",
        severity="cleared",
        status="close",
        event_type="trap",
        occurred_at=datetime.now(timezone.utc),
    )
    active_alarm = ActiveAlarm(
        alarm_id="LOS",
        alarm_obj="xg.1.10",
        dedupe_key="1::xg.1.10::LOS",
        severity="critical",
        status="close",
        first_seen_at=datetime.now(timezone.utc),
        last_seen_at=datetime.now(timezone.utc),
        is_open=False,
    )
    rule = AlarmRule(
        profile_code=DEFAULT_PROFILE_CODE,
        alarm_id="LOS",
        default_severity="critical",
        should_create_active=True,
        should_popup=True,
        description="接口光信号丢失",
    )

    assert _effective_event_severity(event, active_alarm=active_alarm, rule=rule) == "critical"


def test_recovery_event_is_not_treated_as_current_open_when_alarm_reopens() -> None:
    event = AlarmEvent(
        alarm_id="LOS",
        severity="cleared",
        status="close",
        trap_event_id=100,
        event_type="trap",
        occurred_at=datetime.now(timezone.utc),
    )
    active_alarm = ActiveAlarm(
        alarm_id="LOS",
        alarm_obj="xg.1.10",
        dedupe_key="1::xg.1.10::LOS",
        severity="critical",
        status="report",
        first_seen_at=datetime.now(timezone.utc),
        last_seen_at=datetime.now(timezone.utc),
        last_trap_event_id=101,
        is_open=True,
    )

    assert _event_is_current_open(event, active_alarm) is False


def test_iop_low_alarm_auto_recovers_after_normal_check(tmp_path: Path) -> None:
    app, database_url = _build_app(tmp_path)
    engine = create_engine(database_url)
    with Session(engine) as session:
        active_alarm = session.scalar(select(ActiveAlarm))
        assert active_alarm is not None
        active_alarm.alarm_id = "IOP_15L"
        active_alarm.dedupe_key = f"{active_alarm.device_id}::xg.1.10::IOP_15L"
        active_alarm.first_seen_at = datetime.now(timezone.utc) - timedelta(minutes=11)
        active_alarm.last_seen_at = active_alarm.first_seen_at
        active_alarm.is_open = True
        session.commit()

    snmp_client = FakeSnmpClient()
    snmp_client.values["1.3.6.1.4.1.42669.2.10.0"] = "normal"
    pipeline = CollectorPipeline(database_url, "redis://127.0.0.1:6399/0", "test", snmp_client=snmp_client)
    summary = pipeline.run_auto_recovery_checks()
    assert summary["checked"] == 1
    assert summary["recovered"] == 1

    with Session(engine) as session:
        active_alarm = session.scalar(select(ActiveAlarm).where(ActiveAlarm.alarm_id == "IOP_15L"))
        assert active_alarm is not None
        assert active_alarm.is_open is False
        assert active_alarm.closed_at is not None
        assert active_alarm.notes == "系统检查正常，自动恢复"
        recovery_event = session.scalar(
            select(AlarmEvent).where(
                AlarmEvent.alarm_id == "IOP_15L",
                AlarmEvent.event_type == "system_check",
            )
        )
        assert recovery_event is not None
        assert recovery_event.message == "系统检查正常，自动恢复"

    client = app.test_client()
    _login(client)
    response = client.get("/alarms?keyword=IOP_15L")
    assert response.status_code == 200
    assert "系统检查正常，自动恢复" in response.get_data(as_text=True)


def test_realtime_status_processor_writes_latest_and_sampled_history(tmp_path: Path) -> None:
    _app, database_url = _build_app(tmp_path)
    fake_redis = FakeRedis()
    processor = RealtimeStatusProcessor(database_url, "redis://127.0.0.1:6399/0", redis_client=fake_redis)

    payload = {
        "ts": "2026-05-10T12:52:52.842",
        "interfaces": [
            {
                "name": "ens7f0",
                "bandwidth_mbps": 3541.3,
                "bandwidth_str": "3.54 Gbps",
                "packets_per_sec": 323111,
                "programs": 401,
            },
            {
                "name": "ens7f1",
                "bandwidth_mbps": 3560.7,
                "bandwidth_str": "3.56 Gbps",
                "packets_per_sec": 324907,
                "programs": 433,
            },
        ],
    }

    assert processor.process_payload(payload) is True

    latest = json.loads(fake_redis.values["realtime:device:1:latest"])
    assert latest["device_name"] == "RX10-WEB"
    assert latest["interfaces"][0]["bandwidth_mbps"] == 3541.3
    assert latest["raw_data"] == payload

    history = [json.loads(item) for item in fake_redis.lists["realtime:device:1:history"]]
    assert len(history) == 1
    assert history[0]["ens7f0"]["programs"] == 401
    assert history[0]["ens7f1"]["packets_per_sec"] == 324907


def test_realtime_status_api_reads_redis_payload(tmp_path: Path, monkeypatch) -> None:
    app, _database_url = _build_app(tmp_path)
    fake_redis = FakeRedis()
    latest = {
        "device_id": 1,
        "device_name": "RX10-WEB",
        "device_ip": "172.31.3.239",
        "ts": "2026-05-10T12:52:52.842",
        "received_at": datetime.now(timezone.utc).isoformat(),
        "interfaces": [
            {
                "name": "ens7f0",
                "bandwidth_mbps": 3541.3,
                "bandwidth_str": "3.54 Gbps",
                "packets_per_sec": 323111,
                "programs": 401,
            }
        ],
        "raw_data": {"ts": "2026-05-10T12:52:52.842", "interfaces": []},
    }
    sample = {
        "ts": "2026-05-10T12:52:52.842",
        "ens7f0": {"bandwidth_mbps": 3541.3, "programs": 401, "packets_per_sec": 323111},
        "ens7f1": {"bandwidth_mbps": 3560.7, "programs": 433, "packets_per_sec": 324907},
    }
    fake_redis.setex("realtime:device:1:latest", 30, json.dumps(latest))
    fake_redis.rpush("realtime:device:1:history", json.dumps(sample))
    monkeypatch.setattr(
        "repeater_nms.web.routes.redis_client_from_app",
        lambda app: SimpleNamespace(redis=fake_redis),
    )

    client = app.test_client()
    _login(client)
    response = client.get("/api/devices/1/realtime-status")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["ok"] is True
    assert payload["data_status"] == "normal"
    assert payload["interfaces"][0]["name"] == "ens7f0"
    assert payload["history"][0]["ens7f1"]["programs"] == 433


def _program_payload() -> dict:
    return {
        "batch": {"start": 300, "end": 349, "total": 401, "duration": 0.5, "device": "ens7f0"},
        "programs": [
            {
                "no": 301,
                "stream": "228.1.6.112:11000",
                "total_bw": 6263195,
                "status": "OK",
                "l1": 0,
                "l2": 0,
                "l3": 0,
                "video_bw": 4675113,
                "video_codec": "H.264",
                "audio_bw": 252945,
                "audio_codec": "AAC",
            },
            {
                "no": 302,
                "stream": "228.1.6.113:11000",
                "total_bw": 0,
                "status": "NoPAT",
                "l1": 1,
                "l2": 0,
                "l3": 2,
                "video_bw": 0,
                "video_codec": "",
                "audio_bw": 0,
                "audio_codec": "",
            },
        ],
    }


def test_program_analysis_processor_updates_program_hash(tmp_path: Path) -> None:
    _app, database_url = _build_app(tmp_path)
    fake_redis = FakeRedis()
    processor = ProgramAnalysisProcessor(database_url, "redis://127.0.0.1:6399/0", redis_client=fake_redis)

    assert processor.process_payload(_program_payload(), interface_name="ens7f0") is True

    rows = fake_redis.hgetall("program:device:1:ens7f0:programs")
    assert set(rows) == {"301", "302"}
    program = json.loads(rows["301"])
    assert program["multicast_address"] == "228.1.6.112"
    assert program["udp_port"] == 11000
    batch = json.loads(fake_redis.get("program:device:1:ens7f0:batch"))
    assert batch["total"] == 401
    assert batch["last_batch_start"] == 300


def test_program_analysis_processor_accepts_trailing_commas(tmp_path: Path) -> None:
    _app, database_url = _build_app(tmp_path)
    fake_redis = FakeRedis()
    processor = ProgramAnalysisProcessor(database_url, "redis://127.0.0.1:6399/0", redis_client=fake_redis)
    raw = b"""
    {
      "batch": {
        "start": 300,
        "end": 300,
        "total": 401,
        "duration": 0.5,
        "device": "ens7f0",
      },
      "programs": [
        {
          "no": 301,
          "stream": "228.1.6.112:11000",
          "total_bw": 6263195,
          "status": "OK",
          "l1": 0,
          "l2": 0,
          "l3": 0,
        }
      ]
    }
    """

    assert processor.process_datagram(raw, interface_name="ens7f0") is True
    assert "301" in fake_redis.hgetall("program:device:1:ens7f0:programs")


def test_program_analysis_processor_accepts_missing_field_commas(tmp_path: Path) -> None:
    _app, database_url = _build_app(tmp_path)
    fake_redis = FakeRedis()
    processor = ProgramAnalysisProcessor(database_url, "redis://127.0.0.1:6399/0", redis_client=fake_redis)
    raw = b"""
    {
      "batch": {
        "start": 300
        "end": 300
        "total": 401
        "duration": 0.5
        "device": "ens7f0",
      },
      "programs": [
        {
          "no": 301
          "stream": "228.1.6.112:11000"
          "total_bw": 6263195
          "status": "OK"
          "l1": 0
          "l2": 0
          "l3": 0
          "video_bw": 4675113
          "video_codec": "H.264"
          "audio_bw": 252945
          "audio_codec": "AAC"
        }
      ]
    }
    """

    assert processor.process_datagram(raw, interface_name="ens7f0") is True
    program = json.loads(fake_redis.hgetall("program:device:1:ens7f0:programs")["301"])
    assert program["video_codec"] == "H.264"


def test_program_analysis_api_returns_rows_with_formatted_time(tmp_path: Path, monkeypatch) -> None:
    app, database_url = _build_app(tmp_path)
    fake_redis = FakeRedis()
    processor = ProgramAnalysisProcessor(database_url, "redis://127.0.0.1:6399/0", redis_client=fake_redis)
    assert processor.process_payload(_program_payload(), interface_name="ens7f0") is True
    monkeypatch.setattr(
        "repeater_nms.web.routes.redis_client_from_app",
        lambda app: SimpleNamespace(redis=fake_redis),
    )

    client = app.test_client()
    _login(client)
    response = client.get("/api/devices/1/program-analysis?page_size=10")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["ok"] is True
    assert payload["summary"]["ens7f0"]["received_count"] == 2
    assert payload["pagination"]["total"] == 2
    assert payload["programs"][0]["last_update_time_display"]
    assert "T" not in payload["programs"][0]["last_update_time_display"]
