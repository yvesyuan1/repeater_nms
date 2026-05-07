from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from repeater_nms.db.models import ActiveAlarm, AlarmEvent, Device, DeviceLatestValue, PopupNotification, TrapEvent
from repeater_nms.db.seed_data import DEFAULT_PROFILE_CODE


@dataclass
class DemoSeedSummary:
    device_created: bool = False
    trap_created: bool = False
    active_alarm_created: bool = False
    popup_created: bool = False


def _upsert_latest_value(
    session: Session,
    *,
    device_id: int,
    oid: str,
    oid_name: str,
    oid_name_zh: str,
    category: str,
    display_value: str,
    health_status: str,
    health_text: str,
    health_reason: str,
    raw_value: str,
    enum_text: str | None = None,
    value_unit: str | None = None,
) -> None:
    now = datetime.now(timezone.utc)
    row = session.execute(
        select(DeviceLatestValue).where(DeviceLatestValue.device_id == device_id, DeviceLatestValue.oid == oid)
    ).scalar_one_or_none()
    if row is None:
        row = DeviceLatestValue(
            device_id=device_id,
            profile_code=DEFAULT_PROFILE_CODE,
            oid=oid,
            oid_name=oid_name,
            oid_name_zh=oid_name_zh,
            category=category,
            value_raw=raw_value,
            value_text=raw_value,
            display_value=display_value,
            enum_text=enum_text,
            value_unit=value_unit,
            health_status=health_status,
            health_text=health_text,
            health_reason=health_reason,
            poll_status="ok",
            collected_at=now,
            last_success_at=now,
        )
        session.add(row)
        return
    row.profile_code = DEFAULT_PROFILE_CODE
    row.oid_name = oid_name
    row.oid_name_zh = oid_name_zh
    row.category = category
    row.value_raw = raw_value
    row.value_text = raw_value
    row.display_value = display_value
    row.enum_text = enum_text
    row.value_unit = value_unit
    row.health_status = health_status
    row.health_text = health_text
    row.health_reason = health_reason
    row.poll_status = "ok"
    row.collected_at = now
    row.last_success_at = now


def seed_local_demo_data(session: Session) -> DemoSeedSummary:
    summary = DemoSeedSummary()
    now = datetime.now(timezone.utc)

    device = session.execute(select(Device).where(Device.ip == "172.25.22.6")).scalar_one_or_none()
    if device is None:
        device = Device(
            name="RX10-DEMO",
            ip="172.25.22.6",
            device_profile_code=DEFAULT_PROFILE_CODE,
            snmp_port=161,
            trap_port=1162,
            snmp_version="v2c",
            read_community="CSXT",
            write_community="CSXT",
            is_enabled=True,
            notes="Local trial seeded device.",
            last_online_at=now,
            last_polled_at=now,
            last_poll_status="partial",
            last_poll_message="Local trial sample data.",
        )
        session.add(device)
        session.flush()
        summary.device_created = True
    else:
        device.device_profile_code = device.device_profile_code or DEFAULT_PROFILE_CODE

    trap = session.execute(select(TrapEvent).where(TrapEvent.pdu_id == "local-demo-pdu")).scalar_one_or_none()
    if trap is None:
        trap = TrapEvent(
            device_id=device.id,
            profile_code=DEFAULT_PROFILE_CODE,
            pdu_id="local-demo-pdu",
            packet_id="local-demo-pdu",
            source_ip=device.ip,
            source_port=162,
            local_ip="127.0.0.1",
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
            alarm_obj_desc="Local trial sample event.",
            is_active_alarm=True,
            should_popup=True,
            parse_status="parsed",
            raw_summary="almchg obj=xg.1.10 alarm=LOS severity=critical status=report pdu_id=local-demo-pdu",
            raw_json={
                "pdu_id": "local-demo-pdu",
                "source_ip": device.ip,
                "source_port": 162,
                "local_ip": "127.0.0.1",
                "local_port": 1162,
                "snmp_version": "v2c",
                "community_masked": "C**T",
                "sys_uptime": "395525258",
                "snmp_trap_oid": "1.3.6.1.4.1.42669.1.1.0.1",
                "varbinds": [],
            },
            translated_json={
                "pdu_id": "local-demo-pdu",
                "alarm_index": "135463178.30",
                "alarm_obj": "xg.1.10",
                "alarm_id": "LOS",
                "severity_code": 5,
                "severity": "critical",
                "status_code": 43,
                "status": "report",
                "device_alarm_time_raw": "686523786",
                "alarm_obj_desc": "Local trial sample event.",
                "is_active_alarm": True,
                "should_popup": True,
            },
            received_at=now,
        )
        session.add(trap)
        session.flush()
        summary.trap_created = True

    active_alarm = session.execute(
        select(ActiveAlarm).where(ActiveAlarm.dedupe_key == f"{device.id}::xg.1.10::LOS")
    ).scalar_one_or_none()
    if active_alarm is None:
        active_alarm = ActiveAlarm(
            device_id=device.id,
            dedupe_key=f"{device.id}::xg.1.10::LOS",
            alarm_obj="xg.1.10",
            alarm_id="LOS",
            severity_code=5,
            severity="critical",
            status="report",
            first_seen_at=now,
            last_seen_at=now,
            last_trap_event_id=trap.id,
            occurrence_count=1,
            is_open=True,
            is_acknowledged=False,
            notes="Local trial sample alarm.",
        )
        session.add(active_alarm)
        session.flush()
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
                message=trap.raw_summary,
                occurred_at=now,
            )
        )
        summary.active_alarm_created = True

    popup = session.execute(
        select(PopupNotification).where(PopupNotification.popup_key == f"{device.id}::xg.1.10::LOS")
    ).scalar_one_or_none()
    if popup is None:
        session.add(
            PopupNotification(
                popup_key=f"{device.id}::xg.1.10::LOS",
                trap_event_id=trap.id,
                active_alarm_id=active_alarm.id,
                device_id=device.id,
                severity="critical",
                alarm_obj="xg.1.10",
                alarm_id="LOS",
                status="pending",
                is_acknowledged=False,
            )
        )
        summary.popup_created = True

    _upsert_latest_value(
        session,
        device_id=device.id,
        oid="1.3.6.1.4.1.42669.2.9.0",
        oid_name="apsActive",
        oid_name_zh="APS 当前活跃侧",
        category="aps",
        display_value="work",
        health_status="unknown",
        health_text="未知",
        health_reason="未配置正常判断规则",
        raw_value="work",
    )
    _upsert_latest_value(
        session,
        device_id=device.id,
        oid="1.3.6.1.4.1.42669.2.10.0",
        oid_name="apsStat",
        oid_name_zh="APS 状态机状态",
        category="aps",
        display_value="normal",
        health_status="normal",
        health_text="正常",
        health_reason="命中正常判断规则",
        raw_value="0",
        enum_text="正常状态",
    )
    _upsert_latest_value(
        session,
        device_id=device.id,
        oid="1.3.6.1.4.1.42669.3.4.0",
        oid_name="dfpActive",
        oid_name_zh="DFP 当前活跃侧",
        category="dfp",
        display_value="self",
        health_status="unknown",
        health_text="未知",
        health_reason="未配置正常判断规则",
        raw_value="self",
    )
    return summary
