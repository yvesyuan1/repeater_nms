from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from repeater_nms.db.models import ActiveAlarm, AlarmEvent, Device, PopupNotification, TrapEvent


@dataclass
class DemoSeedSummary:
    device_created: bool = False
    trap_created: bool = False
    active_alarm_created: bool = False
    popup_created: bool = False


def seed_local_demo_data(session: Session) -> DemoSeedSummary:
    summary = DemoSeedSummary()
    now = datetime.now(timezone.utc)

    device = session.execute(select(Device).where(Device.ip == "172.25.22.6")).scalar_one_or_none()
    if device is None:
        device = Device(
            name="RX10-DEMO",
            ip="172.25.22.6",
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

    trap = session.execute(select(TrapEvent).where(TrapEvent.pdu_id == "local-demo-pdu")).scalar_one_or_none()
    if trap is None:
        trap = TrapEvent(
            device_id=device.id,
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

    return summary
