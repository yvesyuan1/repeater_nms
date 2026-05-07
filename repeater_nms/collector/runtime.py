from __future__ import annotations

import logging
from collections import defaultdict
from datetime import timezone
from datetime import datetime
from typing import Any

from sqlalchemy import select

from repeater_nms.collector.constants import ACTIVE_ALARM_SEVERITIES, ACTIVE_ALARM_STATUSES
from repeater_nms.collector.mib import MibResolver
from repeater_nms.collector.publisher import EventPublisher, RedisEventPublisher
from repeater_nms.collector.schemas import NormalizedTrapEvent, ParsedTrapBundle, PollResult, PollTarget, PublishedTrapEvent, TrapPdu
from repeater_nms.collector.snmp_client import SnmpV2cClient
from repeater_nms.collector.trap_parser import TrapParser
from repeater_nms.db.base import utc_now
from repeater_nms.db.models import ActiveAlarm, AlarmEvent, Device, DeviceLatestValue, MibNode, PopupNotification, SnmpMetricSample, TrapEvent
from repeater_nms.db.session import session_scope


LOGGER = logging.getLogger("repeater_nms.collector.runtime")


class CollectorPipeline:
    def __init__(
        self,
        database_url: str,
        redis_url: str,
        channel_prefix: str,
        *,
        publisher: EventPublisher | None = None,
        resolver: MibResolver | None = None,
        parser: TrapParser | None = None,
        snmp_client: SnmpV2cClient | None = None,
    ) -> None:
        self.database_url = database_url
        self.publisher = publisher or RedisEventPublisher(redis_url, channel_prefix)
        self.resolver = resolver or MibResolver()
        self.parser = parser or TrapParser(self.resolver)
        self.snmp_client = snmp_client or SnmpV2cClient()

    def ingest_pdu(self, pdu: TrapPdu) -> list[PublishedTrapEvent]:
        parsed = self.parser.parse_pdu(pdu)
        published_events: list[PublishedTrapEvent] = []
        with session_scope(self.database_url) as session:
            device = session.execute(select(Device).where(Device.ip == pdu.source_ip)).scalar_one_or_none()
            device_name = "未知设备" if device is None else device.name

            if parsed.parse_status != "parsed" or not parsed.events:
                trap_event = TrapEvent(
                    device_id=None if device is None else device.id,
                    pdu_id=pdu.pdu_id,
                    source_ip=pdu.source_ip,
                    source_port=pdu.source_port,
                    local_ip=pdu.local_ip,
                    local_port=pdu.local_port,
                    snmp_version=pdu.snmp_version,
                    community_masked=pdu.raw_json()["community_masked"],
                    trap_oid=parsed.trap_oid,
                    trap_name=parsed.trap_name,
                    trap_type=parsed.trap_type,
                    sys_uptime=pdu.sys_uptime,
                    parse_status=parsed.parse_status,
                    parse_error=parsed.parse_error,
                    raw_summary=parsed.parse_error or "trap parse failed",
                    raw_json=pdu.raw_json(),
                    translated_json=None,
                    received_at=pdu.received_at,
                )
                session.add(trap_event)
                session.flush()
                LOGGER.warning(
                    "trap parse failed source_ip=%s trap_oid=%s pdu_id=%s error=%s",
                    pdu.source_ip,
                    parsed.trap_oid,
                    pdu.pdu_id,
                    parsed.parse_error,
                )
                return []

            for event in parsed.events:
                trap_event = TrapEvent(
                    device_id=None if device is None else device.id,
                    pdu_id=pdu.pdu_id,
                    source_ip=pdu.source_ip,
                    source_port=pdu.source_port,
                    local_ip=pdu.local_ip,
                    local_port=pdu.local_port,
                    snmp_version=pdu.snmp_version,
                    community_masked=pdu.raw_json()["community_masked"],
                    trap_oid=parsed.trap_oid,
                    trap_name=parsed.trap_name,
                    trap_type=parsed.trap_type,
                    sys_uptime=pdu.sys_uptime,
                    alarm_index=event.alarm_index,
                    alarm_obj=event.alarm_obj,
                    alarm_id=event.alarm_id,
                    severity_code=event.severity_code,
                    severity=event.severity,
                    status_code=event.status_code,
                    status=event.status,
                    device_alarm_time_raw=event.device_alarm_time_raw,
                    alarm_obj_desc=event.alarm_obj_desc,
                    is_active_alarm=event.is_active_alarm,
                    should_popup=event.should_popup,
                    parse_status=parsed.parse_status,
                    raw_summary=event.raw_summary(),
                    raw_json=pdu.raw_json(),
                    translated_json=event.translated_json(),
                    received_at=pdu.received_at,
                )
                session.add(trap_event)
                session.flush()

                active_alarm = None
                if parsed.trap_type == "alarm":
                    active_alarm = self._apply_active_alarm(
                        session,
                        device_id=None if device is None else device.id,
                        event=event,
                        trap_event=trap_event,
                        occurred_at=pdu.received_at,
                    )
                    self._create_alarm_event(
                        session,
                        device_id=None if device is None else device.id,
                        trap_event=trap_event,
                        event=event,
                        active_alarm=active_alarm,
                        occurred_at=pdu.received_at,
                    )
                    self._apply_popup_notification(
                        session,
                        device_id=None if device is None else device.id,
                        trap_event=trap_event,
                        event=event,
                        active_alarm=active_alarm,
                    )

                published = PublishedTrapEvent(
                    trap_event_id=trap_event.id,
                    pdu_id=trap_event.pdu_id,
                    received_at=trap_event.received_at.astimezone(timezone.utc).isoformat(),
                    source_ip=trap_event.source_ip,
                    device_id=trap_event.device_id,
                    device_name=device_name,
                    trap_type=trap_event.trap_type,
                    trap_name=trap_event.trap_name,
                    alarm_obj=trap_event.alarm_obj,
                    alarm_id=trap_event.alarm_id,
                    severity=trap_event.severity,
                    status=trap_event.status,
                    device_alarm_time_raw=trap_event.device_alarm_time_raw,
                    raw_summary=trap_event.raw_summary,
                    translated_json=trap_event.translated_json,
                )
                published_events.append(published)

            LOGGER.info(
                "trap parsed source_ip=%s trap_oid=%s pdu_id=%s split_count=%s",
                pdu.source_ip,
                parsed.trap_oid,
                pdu.pdu_id,
                len(parsed.events),
            )

        for published in published_events:
            self.publisher.publish_trap_event(published)
        return published_events

    def poll_enabled_devices_once(self) -> dict[str, int]:
        with session_scope(self.database_url) as session:
            devices = session.execute(
                select(Device).where(Device.is_enabled.is_(True))
            ).scalars().all()
            pollable_nodes = session.execute(
                select(MibNode).where(MibNode.is_pollable.is_(True)).order_by(MibNode.oid)
            ).scalars().all()

            targets = [
                PollTarget(
                    oid=node.oid,
                    name=node.name,
                    scalar_suffix_zero=node.scalar_suffix_zero,
                )
                for node in pollable_nodes
            ]

        result_counts = defaultdict(int)
        for device in devices:
            results = self.snmp_client.poll_device_sync(
                device.id,
                device.name,
                device.ip,
                device.snmp_port,
                device.read_community,
                targets,
            )
            with session_scope(self.database_url) as session:
                db_device = session.get(Device, device.id)
                if db_device is None:
                    continue
                success_count = 0
                error_messages: list[str] = []
                for result in results:
                    db_node = session.execute(select(MibNode).where(MibNode.name == result.oid_name)).scalar_one_or_none()
                    sample = SnmpMetricSample(
                        device_id=device.id,
                        mib_node_id=None if db_node is None else db_node.id,
                        oid=result.oid,
                        oid_name=result.oid_name,
                        metric_key=result.oid_name,
                        value_raw=result.value_raw,
                        value_text=result.value_text,
                        value_num=result.value_num,
                        poll_status=result.poll_status,
                        error_message=result.error_message,
                        collected_at=result.collected_at,
                    )
                    session.add(sample)
                    latest = session.execute(
                        select(DeviceLatestValue).where(
                            DeviceLatestValue.device_id == device.id,
                            DeviceLatestValue.oid == result.request_oid,
                        )
                    ).scalar_one_or_none()
                    if latest is None:
                        latest = DeviceLatestValue(
                            device_id=device.id,
                            mib_node_id=None if db_node is None else db_node.id,
                            oid=result.request_oid,
                            oid_name=result.oid_name,
                            value_raw=result.value_raw,
                            value_text=result.value_text,
                            value_num=result.value_num,
                            poll_status=result.poll_status,
                            error_message=result.error_message,
                            collected_at=result.collected_at,
                        )
                        session.add(latest)
                    else:
                        latest.mib_node_id = None if db_node is None else db_node.id
                        latest.oid_name = result.oid_name
                        latest.value_raw = result.value_raw
                        latest.value_text = result.value_text
                        latest.value_num = result.value_num
                        latest.poll_status = result.poll_status
                        latest.error_message = result.error_message
                        latest.collected_at = result.collected_at

                    if result.poll_status == "ok":
                        success_count += 1
                    else:
                        error_messages.append(f"{result.oid_name}: {result.error_message}")

                db_device.last_polled_at = utc_now()
                db_device.last_online_at = utc_now() if success_count else db_device.last_online_at
                db_device.last_poll_status = "ok" if success_count == len(results) else ("partial" if success_count else "error")
                db_device.last_poll_message = "ok" if success_count == len(results) else "; ".join(error_messages[:3])

                self.publisher.cache_device_snapshot(
                    device.id,
                    {
                        "device_id": device.id,
                        "device_name": device.name,
                        "last_polled_at": db_device.last_polled_at.isoformat(),
                        "last_poll_status": db_device.last_poll_status,
                        "last_poll_message": db_device.last_poll_message,
                    },
                )

            result_counts["devices"] += 1
            result_counts["results"] += len(results)

        return dict(result_counts)

    @staticmethod
    def _active_alarm_key(device_id: int | None, alarm_obj: str | None, alarm_id: str | None) -> str:
        return f"{device_id or 'unknown'}::{alarm_obj or ''}::{alarm_id or ''}"

    def _apply_active_alarm(
        self,
        session,
        *,
        device_id: int | None,
        event: NormalizedTrapEvent,
        trap_event: TrapEvent,
        occurred_at: datetime,
    ) -> ActiveAlarm | None:
        if not event.alarm_id and not event.alarm_obj:
            return None

        dedupe_key = self._active_alarm_key(device_id, event.alarm_obj, event.alarm_id)
        active_alarm = session.execute(
            select(ActiveAlarm).where(ActiveAlarm.dedupe_key == dedupe_key)
        ).scalar_one_or_none()

        opens_alarm = bool(event.severity in ACTIVE_ALARM_SEVERITIES and event.status in ACTIVE_ALARM_STATUSES)
        closes_alarm = bool(event.status == "close" or event.severity == "cleared")

        if active_alarm is None and not opens_alarm:
            return None

        if active_alarm is None:
            active_alarm = ActiveAlarm(
                device_id=device_id,
                dedupe_key=dedupe_key,
                alarm_obj=event.alarm_obj or "",
                alarm_id=event.alarm_id or "",
                severity_code=event.severity_code,
                severity=event.severity or "unknown",
                status=event.status or "unknown",
                first_seen_at=occurred_at,
                last_seen_at=occurred_at,
                last_trap_event_id=trap_event.id,
                occurrence_count=1,
                is_open=True,
                is_acknowledged=False,
            )
            session.add(active_alarm)
            session.flush()
            return active_alarm

        if opens_alarm:
            if not active_alarm.is_open:
                active_alarm.is_open = True
                active_alarm.first_seen_at = occurred_at
                active_alarm.closed_at = None
                active_alarm.is_acknowledged = False
                active_alarm.acknowledged_at = None
                active_alarm.acknowledged_by_user_id = None
            active_alarm.severity_code = event.severity_code
            active_alarm.severity = event.severity or active_alarm.severity
            active_alarm.status = event.status or active_alarm.status
            active_alarm.last_seen_at = occurred_at
            active_alarm.last_trap_event_id = trap_event.id
            active_alarm.occurrence_count += 1
            return active_alarm

        if closes_alarm and active_alarm.is_open:
            active_alarm.severity_code = event.severity_code
            active_alarm.severity = event.severity or active_alarm.severity
            active_alarm.status = event.status or active_alarm.status
            active_alarm.last_seen_at = occurred_at
            active_alarm.last_trap_event_id = trap_event.id
            active_alarm.is_open = False
            active_alarm.closed_at = occurred_at
        return active_alarm

    @staticmethod
    def _create_alarm_event(session, *, device_id: int | None, trap_event: TrapEvent, event: NormalizedTrapEvent, active_alarm: ActiveAlarm | None, occurred_at: datetime) -> None:
        alarm_event = AlarmEvent(
            active_alarm_id=None if active_alarm is None else active_alarm.id,
            trap_event_id=trap_event.id,
            device_id=device_id,
            alarm_obj=event.alarm_obj,
            alarm_id=event.alarm_id,
            severity_code=event.severity_code,
            severity=event.severity,
            status_code=event.status_code,
            status=event.status,
            event_type="trap",
            message=trap_event.raw_summary,
            occurred_at=occurred_at,
        )
        session.add(alarm_event)

    @staticmethod
    def _apply_popup_notification(session, *, device_id: int | None, trap_event: TrapEvent, event: NormalizedTrapEvent, active_alarm: ActiveAlarm | None) -> None:
        if not event.should_popup:
            return
        popup_key = CollectorPipeline._active_alarm_key(device_id, event.alarm_obj, event.alarm_id)
        popup = session.execute(
            select(PopupNotification).where(PopupNotification.popup_key == popup_key)
        ).scalar_one_or_none()
        if popup is None:
            popup = PopupNotification(
                popup_key=popup_key,
                trap_event_id=trap_event.id,
                active_alarm_id=None if active_alarm is None else active_alarm.id,
                device_id=device_id,
                severity=event.severity,
                alarm_obj=event.alarm_obj,
                alarm_id=event.alarm_id,
                status="pending",
                is_acknowledged=False,
            )
            session.add(popup)
            return
        if popup.is_acknowledged:
            return
        popup.trap_event_id = trap_event.id
        popup.active_alarm_id = None if active_alarm is None else active_alarm.id
        popup.status = "pending"
