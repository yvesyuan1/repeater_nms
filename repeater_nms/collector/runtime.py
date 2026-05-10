from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

from sqlalchemy import select

from repeater_nms.collector.constants import ACTIVE_ALARM_SEVERITIES, ACTIVE_ALARM_STATUSES
from repeater_nms.collector.mib import MibResolver
from repeater_nms.collector.publisher import EventPublisher, RedisEventPublisher
from repeater_nms.collector.schemas import NormalizedTrapEvent, PollTarget, PublishedTrapEvent, TrapPdu
from repeater_nms.collector.snmp_client import SnmpV2cClient
from repeater_nms.collector.trap_parser import TrapParser
from repeater_nms.db.base import utc_now
from repeater_nms.db.models import (
    ActiveAlarm,
    AlarmEvent,
    AlarmRule,
    Device,
    DeviceLatestValue,
    MibNode,
    PollingStrategy,
    PopupNotification,
    SnmpMetricSample,
    TrapEvent,
)
from repeater_nms.db.seed_data import DEFAULT_PROFILE_CODE
from repeater_nms.db.session import session_scope


LOGGER = logging.getLogger("repeater_nms.collector.runtime")

AUTO_RECOVERY_ALARM_IDS = {"IOP_15L", "IOP_24L"}
AUTO_RECOVERY_DELAY = timedelta(minutes=10)
AUTO_RECOVERY_CHECK_OID = "1.3.6.1.4.1.42669.2.10.0"
AUTO_RECOVERY_MESSAGE = "系统检查正常，自动恢复"

PUBLISHED_SEVERITY_LABELS = {
    "critical": "严重",
    "major": "主要",
    "minor": "次要",
    "warning": "告警",
    "indeterminate": "不确定",
    "cleared": "已清除",
}

PUBLISHED_STATUS_LABELS = {
    "report": "上报",
    "change": "变化",
    "close": "关闭",
}

PUBLISHED_TRAP_NAME_LABELS = {
    "almchg": "告警变更",
    "performance": "性能上报",
}

PUBLISHED_TRAP_TYPE_LABELS = {
    "alarm": "告警 Trap",
    "performance": "性能 Trap",
}

PUBLISHED_ALARM_ID_LABELS = {
    "Power1_Fail": "第一路电源故障",
    "Power2_Fail": "第二路电源故障",
    "HighTemp": "设备高温",
    "LowTemp": "设备低温",
    "PKG_FAIL": "硬件故障",
    "LOS": "接口光信号丢失",
    "LsrOffline": "光模块离线",
    "HighSysMem": "内存使用率高",
    "HighRootfs": "系统分区使用率高",
    "HighAppdisk": "用户分区使用率高",
    "PKG_NOTREADY": "软件启动未完成",
    "FAN1_FAIL": "风扇1故障",
    "FAN2_FAIL": "风扇2故障",
    "FAN3_FAIL": "风扇3故障",
    "FAN4_FAIL": "风扇4故障",
}

PUBLISHED_TREND_METRIC_LABELS = {
    "LB": "激光器偏置电流",
    "LT": "激光器温度",
    "IOP": "激光器输入光功率",
    "OOP": "激光器输出光功率",
    "RAM": "内存利用率",
    "CPU": "CPU利用率",
}


def _label(mapping: dict[str, str], value: str | None, default: str = "-") -> str:
    if not value:
        return default
    return mapping.get(value, value)


def _alarm_description(alarm_id: str | None) -> str | None:
    if not alarm_id:
        return None
    if alarm_id in PUBLISHED_ALARM_ID_LABELS:
        return PUBLISHED_ALARM_ID_LABELS[alarm_id]
    parts = alarm_id.split("_")
    if len(parts) == 2 and parts[0] in PUBLISHED_TREND_METRIC_LABELS and len(parts[1]) == 3:
        window_code = parts[1][:2]
        level_code = parts[1][2:]
        window_text = {"15": "15分钟", "24": "24小时"}.get(window_code)
        level_text = {"L": "低于阈值", "H": "高于阈值"}.get(level_code)
        metric_text = PUBLISHED_TREND_METRIC_LABELS.get(parts[0])
        if window_text and level_text and metric_text:
            return f"{window_text}{metric_text}{level_text}"
    return alarm_id


def _build_published_summary(
    *,
    device_name: str,
    trap_name: str | None,
    trap_type: str | None,
    alarm_obj: str | None,
    alarm_id: str | None,
    severity: str | None,
    status: str | None,
) -> str:
    summary_parts: list[str] = []
    if alarm_id or alarm_obj:
        summary_parts.append(f"{_label(PUBLISHED_TRAP_NAME_LABELS, trap_name)}：设备 {device_name}")
        if alarm_obj:
            summary_parts.append(f"对象 {alarm_obj}")
        if alarm_id:
            summary_parts.append(f"告警 {alarm_id}")
            description = _alarm_description(alarm_id)
            if description and description != alarm_id:
                summary_parts.append(f"说明 {description}")
        if severity:
            summary_parts.append(f"级别 {_label(PUBLISHED_SEVERITY_LABELS, severity)}")
        if status:
            summary_parts.append(f"状态 {_label(PUBLISHED_STATUS_LABELS, status)}")
        return "，".join(summary_parts)
    if trap_name or trap_type:
        return f"{_label(PUBLISHED_TRAP_NAME_LABELS, trap_name, _label(PUBLISHED_TRAP_TYPE_LABELS, trap_type))}：设备 {device_name}"
    return "-"


class CollectorPipeline:
    def __init__(
        self,
        database_url: str,
        redis_url: str,
        channel_prefix: str,
        *,
        publisher: EventPublisher | None = None,
        snmp_client: SnmpV2cClient | None = None,
    ) -> None:
        self.database_url = database_url
        self.publisher = publisher or RedisEventPublisher(redis_url, channel_prefix)
        self.snmp_client = snmp_client or SnmpV2cClient()

    def _resolver(self, profile_code: str | None) -> MibResolver:
        return MibResolver(profile_code or DEFAULT_PROFILE_CODE)

    def _parser(self, profile_code: str | None) -> TrapParser:
        return TrapParser(self._resolver(profile_code))

    def ingest_pdu(self, pdu: TrapPdu) -> list[PublishedTrapEvent]:
        with session_scope(self.database_url) as session:
            device = session.execute(select(Device).where(Device.ip == pdu.source_ip)).scalar_one_or_none()
            profile_code = DEFAULT_PROFILE_CODE if device is None else (device.device_profile_code or DEFAULT_PROFILE_CODE)
            resolver = self._resolver(profile_code)
            parser = TrapParser(resolver)
            parsed = parser.parse_pdu(pdu)
            published_events: list[PublishedTrapEvent] = []
            device_name = "未知设备" if device is None else device.name
            alarm_rules: dict[str, AlarmRule] = {}
            if parsed.trap_type == "alarm":
                alarm_rules = {
                    item.alarm_id: item
                    for item in session.execute(
                        select(AlarmRule).where(AlarmRule.profile_code == profile_code)
                    ).scalars().all()
                    if item.alarm_id
                }

            if parsed.parse_status != "parsed" or not parsed.events:
                trap_event = TrapEvent(
                    device_id=None if device is None else device.id,
                    profile_code=profile_code,
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
                if parsed.trap_type == "alarm":
                    self._apply_alarm_rule(event, alarm_rules.get(event.alarm_id or ""))
                trap_event = TrapEvent(
                    device_id=None if device is None else device.id,
                    profile_code=profile_code,
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
                    received_at_display=trap_event.received_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                    source_ip=trap_event.source_ip,
                    device_id=trap_event.device_id,
                    device_name=device_name,
                    trap_type=trap_event.trap_type,
                    trap_type_label=_label(PUBLISHED_TRAP_TYPE_LABELS, trap_event.trap_type),
                    trap_name=trap_event.trap_name,
                    trap_name_label=_label(PUBLISHED_TRAP_NAME_LABELS, trap_event.trap_name),
                    alarm_obj=trap_event.alarm_obj,
                    alarm_id=trap_event.alarm_id,
                    severity=trap_event.severity,
                    severity_label=_label(PUBLISHED_SEVERITY_LABELS, trap_event.severity),
                    status=trap_event.status,
                    status_label=_label(PUBLISHED_STATUS_LABELS, trap_event.status),
                    device_alarm_time_raw=trap_event.device_alarm_time_raw,
                    raw_summary=trap_event.raw_summary,
                    summary_zh=_build_published_summary(
                        device_name=device_name,
                        trap_name=trap_event.trap_name,
                        trap_type=trap_event.trap_type,
                        alarm_obj=trap_event.alarm_obj,
                        alarm_id=trap_event.alarm_id,
                        severity=trap_event.severity,
                        status=trap_event.status,
                    ),
                    translated_json=trap_event.translated_json,
                )
                published_events.append(published)

            LOGGER.info(
                "trap parsed source_ip=%s trap_oid=%s pdu_id=%s split_count=%s profile=%s",
                pdu.source_ip,
                parsed.trap_oid,
                pdu.pdu_id,
                len(parsed.events),
                profile_code,
            )

        for published in published_events:
            self.publisher.publish_trap_event(published)
        return published_events

    def poll_enabled_devices_once(self) -> dict[str, int]:
        with session_scope(self.database_url) as session:
            devices = session.execute(select(Device).where(Device.is_enabled.is_(True))).scalars().all()
            strategies = session.execute(
                select(PollingStrategy).where(PollingStrategy.is_enabled.is_(True)).order_by(
                    PollingStrategy.profile_code, PollingStrategy.display_order, PollingStrategy.id
                )
            ).scalars().all()
            strategies_by_profile: dict[str, list[PollingStrategy]] = defaultdict(list)
            for item in strategies:
                strategies_by_profile[item.profile_code].append(item)

        result_counts = defaultdict(int)
        for device in devices:
            profile_code = device.device_profile_code or DEFAULT_PROFILE_CODE
            resolver = self._resolver(profile_code)
            profile_strategies = strategies_by_profile.get(profile_code, [])
            targets = [
                PollTarget(
                    oid=item.oid,
                    name=item.node_name,
                    scalar_suffix_zero=bool((resolver.node_by_name(item.node_name) or {}).get("scalar_suffix_zero")),
                )
                for item in profile_strategies
            ]
            if not targets:
                LOGGER.warning("no polling strategy configured for profile=%s device=%s", profile_code, device.name)
                continue

            results = self.snmp_client.poll_device_sync(
                device.id,
                device.name,
                device.ip,
                device.snmp_port,
                device.read_community,
                targets,
            )
            strategy_by_name = {item.node_name: item for item in profile_strategies}
            with session_scope(self.database_url) as session:
                db_device = session.get(Device, device.id)
                if db_device is None:
                    continue
                success_count = 0
                error_messages: list[str] = []
                for result in results:
                    node = resolver.node_by_name(result.oid_name) or resolver.node_by_oid(result.oid)
                    strategy = strategy_by_name.get(result.oid_name)
                    interpreted = self._interpret_poll_result(
                        resolver=resolver,
                        result=result,
                        node=node,
                        strategy=strategy,
                    )
                    db_node = None
                    if node:
                        db_node = session.execute(
                            select(MibNode).where(MibNode.name == node["name"])
                        ).scalar_one_or_none()
                    sample = SnmpMetricSample(
                        device_id=device.id,
                        profile_code=profile_code,
                        mib_node_id=None if db_node is None else db_node.id,
                        oid=result.oid,
                        oid_name=result.oid_name,
                        oid_name_zh=interpreted["oid_name_zh"],
                        category=interpreted["category"],
                        metric_key=result.oid_name,
                        value_raw=result.value_raw,
                        value_text=result.value_text,
                        display_value=interpreted["display_value"],
                        enum_text=interpreted["enum_text"],
                        value_unit=interpreted["value_unit"],
                        value_num=None if result.value_num is None else Decimal(str(result.value_num)),
                        health_status=interpreted["health_status"],
                        health_text=interpreted["health_text"],
                        health_reason=interpreted["health_reason"],
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
                            profile_code=profile_code,
                            mib_node_id=None if db_node is None else db_node.id,
                            oid=result.request_oid,
                            oid_name=result.oid_name,
                            oid_name_zh=interpreted["oid_name_zh"],
                            category=interpreted["category"],
                            value_raw=result.value_raw,
                            value_text=result.value_text,
                            display_value=interpreted["display_value"],
                            enum_text=interpreted["enum_text"],
                            value_unit=interpreted["value_unit"],
                            value_num=None if result.value_num is None else Decimal(str(result.value_num)),
                            value_json=None,
                            health_status=interpreted["health_status"],
                            health_text=interpreted["health_text"],
                            health_reason=interpreted["health_reason"],
                            poll_status=result.poll_status,
                            error_message=result.error_message,
                            collected_at=result.collected_at,
                            last_success_at=result.collected_at if result.poll_status == "ok" else None,
                            last_failure_at=result.collected_at if result.poll_status != "ok" else None,
                            last_failure_message=result.error_message if result.poll_status != "ok" else None,
                        )
                        session.add(latest)
                    else:
                        latest.profile_code = profile_code
                        latest.mib_node_id = None if db_node is None else db_node.id
                        latest.oid_name = result.oid_name
                        latest.oid_name_zh = interpreted["oid_name_zh"]
                        latest.category = interpreted["category"]
                        latest.value_raw = result.value_raw
                        latest.value_text = result.value_text
                        latest.display_value = interpreted["display_value"]
                        latest.enum_text = interpreted["enum_text"]
                        latest.value_unit = interpreted["value_unit"]
                        latest.value_num = None if result.value_num is None else Decimal(str(result.value_num))
                        latest.health_status = interpreted["health_status"]
                        latest.health_text = interpreted["health_text"]
                        latest.health_reason = interpreted["health_reason"]
                        latest.poll_status = result.poll_status
                        latest.error_message = result.error_message
                        latest.collected_at = result.collected_at
                        if result.poll_status == "ok":
                            latest.last_success_at = result.collected_at
                        else:
                            latest.last_failure_at = result.collected_at
                            latest.last_failure_message = result.error_message

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
                        "profile_code": profile_code,
                        "last_polled_at": db_device.last_polled_at.isoformat(),
                        "last_poll_status": db_device.last_poll_status,
                        "last_poll_message": db_device.last_poll_message,
                    },
                )

            result_counts["devices"] += 1
            result_counts["results"] += len(results)

        return dict(result_counts)

    def run_auto_recovery_checks(self, *, now: datetime | None = None) -> dict[str, int]:
        check_at = now or datetime.now(timezone.utc)
        if check_at.tzinfo is None:
            check_at = check_at.replace(tzinfo=timezone.utc)
        cutoff = check_at - AUTO_RECOVERY_DELAY
        checked = 0
        recovered = 0
        skipped = 0
        errored = 0

        with session_scope(self.database_url) as session:
            rows = session.execute(
                select(ActiveAlarm, Device)
                .join(Device, ActiveAlarm.device_id == Device.id)
                .where(
                    ActiveAlarm.is_open.is_(True),
                    ActiveAlarm.alarm_id.in_(AUTO_RECOVERY_ALARM_IDS),
                    ActiveAlarm.first_seen_at <= cutoff,
                    Device.is_enabled.is_(True),
                )
            ).all()

            for active_alarm, device in rows:
                checked += 1
                result = self.snmp_client.get_oid_sync(
                    device.ip,
                    device.snmp_port,
                    device.read_community,
                    AUTO_RECOVERY_CHECK_OID,
                )
                if not result.get("ok"):
                    errored += 1
                    LOGGER.warning(
                        "auto recovery check failed device=%s alarm_id=%s oid=%s error=%s",
                        device.name,
                        active_alarm.alarm_id,
                        AUTO_RECOVERY_CHECK_OID,
                        result.get("error"),
                    )
                    continue

                value = str(result.get("value_text") or result.get("value_raw") or "").strip().lower()
                if value != "normal":
                    skipped += 1
                    continue

                active_alarm.is_open = False
                active_alarm.status = "close"
                active_alarm.severity = "cleared"
                active_alarm.last_seen_at = check_at
                active_alarm.closed_at = check_at
                active_alarm.notes = AUTO_RECOVERY_MESSAGE
                session.add(
                    AlarmEvent(
                        active_alarm_id=active_alarm.id,
                        trap_event_id=None,
                        device_id=active_alarm.device_id,
                        alarm_obj=active_alarm.alarm_obj,
                        alarm_id=active_alarm.alarm_id,
                        severity_code=0,
                        severity="cleared",
                        status_code=None,
                        status="close",
                        event_type="system_check",
                        message=AUTO_RECOVERY_MESSAGE,
                        occurred_at=check_at,
                    )
                )
                recovered += 1
                LOGGER.info(
                    "auto recovered alarm device=%s alarm_id=%s alarm_obj=%s oid=%s value=%s",
                    device.name,
                    active_alarm.alarm_id,
                    active_alarm.alarm_obj,
                    AUTO_RECOVERY_CHECK_OID,
                    value,
                )

        return {"checked": checked, "recovered": recovered, "skipped": skipped, "errored": errored}

    @staticmethod
    def _active_alarm_key(device_id: int | None, alarm_obj: str | None, alarm_id: str | None) -> str:
        return f"{device_id or 'unknown'}::{alarm_obj or ''}::{alarm_id or ''}"

    def _interpret_poll_result(
        self,
        *,
        resolver: MibResolver,
        result,
        node: dict[str, Any] | None,
        strategy: PollingStrategy | None,
    ) -> dict[str, Any]:
        def normalize_text(value: Any) -> str:
            text = "" if value is None else str(value).strip()
            return "-" if not text or text.lower() in {"null", "none", "nan"} else text

        enum_text = None
        display_value = normalize_text(result.value_text or result.value_raw)
        value_unit = None if node is None else node.get("unit")
        if result.poll_status == "ok" and node and node.get("enum_name"):
            try:
                code = int(float(result.value_text or result.value_raw or ""))
            except Exception:
                code = None
            if code is not None:
                enum_text = resolver.enum_description(node.get("enum_name"), code) or resolver.translate_enum(node.get("enum_name"), code)
                if enum_text:
                    display_value = normalize_text(resolver.translate_enum(node.get("enum_name"), code) or display_value)

        health_status = "unknown"
        health_text = "未知"
        health_reason = "未配置正常判断规则"

        if result.poll_status != "ok":
            health_status = "error"
            health_text = "采集失败"
            health_reason = result.error_message or "SNMP 采集失败"
        elif strategy and strategy.judge_type == "enum_equals":
            expected_values = [str(item) for item in (strategy.expected_values_json or [])]
            current_candidates = [str(result.value_raw or ""), str(result.value_text or ""), str(display_value or "")]
            matched = any(item and item in expected_values for item in current_candidates)
            if matched:
                health_status = "normal"
                health_text = "正常"
                health_reason = "命中正常判断规则"
            else:
                health_status = strategy.health_on_mismatch or "warning"
                health_text = {
                    "warning": "告警",
                    "major": "主要告警",
                    "critical": "严重告警",
                    "normal": "正常",
                }.get(health_status, "未知")
                health_reason = f"当前值 {display_value or result.value_raw or '-'} 未命中枚举值判断规则"
        elif strategy and strategy.judge_type == "value_equals":
            expected_values = [str(item) for item in (strategy.expected_values_json or [])]
            current_value = str(result.value_raw or result.value_text or display_value or "")
            if current_value and current_value in expected_values:
                health_status = "normal"
                health_text = "正常"
                health_reason = "命中原始值匹配规则"
            else:
                health_status = strategy.health_on_mismatch or "warning"
                health_text = {
                    "warning": "告警",
                    "major": "主要告警",
                    "critical": "严重告警",
                    "normal": "正常",
                }.get(health_status, "未知")
                health_reason = f"当前值 {current_value or '-'} 未命中原始值匹配规则"
        elif strategy and strategy.judge_type in {"number_gt", "number_gte", "number_lt", "number_lte", "number_between"}:
            expected_numbers = self._parse_expected_numbers(strategy.expected_values_json, strategy.expected_value_text)
            current_number = result.value_num
            if current_number is None:
                try:
                    current_number = float(str(result.value_raw or result.value_text or "").strip())
                except Exception:
                    current_number = None
            matched = False
            if current_number is not None:
                if strategy.judge_type == "number_gt" and len(expected_numbers) >= 1:
                    matched = current_number > expected_numbers[0]
                elif strategy.judge_type == "number_gte" and len(expected_numbers) >= 1:
                    matched = current_number >= expected_numbers[0]
                elif strategy.judge_type == "number_lt" and len(expected_numbers) >= 1:
                    matched = current_number < expected_numbers[0]
                elif strategy.judge_type == "number_lte" and len(expected_numbers) >= 1:
                    matched = current_number <= expected_numbers[0]
                elif strategy.judge_type == "number_between" and len(expected_numbers) >= 2:
                    lower, upper = sorted(expected_numbers[:2])
                    matched = lower <= current_number <= upper
            if matched:
                health_status = "normal"
                health_text = "正常"
                health_reason = "命中数值判断规则"
            else:
                health_status = strategy.health_on_mismatch or "warning"
                health_text = {
                    "warning": "告警",
                    "major": "主要告警",
                    "critical": "严重告警",
                    "normal": "正常",
                }.get(health_status, "未知")
                expected_text = strategy.expected_value_text or ", ".join(str(item) for item in expected_numbers) or "-"
                health_reason = f"当前值 {display_value or result.value_raw or '-'} 未命中数值判断规则 {expected_text}"

        return {
            "oid_name_zh": None if node is None else node.get("name_zh"),
            "category": None if node is None else node.get("category"),
            "display_value": display_value,
            "enum_text": enum_text,
            "value_unit": value_unit,
            "health_status": health_status,
            "health_text": health_text,
            "health_reason": health_reason,
        }

    @staticmethod
    def _parse_expected_numbers(expected_values_json, expected_value_text: str | None) -> list[float]:
        values: list[float] = []
        raw_values = list(expected_values_json or [])
        if not raw_values and expected_value_text:
            raw_values = [item.strip() for item in expected_value_text.replace("，", ",").split(",") if item.strip()]
        for item in raw_values:
            try:
                values.append(float(str(item).strip()))
            except Exception:
                continue
        return values

    @staticmethod
    def _apply_alarm_rule(event: NormalizedTrapEvent, rule: AlarmRule | None) -> None:
        if rule is None:
            return
        if not event.severity and rule.default_severity:
            event.severity = rule.default_severity
        if event.status in ACTIVE_ALARM_STATUSES and event.severity in ACTIVE_ALARM_SEVERITIES:
            event.is_active_alarm = bool(rule.should_create_active)
            event.should_popup = bool(rule.should_popup and event.severity in {"critical", "major"})
        event.extra["rule_severity"] = rule.default_severity
        event.extra["rule_should_create_active"] = rule.should_create_active
        event.extra["rule_should_popup"] = rule.should_popup
        event.extra["rule_description"] = rule.description

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
        active_alarm = session.execute(select(ActiveAlarm).where(ActiveAlarm.dedupe_key == dedupe_key)).scalar_one_or_none()

        opens_alarm = bool(event.is_active_alarm and event.status in ACTIVE_ALARM_STATUSES)
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
    def _create_alarm_event(
        session,
        *,
        device_id: int | None,
        trap_event: TrapEvent,
        event: NormalizedTrapEvent,
        active_alarm: ActiveAlarm | None,
        occurred_at: datetime,
    ) -> None:
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
    def _apply_popup_notification(
        session,
        *,
        device_id: int | None,
        trap_event: TrapEvent,
        event: NormalizedTrapEvent,
        active_alarm: ActiveAlarm | None,
    ) -> None:
        if not event.should_popup:
            return
        popup_key = CollectorPipeline._active_alarm_key(device_id, event.alarm_obj, event.alarm_id)
        popup = session.execute(select(PopupNotification).where(PopupNotification.popup_key == popup_key)).scalar_one_or_none()
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
