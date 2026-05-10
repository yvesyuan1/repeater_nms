from __future__ import annotations

import json
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlencode

from flask import (
    Blueprint,
    Response,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session as flask_session,
    stream_with_context,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash

from repeater_nms.collector.snmp_client import SnmpV2cClient
from repeater_nms.db.models import (
    ActiveAlarm,
    AlarmAckLog,
    AlarmEvent,
    AlarmRule,
    Device,
    DeviceLatestValue,
    DeviceProfile,
    MibEnum,
    MibNode,
    OperationLog,
    PollingStrategy,
    PopupNotification,
    SnmpControlTemplate,
    TrapEvent,
    User,
)
from repeater_nms.db.seed_data import DEFAULT_PROFILE_CODE
from repeater_nms.web.db import get_db_session
from repeater_nms.web.extensions import login_manager
from repeater_nms.web.security import role_required
from repeater_nms.web.snmp_controls import read_control, request_oid, resolve_enum_options, validate_write_value
from repeater_nms.web.utils import (
    alarm_description_label,
    app_timezone,
    build_captcha_svg,
    build_trap_summary,
    compute_device_overview_status,
    format_dt,
    generate_captcha_code,
    health_label,
    highest_severity,
    log_operation,
    overview_status_label,
    parse_local_datetime,
    profile_title,
    redis_client_from_app,
    role_description,
    role_label,
    severity_label,
    status_label,
    trap_name_label,
    trap_type_label,
)


AUTO_RECOVERY_MESSAGE = "系统检查正常，自动恢复"


web_bp = Blueprint("web", __name__)


@login_manager.user_loader
def load_user(user_id: str) -> User | None:
    session = get_db_session()
    return session.get(User, int(user_id))


def _base_context(**extra):
    return {
        "page_title": current_app.config["PAGE_TITLE"],
        "app_name": current_app.config["APP_NAME"],
        **extra,
    }


def _refresh_captcha() -> None:
    flask_session["captcha_code"] = generate_captcha_code(current_app.config["CAPTCHA_LENGTH"])


def _captcha_ok(user_input: str) -> bool:
    expect = str(flask_session.get("captcha_code", "")).strip().upper()
    actual = str(user_input or "").strip().upper()
    return bool(expect and actual and expect == actual)


def _device_map(session) -> dict[int, Device]:
    return {item.id: item for item in session.execute(select(Device)).scalars().all()}


def _profile_map(session) -> dict[str, DeviceProfile]:
    return {item.profile_code: item for item in session.execute(select(DeviceProfile)).scalars().all()}


def _metric_text(value: Any) -> str:
    if value is None:
        return "-"
    text = str(value).strip()
    if not text or text.lower() in {"null", "none", "nan"}:
        return "-"
    return text


def _metric_value(row: DeviceLatestValue | None, *, prefer_enum: bool = False) -> str:
    if row is None:
        return "-"
    candidates = []
    if prefer_enum:
        candidates.extend([row.enum_text, row.display_value, row.value_text, row.value_raw])
    else:
        candidates.extend([row.display_value, row.enum_text, row.value_text, row.value_raw])
    for item in candidates:
        text = _metric_text(item)
        if text != "-":
            return text
    return "-"


def _bool_form(name: str) -> bool:
    return request.form.get(name) == "on"


def _split_expected_values(text: str | None) -> list[str]:
    raw = (text or "").replace("，", ",")
    return [item.strip() for item in raw.split(",") if item.strip()]


def _json_pretty(value: Any) -> str:
    if value is None:
        return "-"
    try:
        return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)
    except Exception:
        return str(value)


def _int_form(name: str, default: int, *, minimum: int | None = None) -> int:
    raw = request.form.get(name, "").strip()
    try:
        value = int(raw or default)
    except Exception:
        value = default
    if minimum is not None:
        value = max(minimum, value)
    return value


def _clean_multi_values(name: str) -> list[str]:
    values: list[str] = []
    for item in request.args.getlist(name):
        text = item.strip()
        if text and text not in values:
            values.append(text)
    return values


def _page_number(default: int = 1) -> int:
    return max(request.args.get("page", default, type=int) or default, 1)


def _per_page_number(default: int = 30, allowed: tuple[int, ...] = (20, 30, 50, 100)) -> int:
    value = request.args.get("per_page", default, type=int) or default
    return value if value in allowed else default


def _json_form(name: str) -> dict[str, Any] | list[Any] | None:
    raw = request.form.get(name, "").strip()
    if not raw:
        return None
    return json.loads(raw)


def _build_page_url(endpoint: str, page: int, **params: Any) -> str:
    payload: dict[str, Any] = {"page": page}
    for key, value in params.items():
        if value in (None, "", [], ()):
            continue
        payload[key] = value
    base = url_for(endpoint)
    query = urlencode(payload, doseq=True)
    return f"{base}?{query}" if query else base


def _build_pager(*, endpoint: str, page: int, per_page: int, total: int, **params: Any) -> dict[str, Any]:
    total_pages = max((total + per_page - 1) // per_page, 1)
    current_page = min(max(page, 1), total_pages)
    start_page = max(1, current_page - 2)
    end_page = min(total_pages, current_page + 2)
    pages = [
        {
            "number": number,
            "url": _build_page_url(endpoint, number, **params),
            "current": number == current_page,
        }
        for number in range(start_page, end_page + 1)
    ]
    return {
        "page": current_page,
        "per_page": per_page,
        "total": total,
        "total_pages": total_pages,
        "pages": pages,
        "first_url": _build_page_url(endpoint, 1, **params) if current_page > 1 else None,
        "last_url": _build_page_url(endpoint, total_pages, **params) if current_page < total_pages else None,
        "prev_url": _build_page_url(endpoint, current_page - 1, **params) if current_page > 1 else None,
        "next_url": _build_page_url(endpoint, current_page + 1, **params) if current_page < total_pages else None,
    }


def _redirect_profile_page(profile_code: str | None = None, **query):
    params = {key: value for key, value in query.items() if value not in (None, "", False)}
    if profile_code:
        params["profile_code"] = profile_code
    if params:
        return redirect(url_for("web.mib_nodes", **params))
    return redirect(url_for("web.mib_nodes"))


def _snmp_client() -> SnmpV2cClient:
    client = current_app.config.get("SNMP_CLIENT")
    if client is not None:
        return client
    return SnmpV2cClient()


def _strategy_from_form(strategy: PollingStrategy, *, mib_node: MibNode | None = None) -> None:
    strategy.poll_interval_seconds = _int_form("poll_interval_seconds", strategy.poll_interval_seconds or 60, minimum=5)
    strategy.display_order = _int_form("display_order", strategy.display_order or 100, minimum=1)
    strategy.is_enabled = _bool_form("is_enabled")
    strategy.save_history = _bool_form("save_history")
    strategy.show_in_overview = _bool_form("show_in_overview")
    strategy.show_in_device_card = _bool_form("show_in_device_card")
    strategy.judge_type = request.form.get("judge_type", "").strip() or None
    expected_value_text = request.form.get("expected_value_text", "").strip()
    strategy.expected_value_text = expected_value_text or None
    strategy.expected_values_json = _split_expected_values(expected_value_text) if expected_value_text else None
    strategy.health_on_mismatch = request.form.get("health_on_mismatch", "").strip() or None
    strategy.notes = request.form.get("notes", "").strip() or None
    if mib_node is not None:
        strategy.mib_node_id = mib_node.id
        strategy.oid = mib_node.oid
        strategy.node_name = mib_node.name
        strategy.node_name_zh = mib_node.name_zh
        strategy.category = mib_node.category
    else:
        strategy.mib_node_id = None
        strategy.oid = request.form.get("oid", strategy.oid).strip() or strategy.oid
        strategy.node_name = request.form.get("node_name", strategy.node_name).strip() or strategy.node_name
        strategy.node_name_zh = request.form.get("node_name_zh", strategy.node_name_zh or "").strip() or None
        strategy.category = request.form.get("category", strategy.category or "").strip() or None


def _mib_node_from_form(node: MibNode) -> None:
    node.oid = request.form.get("oid", node.oid).strip() or node.oid
    node.name = request.form.get("name", node.name).strip() or node.name
    node.name_zh = request.form.get("name_zh", node.name_zh or "").strip() or None
    node.category = request.form.get("category", node.category).strip() or node.category
    node.category_zh = request.form.get("category_zh", node.category_zh or "").strip() or None
    node.access = request.form.get("access", node.access).strip() or node.access
    node.data_type = request.form.get("data_type", node.data_type).strip() or node.data_type
    node.description = request.form.get("description", node.description).strip() or node.description
    node.enum_name = request.form.get("enum_name", node.enum_name or "").strip() or None
    node.unit = request.form.get("unit", node.unit or "").strip() or None
    node.overview_order = _int_form("overview_order", node.overview_order or 100, minimum=0)
    node.is_pollable = _bool_form("is_pollable")
    node.is_trap_field = _bool_form("is_trap_field")
    node.is_set_reserved = _bool_form("is_set_reserved")
    node.scalar_suffix_zero = _bool_form("scalar_suffix_zero")


def _snmp_control_from_form(control: SnmpControlTemplate) -> None:
    control.oid_name = request.form.get("oid_name", control.oid_name).strip() or control.oid_name
    control.oid = request.form.get("oid", control.oid).strip() or control.oid
    control.oid_suffix = request.form.get("oid_suffix", control.oid_suffix or "").strip() or None
    control.display_name = request.form.get("display_name", control.display_name).strip() or control.display_name
    control.description = request.form.get("description", control.description or "").strip() or None
    control.access = request.form.get("access", control.access).strip() or control.access
    control.data_type = request.form.get("data_type", control.data_type).strip() or control.data_type
    control.value_type = request.form.get("value_type", control.value_type).strip() or control.value_type
    control.unit = request.form.get("unit", control.unit or "").strip() or None
    control.enum_name = request.form.get("enum_name", control.enum_name or "").strip() or None
    control.normal_rule = request.form.get("normal_rule", control.normal_rule or "").strip() or None
    control.writable = _bool_form("writable")
    control.sort_order = _int_form("sort_order", control.sort_order or 100, minimum=1)
    control.enabled = _bool_form("enabled")
    control.enum_map_json = _json_form("enum_map_json")


def _alarm_rule_from_form(rule: AlarmRule) -> None:
    rule.alarm_id = request.form.get("alarm_id", rule.alarm_id).strip() or rule.alarm_id
    rule.default_severity = request.form.get("default_severity", rule.default_severity).strip() or rule.default_severity
    rule.should_create_active = _bool_form("should_create_active")
    rule.should_popup = _bool_form("should_popup")
    rule.category = request.form.get("category", rule.category or "").strip() or None
    rule.description = request.form.get("description", rule.description).strip() or rule.description


def _trap_payload(item: TrapEvent, device: Device | None, profile: DeviceProfile | None) -> dict[str, Any]:
    device_name = device.name if device else "未知设备"
    alarm_description = alarm_description_label(item.alarm_id)
    summary_zh = build_trap_summary(
        device_name=device_name,
        trap_name=item.trap_name,
        trap_type=item.trap_type,
        alarm_obj=item.alarm_obj,
        alarm_id=item.alarm_id,
        severity=item.severity,
        status=item.status,
        raw_summary=item.raw_summary,
        alarm_description=alarm_description,
    )
    return {
        "id": item.id,
        "pdu_id": item.pdu_id,
        "received_at": format_dt(item.received_at),
        "received_at_iso": (
            item.received_at.isoformat()
            if item.received_at and item.received_at.tzinfo is None
            else (item.received_at.astimezone(timezone.utc).isoformat() if item.received_at else None)
        ),
        "source_ip": item.source_ip,
        "device_id": item.device_id,
        "device_name": device_name,
        "profile_title": profile_title(profile.vendor if profile else None, profile.model if profile else None),
        "trap_type": item.trap_type,
        "trap_type_label": trap_type_label(item.trap_type),
        "trap_name": item.trap_name,
        "trap_name_label": trap_name_label(item.trap_name),
        "alarm_obj": item.alarm_obj,
        "alarm_id": item.alarm_id,
        "alarm_description": alarm_description,
        "severity": item.severity,
        "severity_label": severity_label(item.severity),
        "status": item.status,
        "status_label": status_label(item.status),
        "device_alarm_time_raw": item.device_alarm_time_raw,
        "raw_summary": item.raw_summary,
        "summary_zh": summary_zh,
        "translated_json": item.translated_json,
        "detail_url": url_for("web.trap_detail", trap_id=item.id),
    }


def _trap_group_payload(rows: list[dict[str, Any]]) -> dict[str, Any]:
    primary = rows[0]
    summaries: list[str] = []
    for item in rows:
        summary = str(item.get("raw_summary") or "").strip()
        if summary and summary not in summaries:
            summaries.append(summary)
    return {
        "pdu_id": primary.get("pdu_id"),
        "received_at": primary.get("received_at"),
        "received_at_iso": primary.get("received_at_iso"),
        "source_ip": primary.get("source_ip"),
        "device_id": primary.get("device_id"),
        "device_name": primary.get("device_name"),
        "profile_title": primary.get("profile_title"),
        "trap_type": primary.get("trap_type"),
        "trap_type_label": primary.get("trap_type_label"),
        "trap_name": primary.get("trap_name"),
        "trap_name_label": primary.get("trap_name_label"),
        "severity": primary.get("severity"),
        "severity_label": primary.get("severity_label"),
        "status": primary.get("status"),
        "status_label": primary.get("status_label"),
        "summary_zh": primary.get("summary_zh"),
        "detail_url": primary.get("detail_url"),
        "row_count": len(rows),
        "split_rows": rows,
        "summary_lines": summaries[:6],
    }


def _collect_device_overviews(session) -> list[dict[str, Any]]:
    devices = session.execute(select(Device).order_by(Device.name.asc())).scalars().all()
    profiles = _profile_map(session)
    strategies = session.execute(select(PollingStrategy).where(PollingStrategy.is_enabled.is_(True))).scalars().all()
    active_alarms = session.execute(select(ActiveAlarm)).scalars().all()
    latest_values = session.execute(select(DeviceLatestValue)).scalars().all()
    recent_traps = session.execute(select(TrapEvent).order_by(TrapEvent.received_at.desc(), TrapEvent.id.desc())).scalars().all()

    active_by_device: dict[int, list[ActiveAlarm]] = {}
    for item in active_alarms:
        if item.device_id is None:
            continue
        active_by_device.setdefault(item.device_id, []).append(item)

    strategy_names_by_profile: dict[str, set[str]] = {}
    for item in strategies:
        strategy_names_by_profile.setdefault(item.profile_code, set()).add(item.node_name)

    latest_by_device: dict[int, dict[str, DeviceLatestValue]] = {}
    for item in latest_values:
        profile_code = item.profile_code or DEFAULT_PROFILE_CODE
        strategy_names = strategy_names_by_profile.get(profile_code)
        metric_key = item.oid_name or item.oid
        if strategy_names and item.oid_name and item.oid_name not in strategy_names:
            continue
        latest_by_device.setdefault(item.device_id, {})[metric_key] = item

    recent_trap_by_device: dict[int, TrapEvent] = {}
    for item in recent_traps:
        if item.device_id is None:
            continue
        recent_trap_by_device.setdefault(item.device_id, item)

    overviews: list[dict[str, Any]] = []
    for device in devices:
        profile = profiles.get(device.device_profile_code)
        current_alarms = [item for item in active_by_device.get(device.id, []) if item.is_open]
        highest_alarm = highest_severity([item.severity for item in current_alarms if item.severity])
        latest_rows = latest_by_device.get(device.id, {})
        health_statuses = [row.health_status for row in latest_rows.values() if row.health_status]
        overview_status = compute_device_overview_status(
            last_poll_status=device.last_poll_status,
            highest_alarm_severity=highest_alarm,
            health_statuses=health_statuses,
        )
        aps_active = latest_rows.get("apsActive")
        aps_stat = latest_rows.get("apsStat")
        dfp_active = latest_rows.get("dfpActive")
        overviews.append(
            {
                "device": device,
                "profile": profile,
                "profile_title": profile_title(profile.vendor if profile else None, profile.model if profile else None),
                "vendor": None if profile is None else profile.vendor,
                "model": None if profile is None else profile.model,
                "active_alarm_count": len(current_alarms),
                "highest_alarm_severity": highest_alarm,
                "highest_alarm_label": severity_label(highest_alarm),
                "recent_trap_at": None if device.id not in recent_trap_by_device else format_dt(recent_trap_by_device[device.id].received_at),
                "recent_poll_at": format_dt(device.last_polled_at),
                "recent_error": "-" if device.last_poll_status == "ok" else _metric_text(device.last_poll_message),
                "aps_active": _metric_value(aps_active),
                "aps_active_health": None if aps_active is None else aps_active.health_status,
                "aps_stat": _metric_value(aps_stat, prefer_enum=True),
                "aps_stat_text": None if aps_stat is None else _metric_text(aps_stat.enum_text or aps_stat.health_reason),
                "dfp_active": _metric_value(dfp_active),
                "dfp_active_health": None if dfp_active is None else dfp_active.health_status,
                "overview_status": overview_status,
                "overview_status_label": overview_status_label(overview_status),
            }
        )
    return overviews


def _device_payload(device: Device, profile: DeviceProfile | None) -> dict[str, Any]:
    return {
        "id": device.id,
        "name": device.name,
        "ip": device.ip,
        "brand": None if profile is None else profile.vendor,
        "model": None if profile is None else profile.model,
        "profile_code": device.device_profile_code,
        "profile_title": profile_title(profile.vendor if profile else None, profile.model if profile else None),
        "snmp_version": device.snmp_version,
        "snmp_port": device.snmp_port,
        "read_community_masked": "已配置" if device.read_community else "未配置",
        "write_community_masked": "已配置" if device.write_community else "未配置",
        "is_enabled": device.is_enabled,
        "notes": device.notes,
        "last_online_at": format_dt(device.last_online_at),
        "last_polled_at": format_dt(device.last_polled_at),
        "last_poll_status": device.last_poll_status,
        "last_poll_message": device.last_poll_message,
    }


def _severity_rank(value: str | None) -> int:
    return {"critical": 5, "major": 4, "warning": 3, "minor": 2, "indeterminate": 1, "cleared": 0}.get(value or "", -1)


def _local_day_bounds(now: datetime | None = None) -> tuple[datetime, datetime]:
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    local_now = current.astimezone(app_timezone())
    day_start_local = local_now.replace(hour=0, minute=0, second=0, microsecond=0)
    day_end_local = day_start_local + timedelta(days=1)
    return day_start_local.astimezone(timezone.utc), day_end_local.astimezone(timezone.utc)


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=app_timezone()).astimezone(timezone.utc)
    return value.astimezone(timezone.utc)


def _event_priority(item: dict[str, Any]) -> tuple[int, int, float, int]:
    event = item["event"]
    active_alarm = item.get("active_alarm")
    is_open = bool(item.get("is_open")) if "is_open" in item else _event_is_current_open(event, active_alarm)
    is_unacked = bool(item.get("is_unacked")) if "is_unacked" in item else _event_is_current_unacked(event, active_alarm)
    severity = _severity_rank(item.get("severity_sort") or event.severity)
    occurrence_count = 0 if active_alarm is None else int(active_alarm.occurrence_count or 0)
    occurred_at = _as_utc(event.occurred_at)
    occurred_ts = occurred_at.timestamp() if occurred_at else 0.0
    return (
        2 if is_open and is_unacked else 1 if is_open else 0,
        severity,
        occurred_ts,
        occurrence_count,
    )


def _effective_event_severity(
    event: AlarmEvent,
    *,
    active_alarm: ActiveAlarm | None = None,
    rule: AlarmRule | None = None,
    trap_event: TrapEvent | None = None,
) -> str | None:
    if event.severity and event.severity != "cleared":
        return event.severity
    if active_alarm and active_alarm.severity and active_alarm.severity != "cleared":
        return active_alarm.severity
    if rule and rule.default_severity:
        return rule.default_severity
    if trap_event and trap_event.severity and trap_event.severity != "cleared":
        return trap_event.severity
    return event.severity


def _event_is_recovery_event(event: AlarmEvent) -> bool:
    return bool(event.status == "close" or event.severity == "cleared")


def _event_is_current_open(event: AlarmEvent, active_alarm: ActiveAlarm | None) -> bool:
    if _event_is_recovery_event(event):
        return False
    if active_alarm is None or not active_alarm.is_open:
        return False
    if event.trap_event_id and active_alarm.last_trap_event_id:
        return active_alarm.last_trap_event_id == event.trap_event_id
    return event.status in {"report", "change"}


def _event_is_current_unacked(event: AlarmEvent, active_alarm: ActiveAlarm | None) -> bool:
    return bool(_event_is_current_open(event, active_alarm) and active_alarm and not active_alarm.is_acknowledged)


def _device_event_payload(
    item: AlarmEvent,
    *,
    active_alarm: ActiveAlarm | None,
    device_name: str,
    device_ip: str | None = None,
    rule: AlarmRule | None = None,
    trap_event: TrapEvent | None = None,
) -> dict[str, Any]:
    effective_severity = _effective_event_severity(
        item,
        active_alarm=active_alarm,
        rule=rule,
        trap_event=trap_event,
    )
    is_open = _event_is_current_open(item, active_alarm)
    auto_recovered = bool(
        item.message == AUTO_RECOVERY_MESSAGE
        or (active_alarm and active_alarm.notes == AUTO_RECOVERY_MESSAGE and not active_alarm.is_open)
    )
    return {
        "id": item.id,
        "trap_event_id": item.trap_event_id,
        "device_id": item.device_id,
        "device_name": device_name,
        "device_ip": device_ip or "-",
        "alarm_obj": item.alarm_obj,
        "alarm_id": item.alarm_id,
        "alarm_description": alarm_description_label(item.alarm_id),
        "severity": effective_severity,
        "severity_label": severity_label(effective_severity),
        "severity_raw": item.severity,
        "status": item.status,
        "status_label": status_label(item.status),
        "event_type": item.event_type,
        "message": item.message,
        "occurred_at": format_dt(item.occurred_at),
        "occurred_at_iso": item.occurred_at.astimezone(timezone.utc).isoformat() if item.occurred_at else None,
        "restored_at": None if not active_alarm or active_alarm.is_open else format_dt(active_alarm.closed_at),
        "state_label": AUTO_RECOVERY_MESSAGE if auto_recovered else ("未恢复" if is_open else "已恢复"),
        "auto_recovered": auto_recovered,
        "source": "Trap",
        "is_open": is_open,
        "is_unacked": _event_is_current_unacked(item, active_alarm),
    }


def _apply_manual_read_status(device: Device, payloads: list[dict[str, Any]]) -> None:
    ok_count = sum(1 for item in payloads if item.get("read_status") == "ok")
    device.last_polled_at = datetime.now(timezone.utc)
    if ok_count:
        device.last_online_at = device.last_polled_at
    if not payloads:
        device.last_poll_status = "error"
        device.last_poll_message = "no enabled snmp controls"
    elif ok_count == len(payloads):
        device.last_poll_status = "ok"
        device.last_poll_message = "manual snmp refresh ok"
    elif ok_count == 0:
        device.last_poll_status = "error"
        device.last_poll_message = "manual snmp refresh failed"
    else:
        device.last_poll_status = "partial"
        device.last_poll_message = "manual snmp refresh partial"


@web_bp.get("/captcha.svg")
def captcha_svg():
    _refresh_captcha()
    svg = build_captcha_svg(flask_session["captcha_code"])
    return Response(svg, mimetype="image/svg+xml", headers={"Cache-Control": "no-store"})


@web_bp.get("/")
def root():
    if current_user.is_authenticated:
        return redirect(url_for("web.dashboard"))
    return redirect(url_for("web.login"))


@web_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("web.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        captcha = request.form.get("captcha", "")
        session = get_db_session()

        if not _captcha_ok(captcha):
            flash("验证码错误，请重新输入。", "error")
            _refresh_captcha()
            return render_template("login.html", **_base_context(page_name="登录"))

        user = session.execute(select(User).where(User.username == username)).scalar_one_or_none()
        if user is None or not user.is_active or not check_password_hash(user.password_hash, password):
            flash("用户名或密码错误。", "error")
        else:
            login_user(user, remember=False)
            user.last_login_at = datetime.now(timezone.utc)
            log_operation(
                session,
                user_id=user.id,
                username_snapshot=user.username,
                action="login",
                target_type="user",
                target_id=str(user.id),
            )
            session.commit()
            return redirect(url_for("web.dashboard"))

        _refresh_captcha()

    if request.method == "GET":
        _refresh_captcha()
    return render_template("login.html", **_base_context(page_name="登录"))


@web_bp.post("/logout")
@login_required
def logout():
    session = get_db_session()
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="logout",
        target_type="user",
        target_id=str(current_user.id),
    )
    session.commit()
    logout_user()
    flash("已退出登录。", "success")
    return redirect(url_for("web.login"))


@web_bp.get("/dashboard")
@login_required
def dashboard():
    session = get_db_session()
    overviews = _collect_device_overviews(session)
    devices = _device_map(session)
    event_rows = session.execute(select(AlarmEvent).order_by(AlarmEvent.occurred_at.desc(), AlarmEvent.id.desc())).scalars().all()
    active_alarm_rows = session.execute(select(ActiveAlarm)).scalars().all()
    active_alarm_map = {item.id: item for item in active_alarm_rows}
    trap_ids = {item.trap_event_id for item in event_rows if item.trap_event_id}
    trap_map = {
        item.id: item
        for item in session.execute(select(TrapEvent).where(TrapEvent.id.in_(trap_ids))).scalars().all()
    } if trap_ids else {}
    profile_codes = {item.profile_code or DEFAULT_PROFILE_CODE for item in trap_map.values()}
    rule_map = {
        (item.profile_code, item.alarm_id): item
        for item in session.execute(select(AlarmRule).where(AlarmRule.profile_code.in_(profile_codes))).scalars().all()
    } if profile_codes else {}
    event_views: list[dict[str, Any]] = []
    for item in event_rows:
        device = devices.get(item.device_id)
        active_alarm = active_alarm_map.get(item.active_alarm_id)
        trap_event = trap_map.get(item.trap_event_id) if item.trap_event_id else None
        profile_code = trap_event.profile_code if trap_event and trap_event.profile_code else DEFAULT_PROFILE_CODE
        rule = rule_map.get((profile_code, item.alarm_id or ""))
        payload = _device_event_payload(
            item,
            active_alarm=active_alarm,
            device_name=device.name if device else "未知设备",
            device_ip=None if device is None else device.ip,
            rule=rule,
            trap_event=trap_event,
        )
        payload["event"] = item
        payload["active_alarm"] = active_alarm
        payload["severity_sort"] = payload["severity"]
        payload["trap_detail_url"] = (
            url_for("web.trap_detail", trap_id=item.trap_event_id) if item.trap_event_id else None
        )
        payload["device_detail_url"] = (
            url_for("web.device_detail", device_id=device.id) if device else None
        )
        payload["occurrence_count"] = 0 if active_alarm is None else int(active_alarm.occurrence_count or 0)
        event_views.append(payload)
    event_views.sort(key=_event_priority, reverse=True)
    event_views = event_views[:6]
    active_alarm_total = sum(item["active_alarm_count"] for item in overviews)
    unacked_alarm_total = sum(1 for item in active_alarm_rows if item.is_open and not item.is_acknowledged)
    normal_device_total = sum(1 for item in overviews if item["overview_status"] == "normal")
    abnormal_device_total = len(overviews) - normal_device_total
    online_device_total = sum(1 for item in overviews if item["device"].last_poll_status in {"ok", "partial"})
    offline_device_total = max(len(overviews) - online_device_total, 0)
    focus_device_total = sum(1 for item in overviews if item["overview_status"] in {"warning", "major", "critical", "poll_error"})
    day_start_utc, day_end_utc = _local_day_bounds()
    today_new_event_total = sum(
        1
        for item in event_rows
        if _as_utc(item.occurred_at) and day_start_utc <= _as_utc(item.occurred_at) < day_end_utc
    )
    overviews.sort(
        key=lambda item: (
            2 if item["overview_status"] in {"critical", "major", "warning", "poll_error"} else 1 if item["overview_status"] == "unknown" else 0,
            _severity_rank(item["highest_alarm_severity"]),
            item["active_alarm_count"],
            item["recent_trap_at"] or "",
        ),
        reverse=True,
    )
    return render_template(
        "dashboard.html",
        **_base_context(
            page_name="系统概览",
            page_description="查看设备运行状态与当前事件统计。",
            device_total=len(overviews),
            online_devices=online_device_total,
            offline_devices=offline_device_total,
            normal_device_total=normal_device_total,
            abnormal_device_total=abnormal_device_total,
            active_alarm_total=active_alarm_total,
            unacked_alarm_total=unacked_alarm_total,
            device_overviews=overviews,
            recent_events=event_views,
            critical_event_total=sum(1 for item in overviews if item["highest_alarm_severity"] == "critical"),
            focus_device_total=focus_device_total,
            today_new_event_total=today_new_event_total,
        ),
    )


@web_bp.route("/users", methods=["GET", "POST"])
@login_required
@role_required("admin")
def users():
    session = get_db_session()
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "viewer")
        is_active = request.form.get("is_active") == "on"
        if not username or not password:
            flash("用户名和密码不能为空。", "error")
        elif session.execute(select(User).where(User.username == username)).scalar_one_or_none():
            flash("用户名已存在。", "error")
        else:
            user = User(
                username=username,
                password_hash=generate_password_hash(password),
                role=role,
                is_active=is_active,
            )
            session.add(user)
            session.flush()
            log_operation(
                session,
                user_id=current_user.id,
                username_snapshot=current_user.username,
                action="create_user",
                target_type="user",
                target_id=str(user.id),
                details_json={"username": username, "role": role, "is_active": is_active},
            )
            session.commit()
            flash("用户已创建。", "success")
            return redirect(url_for("web.users"))

    users_list = session.execute(select(User).order_by(User.id.asc())).scalars().all()
    return render_template(
        "users.html",
        **_base_context(
            page_name="用户管理",
            users=users_list,
            role_descriptions=[
                {"role": "admin", "label": role_label("admin"), "description": role_description("admin")},
                {"role": "operator", "label": role_label("operator"), "description": role_description("operator")},
                {"role": "viewer", "label": role_label("viewer"), "description": role_description("viewer")},
            ],
        ),
    )


@web_bp.post("/users/<int:user_id>/toggle")
@login_required
@role_required("admin")
def toggle_user(user_id: int):
    session = get_db_session()
    user = session.get(User, user_id)
    if user is None:
        flash("用户不存在。", "error")
        return redirect(url_for("web.users"))
    user.is_active = not user.is_active
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="toggle_user",
        target_type="user",
        target_id=str(user.id),
        details_json={"is_active": user.is_active},
    )
    session.commit()
    flash("用户状态已更新。", "success")
    return redirect(url_for("web.users"))


@web_bp.route("/devices", methods=["GET", "POST"])
@login_required
def devices():
    session = get_db_session()
    profiles = session.execute(select(DeviceProfile).order_by(DeviceProfile.vendor.asc(), DeviceProfile.model.asc())).scalars().all()
    if request.method == "POST":
        if current_user.role not in {"admin", "operator"}:
            return Response(status=403)
        name = request.form.get("name", "").strip()
        ip = request.form.get("ip", "").strip()
        read_community = request.form.get("read_community", "").strip()
        write_community = request.form.get("write_community", "").strip() or None
        profile_code = request.form.get("device_profile_code", DEFAULT_PROFILE_CODE).strip() or DEFAULT_PROFILE_CODE
        if not name or not ip or not read_community:
            flash("设备名称、IP 和读团体字不能为空。", "error")
        else:
            device = Device(
                name=name,
                ip=ip,
                device_profile_code=profile_code,
                snmp_port=int(request.form.get("snmp_port", "161") or 161),
                trap_port=int(request.form.get("trap_port", "1162") or 1162),
                snmp_version=request.form.get("snmp_version", "v2c"),
                read_community=read_community,
                write_community=write_community,
                is_enabled=request.form.get("is_enabled") == "on",
                notes=request.form.get("notes", "").strip() or None,
            )
            session.add(device)
            session.flush()
            log_operation(
                session,
                user_id=current_user.id,
                username_snapshot=current_user.username,
                action="create_device",
                target_type="device",
                target_id=str(device.id),
                details_json={"name": device.name, "ip": device.ip, "device_profile_code": profile_code},
            )
            session.commit()
            flash("设备已创建。", "success")
            return redirect(url_for("web.devices"))

    device_rows = session.execute(select(Device).order_by(Device.id.desc())).scalars().all()
    profile_map = _profile_map(session)
    return render_template(
        "devices.html",
        **_base_context(page_name="设备管理", devices=device_rows, profiles=profiles, profile_map=profile_map),
    )


@web_bp.get("/devices/<int:device_id>")
@login_required
def device_detail(device_id: int):
    session = get_db_session()
    device = session.get(Device, device_id)
    if device is None:
        return Response("device not found", status=404)
    profile = session.execute(select(DeviceProfile).where(DeviceProfile.profile_code == device.device_profile_code)).scalar_one_or_none()
    if request.accept_mimetypes.best == "application/json":
        return jsonify(_device_payload(device, profile))
    controls = session.execute(
        select(SnmpControlTemplate)
        .where(
            SnmpControlTemplate.profile_code == device.device_profile_code,
            SnmpControlTemplate.enabled.is_(True),
        )
        .order_by(SnmpControlTemplate.sort_order.asc(), SnmpControlTemplate.id.asc())
    ).scalars().all()
    recent_traps = session.execute(
        select(TrapEvent).where(TrapEvent.device_id == device.id).order_by(TrapEvent.received_at.desc()).limit(10)
    ).scalars().all()
    recent_events = session.execute(
        select(AlarmEvent).where(AlarmEvent.device_id == device.id).order_by(AlarmEvent.occurred_at.desc(), AlarmEvent.id.desc()).limit(8)
    ).scalars().all()
    active_alarms = session.execute(select(ActiveAlarm).where(ActiveAlarm.device_id == device.id)).scalars().all()
    active_alarm_map = {item.id: item for item in active_alarms}
    trap_ids = {item.trap_event_id for item in recent_events if item.trap_event_id}
    trap_map = {
        item.id: item
        for item in session.execute(select(TrapEvent).where(TrapEvent.id.in_(trap_ids))).scalars().all()
    } if trap_ids else {}
    profile_codes = {item.profile_code or DEFAULT_PROFILE_CODE for item in trap_map.values()}
    rule_map = {
        (item.profile_code, item.alarm_id): item
        for item in session.execute(select(AlarmRule).where(AlarmRule.profile_code.in_(profile_codes))).scalars().all()
    } if profile_codes else {}
    trap_views = [_trap_payload(item, device, profile) for item in recent_traps]
    event_views = [
        _device_event_payload(
            item,
            active_alarm=active_alarm_map.get(item.active_alarm_id),
            device_name=device.name,
            device_ip=device.ip,
            rule=rule_map.get(
                (
                    (trap_map.get(item.trap_event_id).profile_code if trap_map.get(item.trap_event_id) and trap_map.get(item.trap_event_id).profile_code else DEFAULT_PROFILE_CODE),
                    item.alarm_id or "",
                )
            ),
            trap_event=trap_map.get(item.trap_event_id) if item.trap_event_id else None,
        )
        for item in recent_events
    ]
    return render_template(
        "device_detail.html",
        **_base_context(
            page_name="设备状态",
            device=device,
            profile=profile,
            device_payload=_device_payload(device, profile),
            snmp_control_count=len(controls),
            recent_traps=trap_views,
            recent_events=event_views,
            open_active_alarm_count=sum(1 for item in active_alarms if item.is_open),
            active_tab=request.args.get("tab", "realtime"),
        ),
    )


@web_bp.post("/devices/<int:device_id>/restore-events")
@login_required
@role_required("admin", "operator")
def restore_device_events(device_id: int):
    session = get_db_session()
    device = session.get(Device, device_id)
    if device is None:
        flash("设备不存在。", "error")
        return redirect(url_for("web.devices"))
    now = datetime.now(timezone.utc)
    alarms = session.execute(
        select(ActiveAlarm).where(
            ActiveAlarm.device_id == device.id,
            ActiveAlarm.is_open.is_(True),
        )
    ).scalars().all()
    for alarm in alarms:
        alarm.is_open = False
        alarm.status = "close"
        alarm.closed_at = now
        alarm.updated_at = now
        alarm.notes = "人工一键恢复"
        session.add(
            AlarmEvent(
                active_alarm_id=alarm.id,
                trap_event_id=alarm.last_trap_event_id,
                device_id=alarm.device_id,
                alarm_obj=alarm.alarm_obj,
                alarm_id=alarm.alarm_id,
                severity_code=alarm.severity_code,
                severity="cleared",
                status_code=None,
                status="close",
                event_type="manual_restore",
                message="人工一键恢复",
                occurred_at=now,
            )
        )
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="restore_device_events",
        target_type="device",
        target_id=str(device.id),
        details_json={"restored_count": len(alarms)},
    )
    session.commit()
    flash(f"已恢复 {len(alarms)} 条未恢复事件。", "success")
    return redirect(url_for("web.device_detail", device_id=device.id, tab="events"))


@web_bp.get("/api/devices/<int:device_id>")
@login_required
def api_device_detail(device_id: int):
    session = get_db_session()
    device = session.get(Device, device_id)
    if device is None:
        return jsonify({"ok": False, "error": "not_found"}), 404
    profile = session.execute(select(DeviceProfile).where(DeviceProfile.profile_code == device.device_profile_code)).scalar_one_or_none()
    return jsonify({"ok": True, "device": _device_payload(device, profile)})


@web_bp.get("/api/devices/<int:device_id>/events")
@login_required
def api_device_events(device_id: int):
    session = get_db_session()
    device = session.get(Device, device_id)
    if device is None:
        return jsonify({"ok": False, "error": "not_found"}), 404
    events = session.execute(
        select(AlarmEvent).where(AlarmEvent.device_id == device.id).order_by(AlarmEvent.occurred_at.desc(), AlarmEvent.id.desc()).limit(20)
    ).scalars().all()
    active_alarm_ids = [item.active_alarm_id for item in events if item.active_alarm_id]
    active_alarm_map = {}
    if active_alarm_ids:
        active_alarm_map = {
            item.id: item
            for item in session.execute(select(ActiveAlarm).where(ActiveAlarm.id.in_(active_alarm_ids))).scalars().all()
        }
    trap_ids = {item.trap_event_id for item in events if item.trap_event_id}
    trap_map = {
        item.id: item
        for item in session.execute(select(TrapEvent).where(TrapEvent.id.in_(trap_ids))).scalars().all()
    } if trap_ids else {}
    profile_codes = {item.profile_code or DEFAULT_PROFILE_CODE for item in trap_map.values()}
    rule_map = {
        (item.profile_code, item.alarm_id): item
        for item in session.execute(select(AlarmRule).where(AlarmRule.profile_code.in_(profile_codes))).scalars().all()
    } if profile_codes else {}
    return jsonify(
        {
            "ok": True,
            "events": [
                _device_event_payload(
                    item,
                    active_alarm=active_alarm_map.get(item.active_alarm_id),
                    device_name=device.name,
                    device_ip=device.ip,
                    rule=rule_map.get(
                        (
                            (trap_map.get(item.trap_event_id).profile_code if trap_map.get(item.trap_event_id) and trap_map.get(item.trap_event_id).profile_code else DEFAULT_PROFILE_CODE),
                            item.alarm_id or "",
                        )
                    ),
                    trap_event=trap_map.get(item.trap_event_id) if item.trap_event_id else None,
                )
                for item in events
            ],
        }
    )


@web_bp.get("/api/devices/<int:device_id>/realtime-status")
@login_required
def api_device_realtime_status(device_id: int):
    session = get_db_session()
    device = session.get(Device, device_id)
    if device is None:
        return jsonify({"ok": False, "error": "not_found"}), 404

    latest_key = f"realtime:device:{device_id}:latest"
    history_key = f"realtime:device:{device_id}:history"
    latest_payload = None
    history_rows: list[dict[str, Any]] = []
    try:
        redis_client = redis_client_from_app(current_app).redis
        latest_raw = redis_client.get(latest_key)
        if latest_raw:
            latest_payload = json.loads(latest_raw)
        for item in redis_client.lrange(history_key, -300, -1):
            try:
                history_rows.append(json.loads(item))
            except Exception:
                continue
    except Exception as exc:
        current_app.logger.warning("realtime status redis read failed device_id=%s error=%s", device_id, exc)

    data_status = "empty"
    last_update_time = None
    interfaces: list[dict[str, Any]] = []
    raw_data = None
    if latest_payload:
        last_update_time = latest_payload.get("ts") or latest_payload.get("received_at")
        interfaces = latest_payload.get("interfaces") if isinstance(latest_payload.get("interfaces"), list) else []
        raw_data = latest_payload.get("raw_data")
        received_at_text = latest_payload.get("received_at")
        data_status = "stale"
        try:
            received_at = datetime.fromisoformat(str(received_at_text).replace("Z", "+00:00"))
            if received_at.tzinfo is None:
                received_at = received_at.replace(tzinfo=timezone.utc)
            age_seconds = (datetime.now(timezone.utc) - received_at.astimezone(timezone.utc)).total_seconds()
            data_status = "normal" if age_seconds <= 5 else "stale"
            if data_status == "stale":
                stale_log_at = current_app.config.setdefault("_REALTIME_STATUS_STALE_LOG_AT", {})
                now_monotonic = time.monotonic()
                if now_monotonic - stale_log_at.get(device_id, 0.0) >= 60:
                    current_app.logger.warning("realtime status data timeout device_id=%s age_seconds=%.3f", device_id, age_seconds)
                    stale_log_at[device_id] = now_monotonic
        except Exception:
            data_status = "stale"

    return jsonify(
        {
            "ok": True,
            "device_id": device.id,
            "device_name": device.name,
            "device_ip": device.ip,
            "last_update_time": last_update_time,
            "data_status": data_status,
            "interfaces": interfaces,
            "history": history_rows,
            "raw_data": raw_data,
        }
    )


def _parse_iso_utc(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _program_status(program: dict[str, Any], now_utc: datetime) -> dict[str, Any]:
    last_update = _parse_iso_utc(program.get("last_update_time"))
    age_seconds = (now_utc - last_update).total_seconds() if last_update else None
    timed_out = bool(age_seconds is None or age_seconds > 30)
    no_video = not int(program.get("video_bw") or 0)
    no_audio = not int(program.get("audio_bw") or 0)
    l1 = int(program.get("l1") or 0)
    l2 = int(program.get("l2") or 0)
    l3 = int(program.get("l3") or 0)
    return {
        "timed_out": timed_out,
        "no_video": no_video,
        "no_audio": no_audio,
        "error_total": l1 + l2 + l3,
    }


def _format_program_for_api(program: dict[str, Any], now_utc: datetime) -> dict[str, Any]:
    flags = _program_status(program, now_utc)
    item = dict(program)
    item.update(flags)
    item["total_bw_mbps"] = round((int(item.get("total_bw") or 0) / 1_000_000), 3)
    item["video_bw_mbps"] = round((int(item.get("video_bw") or 0) / 1_000_000), 3)
    item["audio_bw_mbps"] = round((int(item.get("audio_bw") or 0) / 1_000_000), 3)
    item["last_update_time_display"] = format_dt(_parse_iso_utc(item.get("last_update_time")))
    return item


@web_bp.get("/api/devices/<int:device_id>/program-analysis")
@login_required
def api_device_program_analysis(device_id: int):
    session = get_db_session()
    device = session.get(Device, device_id)
    if device is None:
        return jsonify({"ok": False, "error": "not_found"}), 404

    interface_filter = request.args.get("interface", "all")
    error_filter = request.args.get("error", "all")
    video_filter = request.args.get("video_codec", "all")
    audio_filter = request.args.get("audio_codec", "all")
    keyword = request.args.get("keyword", "").strip().lower()
    page = max(int(request.args.get("page", "1") or 1), 1)
    page_size = min(max(int(request.args.get("page_size", "50") or 50), 10), 200)
    sort_by = request.args.get("sort_by", "default")
    sort_order = request.args.get("sort_order", "asc")

    redis_client = redis_client_from_app(current_app).redis
    interfaces = ["ens7f0", "ens7f1"] if interface_filter == "all" else [interface_filter]
    now_utc = datetime.now(timezone.utc)
    all_programs: list[dict[str, Any]] = []
    batches: dict[str, dict[str, Any]] = {}
    try:
        for interface_name in interfaces:
            if interface_name not in {"ens7f0", "ens7f1"}:
                continue
            programs_key = f"program:device:{device_id}:{interface_name}:programs"
            batch_key = f"program:device:{device_id}:{interface_name}:batch"
            for raw in redis_client.hgetall(programs_key).values():
                try:
                    all_programs.append(_format_program_for_api(json.loads(raw), now_utc))
                except Exception:
                    continue
            batch_raw = redis_client.get(batch_key)
            if batch_raw:
                try:
                    batches[interface_name] = json.loads(batch_raw)
                except Exception:
                    batches[interface_name] = {}
    except Exception as exc:
        current_app.logger.warning("program analysis redis read failed device_id=%s error=%s", device_id, exc)

    def matches(item: dict[str, Any]) -> bool:
        if error_filter == "l1" and int(item.get("l1") or 0) <= 0:
            return False
        if error_filter == "l2" and int(item.get("l2") or 0) <= 0:
            return False
        if error_filter == "l3" and int(item.get("l3") or 0) <= 0:
            return False
        if video_filter == "none" and not item.get("no_video"):
            return False
        if video_filter not in {"all", "none"} and (item.get("video_codec") or "") != video_filter:
            return False
        if audio_filter == "none" and not item.get("no_audio"):
            return False
        if audio_filter not in {"all", "none"} and (item.get("audio_codec") or "") != audio_filter:
            return False
        if keyword:
            haystack = f"{item.get('no')} {item.get('stream')} {item.get('multicast_address')} {item.get('video_codec')} {item.get('audio_codec')}".lower()
            if keyword not in haystack:
                return False
        return True

    filtered = [item for item in all_programs if matches(item)]

    def sort_key(item: dict[str, Any]):
        if sort_by == "no":
            return (int(item.get("no") or 0),)
        if sort_by in {"total_bw", "video_bw", "audio_bw", "l1", "l2", "l3"}:
            return (int(item.get(sort_by) or 0),)
        if sort_by == "last_update_time":
            return (item.get("last_update_time") or "",)
        return (item.get("interface") or "", int(item.get("no") or 0))

    filtered.sort(key=sort_key, reverse=(sort_order == "desc" and sort_by != "default"))
    total = len(filtered)
    start = (page - 1) * page_size
    page_rows = filtered[start : start + page_size]

    port_summary: dict[str, dict[str, Any]] = {}
    for interface_name in ["ens7f0", "ens7f1"]:
        rows = [item for item in all_programs if item.get("interface") == interface_name]
        batch = batches.get(interface_name, {})
        last_update = _parse_iso_utc(batch.get("last_update_time"))
        data_status = "empty" if not batch else ("stale" if not last_update or (now_utc - last_update).total_seconds() > 10 else "normal")
        if data_status == "stale":
            stale_log_at = current_app.config.setdefault("_PROGRAM_ANALYSIS_STALE_LOG_AT", {})
            key = f"{device_id}:{interface_name}"
            now_monotonic = time.monotonic()
            if now_monotonic - stale_log_at.get(key, 0.0) >= 60:
                current_app.logger.warning("program analysis port data timeout device_id=%s interface=%s", device_id, interface_name)
                stale_log_at[key] = now_monotonic
        port_summary[interface_name] = {
            "total": int(batch.get("total") or len(rows) or 0),
            "received_count": len(rows),
            "total_bandwidth": sum(int(item.get("total_bw") or 0) for item in rows),
            "last_batch_start": batch.get("last_batch_start"),
            "last_batch_end": batch.get("last_batch_end"),
            "last_duration": batch.get("last_duration"),
            "last_update_time": batch.get("last_update_time"),
            "last_update_time_display": format_dt(last_update),
            "data_status": data_status,
        }

    stale_program_count = sum(1 for item in all_programs if item.get("timed_out"))
    if stale_program_count:
        stale_log_at = current_app.config.setdefault("_PROGRAM_STALE_LOG_AT", {})
        now_monotonic = time.monotonic()
        if now_monotonic - stale_log_at.get(device_id, 0.0) >= 60:
            current_app.logger.warning("program analysis program data timeout device_id=%s count=%s", device_id, stale_program_count)
            stale_log_at[device_id] = now_monotonic

    last_update_time = max((value.get("last_update_time") for value in port_summary.values() if value.get("last_update_time")), default=None)
    last_update_dt = _parse_iso_utc(last_update_time)
    total_programs = sum(value["received_count"] for value in port_summary.values())
    summary = {
        "total_programs": total_programs,
        "total_bandwidth": sum(int(item.get("total_bw") or 0) for item in all_programs),
        "ens7f0": port_summary["ens7f0"],
        "ens7f1": port_summary["ens7f1"],
    }
    return jsonify(
        {
            "ok": True,
            "device_id": device.id,
            "last_update_time": last_update_time,
            "last_update_time_display": format_dt(last_update_dt),
            "summary": summary,
            "programs": page_rows,
            "pagination": {"page": page, "page_size": page_size, "total": total, "pages": max((total + page_size - 1) // page_size, 1)},
        }
    )


@web_bp.get("/api/devices/<int:device_id>/snmp-controls")
@login_required
def api_device_snmp_controls(device_id: int):
    session = get_db_session()
    device = session.get(Device, device_id)
    if device is None:
        return jsonify({"ok": False, "error": "not_found"}), 404
    profile = session.execute(select(DeviceProfile).where(DeviceProfile.profile_code == device.device_profile_code)).scalar_one_or_none()
    controls = session.execute(
        select(SnmpControlTemplate)
        .where(
            SnmpControlTemplate.profile_code == device.device_profile_code,
            SnmpControlTemplate.enabled.is_(True),
        )
        .order_by(SnmpControlTemplate.sort_order.asc(), SnmpControlTemplate.id.asc())
    ).scalars().all()
    client = _snmp_client()
    payloads = [read_control(session, client, device, control).payload for control in controls]
    _apply_manual_read_status(device, payloads)
    session.commit()
    return jsonify({"ok": True, "controls": payloads, "device": _device_payload(device, profile)})


@web_bp.get("/api/devices/<int:device_id>/snmp-controls/<int:control_id>")
@login_required
def api_device_snmp_control(device_id: int, control_id: int):
    session = get_db_session()
    device = session.get(Device, device_id)
    if device is None:
        return jsonify({"ok": False, "error": "not_found"}), 404
    control = session.get(SnmpControlTemplate, control_id)
    if control is None or control.profile_code != device.device_profile_code or not control.enabled:
        return jsonify({"ok": False, "error": "control_not_found"}), 404
    payload = read_control(session, _snmp_client(), device, control).payload
    _apply_manual_read_status(device, [payload])
    session.commit()
    return jsonify({"ok": True, "control": payload})


@web_bp.post("/api/devices/<int:device_id>/snmp-controls/<int:control_id>/set")
@login_required
@role_required("admin", "operator")
def api_set_device_snmp_control(device_id: int, control_id: int):
    session = get_db_session()
    device = session.get(Device, device_id)
    if device is None:
        return jsonify({"ok": False, "error": "not_found"}), 404
    control = session.get(SnmpControlTemplate, control_id)
    if control is None or control.profile_code != device.device_profile_code or not control.enabled:
        return jsonify({"ok": False, "error": "control_not_found"}), 404
    if control.access != "read-write" or not control.writable:
        return jsonify({"ok": False, "error": "read_only", "message": "该控制项不允许写入"}), 400
    if not device.write_community:
        return jsonify({"ok": False, "error": "missing_write_community", "message": "设备未配置写 community"}), 400

    body = request.get_json(silent=True) or request.form
    enum_options = resolve_enum_options(session, control)
    try:
        target_value = validate_write_value(control, body.get("value"), enum_options)
    except (TypeError, ValueError) as exc:
        return jsonify({"ok": False, "error": "invalid_value", "message": str(exc)}), 400

    client = _snmp_client()
    before_payload = read_control(session, client, device, control).payload
    set_result = client.set_oid_sync(
        device.ip,
        device.snmp_port,
        device.write_community,
        request_oid(control.oid),
        control.data_type,
        target_value,
    )
    verify_payload = read_control(session, client, device, control).payload
    _apply_manual_read_status(device, [verify_payload])

    if not set_result.get("ok"):
        result_code = "set_failed"
        message = str(set_result.get("error") or "SNMP 写入失败")
        ok = False
    elif verify_payload.get("read_status") != "ok":
        result_code = "verify_failed"
        message = "写入成功，但回读校验失败"
        ok = False
    elif str(verify_payload.get("current_value_raw") or "") != target_value:
        result_code = "verify_mismatch"
        message = "写入成功，但读取校验值不一致"
        ok = False
    else:
        result_code = "success"
        message = "控制成功"
        ok = True

    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="snmp_set_control",
        target_type="snmp_control",
        target_id=str(control.id),
        details_json={
            "device_id": device.id,
            "device_name": device.name,
            "oid_name": control.oid_name,
            "oid": control.oid,
            "old_value": before_payload.get("current_value_raw"),
            "new_value": target_value,
            "verify_value": verify_payload.get("current_value_raw"),
            "result_code": result_code,
            "message": message,
        },
    )
    session.commit()
    return jsonify(
        {
            "ok": ok,
            "result_code": result_code,
            "message": message,
            "before": before_payload,
            "verify": verify_payload,
        }
    ), (200 if ok else 400)


@web_bp.route("/devices/<int:device_id>/edit", methods=["GET", "POST"])
@login_required
@role_required("admin", "operator")
def edit_device(device_id: int):
    session = get_db_session()
    device = session.get(Device, device_id)
    profiles = session.execute(select(DeviceProfile).order_by(DeviceProfile.vendor.asc(), DeviceProfile.model.asc())).scalars().all()
    if device is None:
        return Response("device not found", status=404)
    if request.method == "POST":
        device.name = request.form.get("name", device.name).strip() or device.name
        device.ip = request.form.get("ip", device.ip).strip() or device.ip
        device.device_profile_code = request.form.get("device_profile_code", device.device_profile_code).strip() or device.device_profile_code
        device.snmp_port = int(request.form.get("snmp_port", str(device.snmp_port)) or device.snmp_port)
        device.trap_port = int(request.form.get("trap_port", str(device.trap_port)) or device.trap_port)
        device.snmp_version = request.form.get("snmp_version", device.snmp_version)
        if read_community := request.form.get("read_community", "").strip():
            device.read_community = read_community
        if "write_community" in request.form:
            write_community = request.form.get("write_community", "").strip()
            if write_community:
                device.write_community = write_community
        device.is_enabled = request.form.get("is_enabled") == "on"
        device.notes = request.form.get("notes", "").strip() or None
        log_operation(
            session,
            user_id=current_user.id,
            username_snapshot=current_user.username,
            action="edit_device",
            target_type="device",
            target_id=str(device.id),
            details_json={"name": device.name, "ip": device.ip, "device_profile_code": device.device_profile_code},
        )
        session.commit()
        flash("设备已更新。", "success")
        return redirect(url_for("web.device_detail", device_id=device.id))
    return render_template("device_form.html", **_base_context(page_name=f"编辑设备 - {device.name}", device=device, profiles=profiles))


@web_bp.post("/devices/<int:device_id>/toggle")
@login_required
@role_required("admin", "operator")
def toggle_device(device_id: int):
    session = get_db_session()
    device = session.get(Device, device_id)
    if device is None:
        flash("设备不存在。", "error")
        return redirect(url_for("web.devices"))
    device.is_enabled = not device.is_enabled
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="toggle_device",
        target_type="device",
        target_id=str(device.id),
        details_json={"is_enabled": device.is_enabled},
    )
    session.commit()
    flash("设备启停状态已更新。", "success")
    return redirect(url_for("web.devices"))


@web_bp.get("/mib-nodes")
@login_required
def mib_nodes():
    session = get_db_session()
    profiles = session.execute(select(DeviceProfile).order_by(DeviceProfile.vendor.asc(), DeviceProfile.model.asc())).scalars().all()
    selected_code = request.args.get("profile_code", "").strip() or (profiles[0].profile_code if profiles else DEFAULT_PROFILE_CODE)
    active_tab = request.args.get("tab", "").strip() or "profile"
    create_mode = request.args.get("mode", "").strip() == "create"
    selected_profile = next((item for item in profiles if item.profile_code == selected_code), None)
    nodes = session.execute(
        select(MibNode)
        .where(MibNode.profile_code == selected_code)
        .order_by(MibNode.category.asc(), MibNode.overview_order.asc(), MibNode.oid.asc())
    ).scalars().all()
    strategies = session.execute(
        select(PollingStrategy).where(PollingStrategy.profile_code == selected_code).order_by(PollingStrategy.display_order.asc(), PollingStrategy.id.asc())
    ).scalars().all()
    controls = session.execute(
        select(SnmpControlTemplate)
        .where(SnmpControlTemplate.profile_code == selected_code)
        .order_by(SnmpControlTemplate.sort_order.asc(), SnmpControlTemplate.id.asc())
    ).scalars().all()
    enums = session.execute(
        select(MibEnum).where(MibEnum.profile_code == selected_code).order_by(MibEnum.enum_name.asc(), MibEnum.code.asc())
    ).scalars().all()
    alarm_rules = session.execute(
        select(AlarmRule).where(AlarmRule.profile_code == selected_code).order_by(AlarmRule.category.asc(), AlarmRule.alarm_id.asc())
    ).scalars().all()
    selected_strategy_id = request.args.get("strategy_id", type=int)
    selected_control_id = request.args.get("control_id", type=int)
    selected_node_id = request.args.get("node_id", type=int)
    selected_enum_id = request.args.get("enum_id", type=int)
    selected_rule_id = request.args.get("rule_id", type=int)
    selected_strategy = next((item for item in strategies if item.id == selected_strategy_id), strategies[0] if strategies else None)
    selected_control = next((item for item in controls if item.id == selected_control_id), controls[0] if controls else None)
    selected_node = next((item for item in nodes if item.id == selected_node_id), nodes[0] if nodes else None)
    selected_enum = next((item for item in enums if item.id == selected_enum_id), enums[0] if enums else None)
    selected_rule = next((item for item in alarm_rules if item.id == selected_rule_id), alarm_rules[0] if alarm_rules else None)
    return render_template(
        "mib_nodes.html",
        **_base_context(
            page_name="设备模板",
            profiles=profiles,
            selected_profile=selected_profile,
            active_tab=active_tab,
            create_mode=create_mode,
            nodes=nodes,
            strategies=strategies,
            controls=controls,
            enums=enums,
            alarm_rules=alarm_rules,
            selected_strategy=selected_strategy,
            selected_control=selected_control,
            selected_node=selected_node,
            selected_enum=selected_enum,
            selected_rule=selected_rule,
            access_options=[
                ("read-only", "read-only"),
                ("read-write", "read-write"),
            ],
            value_type_options=[
                ("text", "文本"),
                ("number", "数值"),
                ("switch", "开关"),
                ("enum", "枚举"),
                ("ip", "IP 地址"),
            ],
            judge_type_options=[
                ("", "不做判断"),
                ("enum_equals", "枚举值匹配"),
                ("value_equals", "原始值匹配"),
                ("number_gt", "数值大于"),
                ("number_gte", "数值大于等于"),
                ("number_lt", "数值小于"),
                ("number_lte", "数值小于等于"),
                ("number_between", "数值区间"),
            ],
            health_options=[
                ("", "未知"),
                ("warning", "警告"),
                ("major", "主要"),
                ("critical", "紧急"),
            ],
            severity_options=[
                ("warning", "警告"),
                ("minor", "次要"),
                ("major", "主要"),
                ("critical", "紧急"),
                ("indeterminate", "不确定"),
                ("cleared", "清除"),
            ],
            can_manage_templates=current_user.role == "admin",
        ),
    )


@web_bp.post("/mib-nodes/profiles")
@login_required
@role_required("admin")
def create_mib_profile():
    session = get_db_session()
    profile_code = request.form.get("profile_code", "").strip()
    vendor = request.form.get("vendor", "").strip()
    model = request.form.get("model", "").strip()
    category = request.form.get("category", "").strip() or "中继器"
    parser_key = request.form.get("parser_key", "").strip() or DEFAULT_PROFILE_CODE
    description = request.form.get("description", "").strip() or None

    if not profile_code or not vendor or not model:
        flash("模板编码、厂家和型号不能为空。", "error")
        return redirect(url_for("web.mib_nodes"))
    if session.execute(select(DeviceProfile).where(DeviceProfile.profile_code == profile_code)).scalar_one_or_none():
        flash("模板编码已存在。", "error")
        return redirect(url_for("web.mib_nodes", profile_code=profile_code))

    profile = DeviceProfile(
        profile_code=profile_code,
        vendor=vendor,
        model=model,
        category=category,
        parser_key=parser_key,
        description=description,
        is_builtin=False,
    )
    session.add(profile)
    session.flush()
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="create_device_profile",
        target_type="device_profile",
        target_id=str(profile.id),
        details_json={"profile_code": profile.profile_code, "vendor": vendor, "model": model},
    )
    session.commit()
    flash("设备模板已创建。", "success")
    return _redirect_profile_page(profile.profile_code, tab="profile")


@web_bp.post("/mib-nodes/profiles/<profile_code>")
@login_required
@role_required("admin")
def update_mib_profile(profile_code: str):
    session = get_db_session()
    profile = session.execute(select(DeviceProfile).where(DeviceProfile.profile_code == profile_code)).scalar_one_or_none()
    if profile is None:
        flash("设备模板不存在。", "error")
        return redirect(url_for("web.mib_nodes"))

    profile.vendor = request.form.get("vendor", profile.vendor).strip() or profile.vendor
    profile.model = request.form.get("model", profile.model).strip() or profile.model
    profile.category = request.form.get("category", profile.category).strip() or profile.category
    profile.parser_key = request.form.get("parser_key", profile.parser_key).strip() or profile.parser_key
    profile.description = request.form.get("description", "").strip() or None
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="update_device_profile",
        target_type="device_profile",
        target_id=str(profile.id),
        details_json={"profile_code": profile.profile_code},
    )
    session.commit()
    flash("设备模板配置已更新。", "success")
    return _redirect_profile_page(profile.profile_code, tab="profile")


@web_bp.post("/mib-nodes/profiles/<profile_code>/delete")
@login_required
@role_required("admin")
def delete_mib_profile(profile_code: str):
    session = get_db_session()
    profile = session.execute(select(DeviceProfile).where(DeviceProfile.profile_code == profile_code)).scalar_one_or_none()
    if profile is None:
        flash("设备模板不存在。", "error")
        return _redirect_profile_page(tab="profile")
    if profile.is_builtin:
        flash("内置设备模板不允许删除。", "error")
        return _redirect_profile_page(profile.profile_code, tab="profile")
    if session.execute(select(Device.id).where(Device.device_profile_code == profile_code).limit(1)).scalar_one_or_none() is not None:
        flash("仍有设备使用该模板，不能删除。", "error")
        return _redirect_profile_page(profile.profile_code, tab="profile")
    if session.execute(select(TrapEvent.id).where(TrapEvent.profile_code == profile_code).limit(1)).scalar_one_or_none() is not None:
        flash("该模板已有 Trap 历史记录，不能删除。", "error")
        return _redirect_profile_page(profile.profile_code, tab="profile")

    session.query(PollingStrategy).filter(PollingStrategy.profile_code == profile_code).delete()
    session.query(SnmpControlTemplate).filter(SnmpControlTemplate.profile_code == profile_code).delete()
    session.query(AlarmRule).filter(AlarmRule.profile_code == profile_code).delete()
    session.query(MibEnum).filter(MibEnum.profile_code == profile_code).delete()
    session.query(MibNode).filter(MibNode.profile_code == profile_code).delete()
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="delete_device_profile",
        target_type="device_profile",
        target_id=str(profile.id),
        details_json={"profile_code": profile.profile_code},
    )
    session.delete(profile)
    session.commit()
    flash("设备模板已删除。", "success")
    return _redirect_profile_page(tab="profile")


@web_bp.post("/mib-nodes/strategies")
@login_required
@role_required("admin")
def create_polling_strategy():
    session = get_db_session()
    profile_code = request.form.get("profile_code", "").strip()
    profile = session.execute(select(DeviceProfile).where(DeviceProfile.profile_code == profile_code)).scalar_one_or_none()
    if profile is None:
        flash("设备模板不存在。", "error")
        return _redirect_profile_page(tab="strategies")

    mib_node_id_raw = request.form.get("mib_node_id", "").strip()
    mib_node = None
    if mib_node_id_raw:
        mib_node = session.get(MibNode, int(mib_node_id_raw))
        if mib_node is None or mib_node.profile_code != profile_code:
            flash("采集项关联的 MIB 节点不存在。", "error")
            return _redirect_profile_page(profile_code, tab="strategies", mode="create")

    strategy = PollingStrategy(
        profile_code=profile_code,
        oid=request.form.get("oid", "").strip() or (mib_node.oid if mib_node else ""),
        node_name=request.form.get("node_name", "").strip() or (mib_node.name if mib_node else ""),
        node_name_zh=request.form.get("node_name_zh", "").strip() or (mib_node.name_zh if mib_node else None),
        category=request.form.get("category", "").strip() or (mib_node.category if mib_node else None),
        poll_interval_seconds=60,
        is_enabled=True,
        save_history=True,
        show_in_overview=False,
        show_in_device_card=False,
        display_order=100,
    )
    _strategy_from_form(strategy, mib_node=mib_node)
    if not strategy.oid or not strategy.node_name:
        flash("采集策略必须填写节点名和 OID。", "error")
        return _redirect_profile_page(profile_code, tab="strategies", mode="create")

    session.add(strategy)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        flash("同一模板下节点名重复，无法创建采集策略。", "error")
        return _redirect_profile_page(profile_code, tab="strategies", mode="create")
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="create_polling_strategy",
        target_type="polling_strategy",
        target_id=str(strategy.id),
        details_json={"profile_code": strategy.profile_code, "node_name": strategy.node_name},
    )
    session.commit()
    flash("采集策略已创建。", "success")
    return _redirect_profile_page(profile_code, tab="strategies", strategy_id=strategy.id)


@web_bp.post("/mib-nodes/strategies/<int:strategy_id>")
@login_required
@role_required("admin")
def update_polling_strategy(strategy_id: int):
    session = get_db_session()
    strategy = session.get(PollingStrategy, strategy_id)
    if strategy is None:
        flash("采集策略不存在。", "error")
        return _redirect_profile_page(tab="strategies")

    mib_node_id_raw = request.form.get("mib_node_id", "").strip()
    mib_node = None
    if mib_node_id_raw:
        mib_node = session.get(MibNode, int(mib_node_id_raw))
        if mib_node is None or mib_node.profile_code != strategy.profile_code:
            flash("采集项关联的 MIB 节点不存在。", "error")
            return _redirect_profile_page(strategy.profile_code, tab="strategies", strategy_id=strategy.id)

    _strategy_from_form(strategy, mib_node=mib_node)
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="update_polling_strategy",
        target_type="polling_strategy",
        target_id=str(strategy.id),
        details_json={"profile_code": strategy.profile_code, "node_name": strategy.node_name},
    )
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        flash("同一模板下节点名重复，无法保存采集策略。", "error")
        return _redirect_profile_page(strategy.profile_code, tab="strategies", strategy_id=strategy.id)
    flash("采集策略已更新。", "success")
    return _redirect_profile_page(strategy.profile_code, tab="strategies", strategy_id=strategy.id)


@web_bp.post("/mib-nodes/strategies/<int:strategy_id>/delete")
@login_required
@role_required("admin")
def delete_polling_strategy(strategy_id: int):
    session = get_db_session()
    strategy = session.get(PollingStrategy, strategy_id)
    if strategy is None:
        flash("采集策略不存在。", "error")
        return _redirect_profile_page(tab="strategies")
    profile_code = strategy.profile_code
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="delete_polling_strategy",
        target_type="polling_strategy",
        target_id=str(strategy.id),
        details_json={"profile_code": strategy.profile_code, "node_name": strategy.node_name},
    )
    session.delete(strategy)
    session.commit()
    flash("采集策略已删除。", "success")
    return _redirect_profile_page(profile_code, tab="strategies")


@web_bp.post("/mib-nodes/controls")
@login_required
@role_required("admin")
def create_snmp_control_template():
    session = get_db_session()
    profile_code = request.form.get("profile_code", "").strip()
    profile = session.execute(select(DeviceProfile).where(DeviceProfile.profile_code == profile_code)).scalar_one_or_none()
    if profile is None:
        flash("设备模板不存在。", "error")
        return _redirect_profile_page(tab="controls")

    control = SnmpControlTemplate(
        profile_code=profile_code,
        oid_name=request.form.get("oid_name", "").strip(),
        oid=request.form.get("oid", "").strip(),
        display_name=request.form.get("display_name", "").strip() or request.form.get("oid_name", "").strip(),
        access="read-only",
        data_type=request.form.get("data_type", "").strip() or "DisplayString",
        value_type=request.form.get("value_type", "").strip() or "text",
        writable=False,
        sort_order=100,
        enabled=True,
    )
    try:
        _snmp_control_from_form(control)
    except ValueError:
        flash("枚举映射 JSON 格式不正确。", "error")
        return _redirect_profile_page(profile_code, tab="controls", mode="create")
    if not control.oid_name or not control.oid or not control.display_name:
        flash("SNMP 控制项必须填写名称、OID 和显示名称。", "error")
        return _redirect_profile_page(profile_code, tab="controls", mode="create")

    session.add(control)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        flash("同一模板下控制项名称或 OID 重复。", "error")
        return _redirect_profile_page(profile_code, tab="controls", mode="create")
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="create_snmp_control_template",
        target_type="snmp_control_template",
        target_id=str(control.id),
        details_json={"profile_code": control.profile_code, "oid_name": control.oid_name, "oid": control.oid},
    )
    session.commit()
    flash("SNMP 控制项已创建。", "success")
    return _redirect_profile_page(profile_code, tab="controls", control_id=control.id)


@web_bp.post("/mib-nodes/controls/<int:control_id>")
@login_required
@role_required("admin")
def update_snmp_control_template(control_id: int):
    session = get_db_session()
    control = session.get(SnmpControlTemplate, control_id)
    if control is None:
        flash("SNMP 控制项不存在。", "error")
        return _redirect_profile_page(tab="controls")
    try:
        _snmp_control_from_form(control)
    except ValueError:
        flash("枚举映射 JSON 格式不正确。", "error")
        return _redirect_profile_page(control.profile_code, tab="controls", control_id=control.id)
    if not control.oid_name or not control.oid or not control.display_name:
        flash("SNMP 控制项必须填写名称、OID 和显示名称。", "error")
        return _redirect_profile_page(control.profile_code, tab="controls", control_id=control.id)
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="update_snmp_control_template",
        target_type="snmp_control_template",
        target_id=str(control.id),
        details_json={"profile_code": control.profile_code, "oid_name": control.oid_name, "oid": control.oid},
    )
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        flash("同一模板下控制项名称或 OID 重复。", "error")
        return _redirect_profile_page(control.profile_code, tab="controls", control_id=control.id)
    flash("SNMP 控制项已更新。", "success")
    return _redirect_profile_page(control.profile_code, tab="controls", control_id=control.id)


@web_bp.post("/mib-nodes/controls/<int:control_id>/delete")
@login_required
@role_required("admin")
def delete_snmp_control_template(control_id: int):
    session = get_db_session()
    control = session.get(SnmpControlTemplate, control_id)
    if control is None:
        flash("SNMP 控制项不存在。", "error")
        return _redirect_profile_page(tab="controls")
    profile_code = control.profile_code
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="delete_snmp_control_template",
        target_type="snmp_control_template",
        target_id=str(control.id),
        details_json={"profile_code": control.profile_code, "oid_name": control.oid_name},
    )
    session.delete(control)
    session.commit()
    flash("SNMP 控制项已删除。", "success")
    return _redirect_profile_page(profile_code, tab="controls")


@web_bp.post("/mib-nodes/nodes")
@login_required
@role_required("admin")
def create_mib_node():
    session = get_db_session()
    profile_code = request.form.get("profile_code", "").strip()
    profile = session.execute(select(DeviceProfile).where(DeviceProfile.profile_code == profile_code)).scalar_one_or_none()
    if profile is None:
        flash("设备模板不存在。", "error")
        return _redirect_profile_page(tab="nodes")

    node = MibNode(
        profile_code=profile_code,
        oid=request.form.get("oid", "").strip(),
        name=request.form.get("name", "").strip(),
        category=request.form.get("category", "").strip() or "system",
        access=request.form.get("access", "").strip() or "read-only",
        data_type=request.form.get("data_type", "").strip() or "String",
        description=request.form.get("description", "").strip() or "未填写说明",
    )
    _mib_node_from_form(node)
    if not node.oid or not node.name:
        flash("MIB 节点必须填写 OID 和节点名。", "error")
        return _redirect_profile_page(profile_code, tab="nodes", mode="create")

    session.add(node)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        flash("OID 或节点名已存在，当前库暂不支持跨模板重复。", "error")
        return _redirect_profile_page(profile_code, tab="nodes", mode="create")
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="create_mib_node",
        target_type="mib_node",
        target_id=str(node.id),
        details_json={"profile_code": node.profile_code, "name": node.name, "oid": node.oid},
    )
    session.commit()
    flash("MIB 节点已创建。", "success")
    return _redirect_profile_page(profile_code, tab="nodes", node_id=node.id)


@web_bp.post("/mib-nodes/nodes/<int:node_id>")
@login_required
@role_required("admin")
def update_mib_node(node_id: int):
    session = get_db_session()
    node = session.get(MibNode, node_id)
    if node is None:
        flash("MIB 节点不存在。", "error")
        return _redirect_profile_page(tab="nodes")

    _mib_node_from_form(node)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        flash("OID 或节点名已存在，当前库暂不支持跨模板重复。", "error")
        return _redirect_profile_page(node.profile_code, tab="nodes", node_id=node.id)
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="update_mib_node",
        target_type="mib_node",
        target_id=str(node.id),
        details_json={"profile_code": node.profile_code, "name": node.name, "oid": node.oid},
    )
    session.commit()
    flash("MIB 节点已更新。", "success")
    return _redirect_profile_page(node.profile_code, tab="nodes", node_id=node.id)


@web_bp.post("/mib-nodes/nodes/<int:node_id>/delete")
@login_required
@role_required("admin")
def delete_mib_node(node_id: int):
    session = get_db_session()
    node = session.get(MibNode, node_id)
    if node is None:
        flash("MIB 节点不存在。", "error")
        return _redirect_profile_page(tab="nodes")
    profile_code = node.profile_code
    if session.execute(select(PollingStrategy.id).where(PollingStrategy.mib_node_id == node.id).limit(1)).scalar_one_or_none() is not None:
        flash("该 MIB 节点仍被采集策略引用，不能删除。", "error")
        return _redirect_profile_page(profile_code, tab="nodes", node_id=node.id)
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="delete_mib_node",
        target_type="mib_node",
        target_id=str(node.id),
        details_json={"profile_code": node.profile_code, "name": node.name, "oid": node.oid},
    )
    session.delete(node)
    session.commit()
    flash("MIB 节点已删除。", "success")
    return _redirect_profile_page(profile_code, tab="nodes")


@web_bp.post("/mib-nodes/enums")
@login_required
@role_required("admin")
def create_mib_enum():
    session = get_db_session()
    profile_code = request.form.get("profile_code", "").strip()
    if session.execute(select(DeviceProfile.id).where(DeviceProfile.profile_code == profile_code)).scalar_one_or_none() is None:
        flash("设备模板不存在。", "error")
        return _redirect_profile_page(tab="enums")

    enum_name = request.form.get("enum_name", "").strip()
    label = request.form.get("label", "").strip()
    description = request.form.get("description", "").strip()
    code = _int_form("code", 0)
    if not enum_name or not label or not description:
        flash("枚举名称、值标签和说明不能为空。", "error")
        return _redirect_profile_page(profile_code, tab="enums", mode="create")

    enum_item = MibEnum(
        profile_code=profile_code,
        enum_name=enum_name,
        code=code,
        label=label,
        description=description,
    )
    session.add(enum_item)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        flash("同名枚举值已存在，当前库暂不支持跨模板重复。", "error")
        return _redirect_profile_page(profile_code, tab="enums", mode="create")
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="create_mib_enum",
        target_type="mib_enum",
        target_id=str(enum_item.id),
        details_json={"profile_code": enum_item.profile_code, "enum_name": enum_item.enum_name, "code": enum_item.code},
    )
    session.commit()
    flash("枚举已创建。", "success")
    return _redirect_profile_page(profile_code, tab="enums", enum_id=enum_item.id)


@web_bp.post("/mib-nodes/enums/<int:enum_id>")
@login_required
@role_required("admin")
def update_mib_enum(enum_id: int):
    session = get_db_session()
    enum_item = session.get(MibEnum, enum_id)
    if enum_item is None:
        flash("枚举不存在。", "error")
        return _redirect_profile_page(tab="enums")

    enum_item.enum_name = request.form.get("enum_name", enum_item.enum_name).strip() or enum_item.enum_name
    enum_item.code = _int_form("code", enum_item.code)
    enum_item.label = request.form.get("label", enum_item.label).strip() or enum_item.label
    enum_item.description = request.form.get("description", enum_item.description).strip() or enum_item.description
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        flash("同名枚举值已存在，当前库暂不支持跨模板重复。", "error")
        return _redirect_profile_page(enum_item.profile_code, tab="enums", enum_id=enum_item.id)
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="update_mib_enum",
        target_type="mib_enum",
        target_id=str(enum_item.id),
        details_json={"profile_code": enum_item.profile_code, "enum_name": enum_item.enum_name, "code": enum_item.code},
    )
    session.commit()
    flash("枚举已更新。", "success")
    return _redirect_profile_page(enum_item.profile_code, tab="enums", enum_id=enum_item.id)


@web_bp.post("/mib-nodes/enums/<int:enum_id>/delete")
@login_required
@role_required("admin")
def delete_mib_enum(enum_id: int):
    session = get_db_session()
    enum_item = session.get(MibEnum, enum_id)
    if enum_item is None:
        flash("枚举不存在。", "error")
        return _redirect_profile_page(tab="enums")
    profile_code = enum_item.profile_code
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="delete_mib_enum",
        target_type="mib_enum",
        target_id=str(enum_item.id),
        details_json={"profile_code": enum_item.profile_code, "enum_name": enum_item.enum_name, "code": enum_item.code},
    )
    session.delete(enum_item)
    session.commit()
    flash("枚举已删除。", "success")
    return _redirect_profile_page(profile_code, tab="enums")


@web_bp.post("/mib-nodes/alarm-rules")
@login_required
@role_required("admin")
def create_alarm_rule():
    session = get_db_session()
    profile_code = request.form.get("profile_code", "").strip()
    if session.execute(select(DeviceProfile.id).where(DeviceProfile.profile_code == profile_code)).scalar_one_or_none() is None:
        flash("设备模板不存在。", "error")
        return _redirect_profile_page(tab="rules")

    rule = AlarmRule(
        profile_code=profile_code,
        alarm_id=request.form.get("alarm_id", "").strip(),
        default_severity=request.form.get("default_severity", "").strip() or "warning",
        should_create_active=True,
        should_popup=False,
        description=request.form.get("description", "").strip() or "未填写告警说明",
    )
    _alarm_rule_from_form(rule)
    if not rule.alarm_id:
        flash("告警 ID 不能为空。", "error")
        return _redirect_profile_page(profile_code, tab="rules", mode="create")
    session.add(rule)
    session.flush()
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="create_alarm_rule",
        target_type="alarm_rule",
        target_id=str(rule.id),
        details_json={"profile_code": rule.profile_code, "alarm_id": rule.alarm_id},
    )
    session.commit()
    flash("告警规则已创建。", "success")
    return _redirect_profile_page(profile_code, tab="rules", rule_id=rule.id)


@web_bp.post("/mib-nodes/alarm-rules/<int:rule_id>")
@login_required
@role_required("admin")
def update_alarm_rule(rule_id: int):
    session = get_db_session()
    rule = session.get(AlarmRule, rule_id)
    if rule is None:
        flash("告警规则不存在。", "error")
        return _redirect_profile_page(tab="rules")
    _alarm_rule_from_form(rule)
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="update_alarm_rule",
        target_type="alarm_rule",
        target_id=str(rule.id),
        details_json={"profile_code": rule.profile_code, "alarm_id": rule.alarm_id},
    )
    session.commit()
    flash("告警规则已更新。", "success")
    return _redirect_profile_page(rule.profile_code, tab="rules", rule_id=rule.id)


@web_bp.post("/mib-nodes/alarm-rules/<int:rule_id>/delete")
@login_required
@role_required("admin")
def delete_alarm_rule(rule_id: int):
    session = get_db_session()
    rule = session.get(AlarmRule, rule_id)
    if rule is None:
        flash("告警规则不存在。", "error")
        return _redirect_profile_page(tab="rules")
    profile_code = rule.profile_code
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="delete_alarm_rule",
        target_type="alarm_rule",
        target_id=str(rule.id),
        details_json={"profile_code": rule.profile_code, "alarm_id": rule.alarm_id},
    )
    session.delete(rule)
    session.commit()
    flash("告警规则已删除。", "success")
    return _redirect_profile_page(profile_code, tab="rules")


@web_bp.get("/traps")
@login_required
def traps():
    session = get_db_session()
    severity_value = request.args.get("severity", "").strip()
    trap_type_value = request.args.get("trap_type", "").strip()
    device_id_value = request.args.get("device_id", "").strip()
    device_id = int(device_id_value) if device_id_value.isdigit() else None
    keyword = request.args.get("keyword", "").strip()
    page = _page_number()
    per_page = _per_page_number()
    stmt = select(TrapEvent)
    if severity_value:
        stmt = stmt.where(TrapEvent.severity == severity_value)
    if trap_type_value:
        stmt = stmt.where(TrapEvent.trap_type == trap_type_value)
    if device_id is not None:
        stmt = stmt.where(TrapEvent.device_id == device_id)
    if keyword:
        stmt = stmt.where(
            or_(
                TrapEvent.alarm_obj.ilike(f"%{keyword}%"),
                TrapEvent.alarm_id.ilike(f"%{keyword}%"),
                TrapEvent.source_ip.ilike(f"%{keyword}%"),
                TrapEvent.pdu_id.ilike(f"%{keyword}%"),
                TrapEvent.raw_summary.ilike(f"%{keyword}%"),
            )
        )
    trap_rows = session.execute(
        stmt.order_by(TrapEvent.received_at.desc(), TrapEvent.id.desc())
    ).scalars().all()
    devices = _device_map(session)
    profiles = _profile_map(session)
    severity_option_values = sorted(
        {item for item in session.execute(select(TrapEvent.severity).where(TrapEvent.severity.is_not(None)).distinct()).scalars().all() if item}
        | ({severity_value} if severity_value else set())
    )
    trap_type_option_values = sorted(
        {item for item in session.execute(select(TrapEvent.trap_type).where(TrapEvent.trap_type.is_not(None)).distinct()).scalars().all() if item}
        | ({trap_type_value} if trap_type_value else set())
    )
    trap_views = [
        _trap_payload(item, devices.get(item.device_id) if item.device_id else None, profiles.get(item.profile_code or DEFAULT_PROFILE_CODE))
        for item in trap_rows
    ]
    grouped_traps: list[dict[str, Any]] = []
    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    ordered_keys: list[str] = []
    for item in trap_views:
        key = str(item.get("pdu_id") or f"single-{item['id']}")
        if key not in buckets:
            ordered_keys.append(key)
        buckets[key].append(item)
    for key in ordered_keys:
        grouped_traps.append(_trap_group_payload(buckets[key]))
    total = len(grouped_traps)
    pager = _build_pager(
        endpoint="web.traps",
        page=page,
        per_page=per_page,
        total=total,
        severity=severity_value or None,
        trap_type=trap_type_value or None,
        device_id=device_id_value or None,
        keyword=keyword,
    )
    grouped_traps = grouped_traps[(pager["page"] - 1) * per_page : pager["page"] * per_page]
    return render_template(
        "traps.html",
        **_base_context(
            page_name="设备日志",
            page_description="查看设备原始日志、Trap 信息和状态变化记录。",
            traps=grouped_traps,
            devices=list(devices.values()),
            severity_options=severity_option_values,
            trap_type_options=trap_type_option_values,
            filter_severity=severity_value,
            filter_trap_type=trap_type_value,
            filter_device_id=device_id,
            filter_keyword=keyword,
            pager=pager,
            per_page_options=[20, 30, 50, 100],
        ),
    )


@web_bp.get("/traps/<int:trap_id>")
@login_required
def trap_detail(trap_id: int):
    session = get_db_session()
    trap = session.get(TrapEvent, trap_id)
    if trap is None:
        return Response("trap not found", status=404)
    device = session.get(Device, trap.device_id) if trap.device_id else None
    profile = session.execute(select(DeviceProfile).where(DeviceProfile.profile_code == (trap.profile_code or DEFAULT_PROFILE_CODE))).scalar_one_or_none()
    payload = _trap_payload(trap, device, profile)
    sibling_rows = session.execute(
        select(TrapEvent).where(TrapEvent.pdu_id == trap.pdu_id).order_by(TrapEvent.id.asc())
    ).scalars().all() if trap.pdu_id else [trap]
    split_rows = [
        _trap_payload(
            item,
            session.get(Device, item.device_id) if item.device_id else None,
            profile,
        )
        for item in sibling_rows
    ]
    raw_varbinds = []
    if isinstance(trap.raw_json, dict):
        maybe_varbinds = trap.raw_json.get("varbinds")
        if isinstance(maybe_varbinds, list):
            raw_varbinds = maybe_varbinds
    return render_template(
        "trap_detail.html",
        **_base_context(
            page_name=f"设备日志详情 - {trap.id}",
            trap=trap,
            payload=payload,
            device=device,
            profile=profile,
            raw_json_pretty=_json_pretty(trap.raw_json),
            translated_json_pretty=_json_pretty(trap.translated_json),
            raw_varbinds=raw_varbinds,
            split_rows=split_rows,
        ),
    )


@web_bp.get("/alarms")
@login_required
def alarms():
    session = get_db_session()
    device_id = request.args.get("device_id", "").strip()
    severity = request.args.get("severity", "").strip()
    ack_state = request.args.get("ack_state", "").strip()
    open_state = request.args.get("open_state", "all").strip() or "all"
    history_status = request.args.get("history_status", "").strip()
    keyword = request.args.get("keyword", "").strip()
    start_at = request.args.get("start_at", "").strip()
    end_at = request.args.get("end_at", "").strip()
    page = _page_number()
    per_page = _per_page_number()

    events = session.execute(select(AlarmEvent).order_by(AlarmEvent.occurred_at.desc(), AlarmEvent.id.desc())).scalars().all()
    active_map = {item.id: item for item in session.execute(select(ActiveAlarm)).scalars().all()}
    devices = session.execute(select(Device).order_by(Device.name.asc())).scalars().all()
    device_map = {item.id: item for item in devices}
    device_names = {item.id: item.name for item in devices}
    trap_ids = {item.trap_event_id for item in events if item.trap_event_id}
    trap_map = {}
    if trap_ids:
        trap_map = {
            item.id: item
            for item in session.execute(select(TrapEvent).where(TrapEvent.id.in_(trap_ids))).scalars().all()
        }
    profile_codes = {item.profile_code or DEFAULT_PROFILE_CODE for item in trap_map.values()}
    rule_map = {}
    if profile_codes:
        rule_map = {
            (item.profile_code, item.alarm_id): item
            for item in session.execute(select(AlarmRule).where(AlarmRule.profile_code.in_(profile_codes))).scalars().all()
        }

    start_dt = parse_local_datetime(start_at)
    end_dt = parse_local_datetime(end_at, end_of_day=True)
    rows: list[dict[str, Any]] = []
    for item in events:
        active_alarm = active_map.get(item.active_alarm_id) if item.active_alarm_id else None
        trap_event = trap_map.get(item.trap_event_id) if item.trap_event_id else None
        profile_code = trap_event.profile_code if trap_event and trap_event.profile_code else DEFAULT_PROFILE_CODE
        rule = rule_map.get((profile_code, item.alarm_id or ""))
        alarm_description = (
            rule.description
            if rule and rule.description and rule.description != (item.alarm_id or "")
            else alarm_description_label(item.alarm_id)
        )
        effective_severity = _effective_event_severity(
            item,
            active_alarm=active_alarm,
            rule=rule,
            trap_event=trap_event,
        )
        row = {
            "event": item,
            "active_alarm": active_alarm,
            "trap_event": trap_event,
            "device_name": device_names.get(item.device_id, "未知设备"),
            "device_ip": "-" if item.device_id not in device_map else device_map[item.device_id].ip,
            "alarm_description": alarm_description,
            "severity": effective_severity,
            "severity_label": severity_label(effective_severity),
            "status_label": status_label(item.status),
            "active_state_label": (
                AUTO_RECOVERY_MESSAGE
                if (
                    item.message == AUTO_RECOVERY_MESSAGE
                    or (active_alarm and active_alarm.notes == AUTO_RECOVERY_MESSAGE and not active_alarm.is_open)
                )
                else ("未恢复" if _event_is_current_open(item, active_alarm) else "已恢复")
            ),
            "ack_state_label": "已确认" if _event_is_current_unacked(item, active_alarm) is False and active_alarm and active_alarm.is_acknowledged else "未确认",
        }
        row["severity_sort"] = effective_severity
        row["is_open"] = _event_is_current_open(item, active_alarm)
        row["is_unacked"] = _event_is_current_unacked(item, active_alarm)
        row["event_state_label"] = "恢复事件" if item.status == "close" or item.severity == "cleared" else "状态事件"
        row["occurrence_count"] = 0 if active_alarm is None else int(active_alarm.occurrence_count or 0)
        row["device_detail_url"] = url_for("web.device_detail", device_id=item.device_id) if item.device_id else None
        row["trap_detail_url"] = url_for("web.trap_detail", trap_id=item.trap_event_id) if item.trap_event_id else None
        row["trap_summary"] = None if trap_event is None else trap_event.raw_summary
        row["restored_at"] = None if not active_alarm or active_alarm.is_open else format_dt(active_alarm.closed_at)
        row["can_ack"] = bool(row["is_open"] and row["is_unacked"])
        if device_id and str(item.device_id or "") != device_id:
            continue
        if severity and effective_severity != severity:
            continue
        if history_status and item.status != history_status:
            continue
        if ack_state == "ack" and row["ack_state_label"] != "已确认":
            continue
        if ack_state == "unack" and row["ack_state_label"] != "未确认":
            continue
        if open_state == "open" and not row["is_open"]:
            continue
        if open_state == "closed" and row["is_open"]:
            continue
        occurred_at_utc = _as_utc(item.occurred_at)
        if start_dt and occurred_at_utc and occurred_at_utc < start_dt:
            continue
        if end_dt and occurred_at_utc and occurred_at_utc >= end_dt:
            continue
        if keyword:
            haystack = " ".join(
                filter(
                    None,
                    [
                        device_names.get(item.device_id),
                        None if item.device_id not in device_map else device_map[item.device_id].ip,
                        item.alarm_obj,
                        item.alarm_id,
                        alarm_description,
                        item.message,
                        None if trap_event is None else trap_event.raw_summary,
                        None if active_alarm is None else active_alarm.notes,
                    ],
                )
            ).lower()
            if keyword.lower() not in haystack:
                continue
        rows.append(row)

    active_count = sum(1 for item in active_map.values() if item.is_open)
    unacked_count = sum(1 for item in active_map.values() if item.is_open and not item.is_acknowledged)
    severe_major_count = sum(1 for item in active_map.values() if item.is_open and item.severity in {"critical", "major"})
    day_start_utc, day_end_utc = _local_day_bounds()
    today_new_event_total = sum(
        1
        for item in events
        if _as_utc(item.occurred_at) and day_start_utc <= _as_utc(item.occurred_at) < day_end_utc
    )
    total = len(rows)
    pager = _build_pager(
        endpoint="web.alarms",
        page=page,
        per_page=per_page,
        total=total,
        device_id=device_id,
        severity=severity,
        ack_state=ack_state,
        open_state=open_state,
        history_status=history_status,
        keyword=keyword,
        start_at=start_at,
        end_at=end_at,
    )
    rows = rows[(pager["page"] - 1) * per_page : pager["page"] * per_page]
    return render_template(
        "alarms.html",
        **_base_context(
            page_name="事件中心",
            page_description="按时间顺序查看和筛选设备事件。",
            alarm_rows=rows,
            devices=devices,
            active_count=active_count,
            unacked_count=unacked_count,
            severe_major_count=severe_major_count,
            today_new_event_total=today_new_event_total,
            pager=pager,
            per_page_options=[20, 30, 50, 100],
            filters={
                "device_id": device_id,
                "severity": severity,
                "ack_state": ack_state,
                "open_state": open_state,
                "history_status": history_status,
                "keyword": keyword,
                "start_at": start_at,
                "end_at": end_at,
                "per_page": str(per_page),
            },
        ),
    )


@web_bp.post("/alarms/<int:alarm_id>/ack")
@login_required
@role_required("admin", "operator")
def ack_alarm(alarm_id: int):
    session = get_db_session()
    alarm = session.get(ActiveAlarm, alarm_id)
    if alarm is None:
        flash("活动告警不存在。", "error")
        return redirect(url_for("web.alarms"))
    alarm.is_acknowledged = True
    alarm.acknowledged_at = datetime.now(timezone.utc)
    alarm.acknowledged_by_user_id = current_user.id
    note = request.form.get("note", "").strip() or None
    if note:
        alarm.notes = note
    session.add(AlarmAckLog(active_alarm_id=alarm.id, user_id=current_user.id, ack_note=note))
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="ack_alarm",
        target_type="active_alarm",
        target_id=str(alarm.id),
        details_json={"note": note},
    )
    session.commit()
    flash("告警已确认。", "success")
    return redirect(request.referrer or url_for("web.alarms"))


@web_bp.get("/logs")
@login_required
def logs():
    session = get_db_session()
    rows = session.execute(select(OperationLog).order_by(OperationLog.created_at.desc(), OperationLog.id.desc()).limit(200)).scalars().all()
    return render_template("logs.html", **_base_context(page_name="操作日志", logs=rows))


@web_bp.get("/api/trap-events")
@login_required
def api_trap_events():
    session = get_db_session()
    severity_values = _clean_multi_values("severity")
    trap_type_values = _clean_multi_values("trap_type")
    device_ids = [int(item) for item in _clean_multi_values("device_id") if item.isdigit()]
    keyword = request.args.get("keyword", "").strip()
    stmt = select(TrapEvent)
    if severity_values:
        stmt = stmt.where(TrapEvent.severity.in_(severity_values))
    if trap_type_values:
        stmt = stmt.where(TrapEvent.trap_type.in_(trap_type_values))
    if device_ids:
        stmt = stmt.where(TrapEvent.device_id.in_(device_ids))
    if keyword:
        stmt = stmt.where(
            or_(
                TrapEvent.alarm_obj.ilike(f"%{keyword}%"),
                TrapEvent.alarm_id.ilike(f"%{keyword}%"),
                TrapEvent.source_ip.ilike(f"%{keyword}%"),
                TrapEvent.pdu_id.ilike(f"%{keyword}%"),
                TrapEvent.raw_summary.ilike(f"%{keyword}%"),
            )
        )
    rows = session.execute(stmt.order_by(TrapEvent.received_at.desc(), TrapEvent.id.desc()).limit(100)).scalars().all()
    devices = _device_map(session)
    profiles = _profile_map(session)
    return jsonify(
        [
            _trap_payload(item, devices.get(item.device_id) if item.device_id else None, profiles.get(item.profile_code or DEFAULT_PROFILE_CODE))
            for item in rows
        ]
    )


@web_bp.get("/api/popup-notifications")
@login_required
def api_popup_notifications():
    session = get_db_session()
    device_names = {item.id: item.name for item in session.execute(select(Device)).scalars().all()}
    items = session.execute(
        select(PopupNotification)
        .where(PopupNotification.is_acknowledged.is_(False), PopupNotification.status == "pending")
        .order_by(PopupNotification.created_at.desc())
        .limit(20)
    ).scalars().all()
    return jsonify(
        [
            {
                "id": item.id,
                "popup_key": item.popup_key,
                "severity": item.severity,
                "severity_label": severity_label(item.severity),
                "alarm_obj": item.alarm_obj,
                "alarm_id": item.alarm_id,
                "status": item.status,
                "status_label": status_label(item.status),
                "device_name": device_names.get(item.device_id, "未知设备"),
                "created_at_display": format_dt(item.created_at),
                "created_at": item.created_at.astimezone(timezone.utc).isoformat() if item.created_at else None,
            }
            for item in items
        ]
    )


@web_bp.post("/api/popup-notifications/<int:popup_id>/ack")
@login_required
@role_required("admin", "operator")
def api_ack_popup(popup_id: int):
    session = get_db_session()
    popup = session.get(PopupNotification, popup_id)
    if popup is None:
        return jsonify({"ok": False, "error": "not_found"}), 404
    popup.is_acknowledged = True
    popup.acknowledged_at = datetime.now(timezone.utc)
    popup.acknowledged_by_user_id = current_user.id
    popup.status = "acknowledged"
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="ack_popup",
        target_type="popup_notification",
        target_id=str(popup.id),
    )
    session.commit()
    return jsonify({"ok": True})


@web_bp.get("/api/events/stream")
@login_required
def event_stream():
    heartbeat_seconds = current_app.config["SSE_HEARTBEAT_SECONDS"]

    @stream_with_context
    def generate():
        yield "retry: 3000\n\n"
        pubsub = None
        try:
            publisher = redis_client_from_app(current_app)
            pubsub = publisher.redis.pubsub(ignore_subscribe_messages=True)
            pubsub.subscribe(publisher.trap_channel)
            last_heartbeat = time.monotonic()
            while True:
                message = pubsub.get_message(timeout=1.0)
                now = time.monotonic()
                if message and message.get("type") == "message":
                    payload = message["data"]
                    yield f"event: trap_event\ndata: {payload}\n\n"
                    last_heartbeat = now
                elif now - last_heartbeat >= heartbeat_seconds:
                    yield 'event: heartbeat\ndata: {"message":"heartbeat"}\n\n'
                    last_heartbeat = now
        except Exception as exc:
            error_payload = json.dumps({"message": f"实时事件通道异常：{exc}"}, ensure_ascii=False)
            yield f"event: error\ndata: {error_payload}\n\n"
        finally:
            if pubsub is not None:
                pubsub.close()

    return Response(generate(), mimetype="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@web_bp.get("/healthz")
def healthz():
    return {"status": "ok", "service": "repeater-nms-web"}
