from __future__ import annotations

import random
import string
from datetime import datetime, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from flask import current_app, has_app_context, request
from sqlalchemy.orm import Session

from repeater_nms.collector.publisher import RedisEventPublisher
from repeater_nms.db.models import OperationLog


try:
    SHANGHAI_TZ = ZoneInfo("Asia/Shanghai")
except ZoneInfoNotFoundError:
    SHANGHAI_TZ = timezone(timedelta(hours=8))

ROLE_LABELS = {
    "admin": "管理员",
    "operator": "值班员",
    "viewer": "只读用户",
}

ROLE_DESCRIPTIONS = {
    "admin": "可管理用户、设备、告警确认和全部页面。",
    "operator": "可管理设备、确认告警、查看 Trap 与日志，但不能管理用户。",
    "viewer": "只能查看页面和状态，不能新增、修改或确认。",
}

SEVERITY_LABELS = {
    "critical": "严重",
    "major": "主要",
    "minor": "次要",
    "warning": "告警",
    "indeterminate": "不确定",
    "cleared": "已清除",
}

STATUS_LABELS = {
    "report": "上报",
    "change": "变化",
    "close": "关闭",
    "pending": "待确认",
    "acknowledged": "已确认",
    "ok": "成功",
    "partial": "部分成功",
    "error": "失败",
}

POLL_STATUS_DESCRIPTIONS = {
    "ok": "本轮采集全部成功。",
    "partial": "本轮采集部分成功，至少有一个 OID 成功，至少有一个 OID 失败。",
    "error": "本轮采集全部失败，当前没有拿到有效 SNMP 数据。",
}

TRAP_NAME_LABELS = {
    "almchg": "告警变更",
    "performance": "性能上报",
}

TRAP_TYPE_LABELS = {
    "alarm": "告警 Trap",
    "performance": "性能 Trap",
}


def app_timezone():
    tz_name = None
    if has_app_context():
        tz_name = current_app.config.get("TIMEZONE")
    try:
        return ZoneInfo(tz_name or "Asia/Shanghai")
    except Exception:
        return SHANGHAI_TZ


def format_dt(value: datetime | None) -> str:
    if value is None:
        return "-"
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(app_timezone()).strftime("%Y-%m-%d %H:%M:%S")


def mask_secret(value: str | None) -> str:
    if not value:
        return "-"
    if len(value) <= 2:
        return "*" * len(value)
    return f"{value[0]}{'*' * (len(value) - 2)}{value[-1]}"


def label_for(mapping: dict[str, str], value: str | None, default: str = "-") -> str:
    if not value:
        return default
    return mapping.get(value, value)


def role_label(value: str | None) -> str:
    return label_for(ROLE_LABELS, value)


def role_description(value: str | None) -> str:
    return label_for(ROLE_DESCRIPTIONS, value, default="-")


def severity_label(value: str | None) -> str:
    return label_for(SEVERITY_LABELS, value)


def status_label(value: str | None) -> str:
    return label_for(STATUS_LABELS, value)


def poll_status_label(value: str | None) -> str:
    return label_for(STATUS_LABELS, value)


def poll_status_description(value: str | None, message: str | None = None) -> str:
    parts: list[str] = []
    if value:
        parts.append(POLL_STATUS_DESCRIPTIONS.get(value, value))
    if message:
        parts.append(f"最近说明：{message}")
    return " ".join(parts) if parts else "-"


def trap_name_label(value: str | None) -> str:
    return label_for(TRAP_NAME_LABELS, value, default="-")


def trap_type_label(value: str | None) -> str:
    return label_for(TRAP_TYPE_LABELS, value, default="-")


def device_name_label(device_name: str | None) -> str:
    return device_name or "未知设备"


def build_trap_summary(
    *,
    device_name: str | None,
    trap_name: str | None,
    trap_type: str | None,
    alarm_obj: str | None,
    alarm_id: str | None,
    severity: str | None,
    status: str | None,
    raw_summary: str | None,
) -> str:
    summary_parts: list[str] = []
    if alarm_id or alarm_obj:
        summary_parts.append(
            f"{trap_name_label(trap_name)}：设备 {device_name_label(device_name)}"
        )
        if alarm_obj:
            summary_parts.append(f"对象 {alarm_obj}")
        if alarm_id:
            summary_parts.append(f"告警 {alarm_id}")
        if severity:
            summary_parts.append(f"级别 {severity_label(severity)}")
        if status:
            summary_parts.append(f"状态 {status_label(status)}")
    elif trap_name or trap_type:
        summary_parts.append(f"{trap_name_label(trap_name) if trap_name else trap_type_label(trap_type)}：设备 {device_name_label(device_name)}")
    if summary_parts:
        return "，".join(summary_parts)
    return raw_summary or "-"


def generate_captcha_code(length: int = 4) -> str:
    alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
    return "".join(random.choice(alphabet) for _ in range(length))


def build_captcha_svg(code: str) -> str:
    noise_lines = []
    for idx in range(4):
        x1 = 10 + idx * 28
        x2 = 110 - idx * 18
        y1 = 14 + idx * 7
        y2 = 38 + idx * 5
        noise_lines.append(
            f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="#d7dee8" stroke-width="1.5" />'
        )
    letters = []
    for idx, char in enumerate(code):
        x = 16 + idx * 24
        rotate = (-10, -4, 6, 10)[idx % 4]
        letters.append(
            f'<text x="{x}" y="34" transform="rotate({rotate} {x} 34)" '
            'font-family="Segoe UI, Microsoft YaHei, sans-serif" font-size="24" '
            'font-weight="700" fill="#16354a">'
            f"{char}</text>"
        )
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" width="120" height="44" viewBox="0 0 120 44">'
        '<rect width="120" height="44" rx="10" fill="#f8fbfd" stroke="#d7dee8" />'
        + "".join(noise_lines)
        + "".join(letters)
        + "</svg>"
    )


def parse_local_datetime(value: str | None, *, end_of_day: bool = False) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=app_timezone())
    if end_of_day and parsed.hour == 0 and parsed.minute == 0 and parsed.second == 0:
        parsed = parsed + timedelta(days=1)
    return parsed.astimezone(timezone.utc)


def log_operation(
    session: Session,
    *,
    user_id: int | None,
    username_snapshot: str | None,
    action: str,
    target_type: str | None = None,
    target_id: str | None = None,
    details_json: dict[str, Any] | list[Any] | None = None,
) -> None:
    session.add(
        OperationLog(
            user_id=user_id,
            username_snapshot=username_snapshot,
            action=action,
            target_type=target_type,
            target_id=target_id,
            source_ip=request.headers.get("X-Forwarded-For", request.remote_addr),
            details_json=details_json,
        )
    )


def redis_client_from_app(app) -> RedisEventPublisher:
    return RedisEventPublisher(app.config["REDIS_URL"], app.config["REDIS_CHANNEL_PREFIX"])
