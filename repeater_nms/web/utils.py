from __future__ import annotations

import random
import re
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

HEALTH_LABELS = {
    "normal": "正常",
    "warning": "告警",
    "major": "主要告警",
    "critical": "严重告警",
    "error": "采集失败",
    "unknown": "未知",
}

OVERVIEW_STATUS_LABELS = {
    "normal": "正常",
    "warning": "告警",
    "major": "主要告警",
    "critical": "严重告警",
    "poll_error": "采集失败",
    "unknown": "未知",
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

ALARM_ID_LABELS = {
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

TREND_ALARM_METRIC_LABELS = {
    "LB": "激光器偏置电流",
    "LT": "激光器温度",
    "IOP": "激光器输入光功率",
    "OOP": "激光器输出光功率",
    "RAM": "内存利用率",
    "CPU": "CPU利用率",
}

TREND_ALARM_WINDOW_LABELS = {
    "15": "15分钟",
    "24": "24小时",
}

TREND_ALARM_LEVEL_LABELS = {
    "L": "低于阈值",
    "H": "高于阈值",
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
        return value.strftime("%Y-%m-%d %H:%M:%S")
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


def health_label(value: str | None) -> str:
    return label_for(HEALTH_LABELS, value, default="未知")


def overview_status_label(value: str | None) -> str:
    return label_for(OVERVIEW_STATUS_LABELS, value, default="未知")


def device_name_label(device_name: str | None) -> str:
    return device_name or "未知设备"


def profile_title(vendor: str | None, model: str | None) -> str:
    if vendor and model:
        return f"{vendor} {model}"
    return vendor or model or "-"


def alarm_description_label(alarm_id: str | None) -> str:
    if not alarm_id:
        return "-"
    if alarm_id in ALARM_ID_LABELS:
        return ALARM_ID_LABELS[alarm_id]
    match = re.fullmatch(r"(LB|LT|IOP|OOP|RAM|CPU)_(15|24)(L|H)", alarm_id)
    if not match:
        return alarm_id
    metric_code, window_code, level_code = match.groups()
    metric_text = TREND_ALARM_METRIC_LABELS.get(metric_code, metric_code)
    window_text = TREND_ALARM_WINDOW_LABELS.get(window_code, window_code)
    level_text = TREND_ALARM_LEVEL_LABELS.get(level_code, level_code)
    return f"{window_text}{metric_text}{level_text}"


def highest_severity(values: list[str]) -> str | None:
    order = {"critical": 5, "major": 4, "warning": 3, "minor": 2, "indeterminate": 1, "cleared": 0}
    ranked = sorted((value for value in values if value), key=lambda item: order.get(item, -1), reverse=True)
    return ranked[0] if ranked else None


def compute_device_overview_status(
    *,
    last_poll_status: str | None,
    highest_alarm_severity: str | None,
    health_statuses: list[str],
) -> str:
    if highest_alarm_severity in {"critical", "major"}:
        return highest_alarm_severity
    if last_poll_status == "error":
        return "poll_error"
    if highest_alarm_severity in {"warning", "minor"}:
        return "warning"
    if any(item == "critical" for item in health_statuses):
        return "critical"
    if any(item == "major" for item in health_statuses):
        return "major"
    if any(item == "warning" for item in health_statuses):
        return "warning"
    if last_poll_status == "ok" and any(item == "normal" for item in health_statuses):
        return "normal"
    return "unknown"


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
    alarm_description: str | None = None,
) -> str:
    summary_parts: list[str] = []
    if alarm_id or alarm_obj:
        summary_parts.append(f"{trap_name_label(trap_name)}：设备 {device_name_label(device_name)}")
        if alarm_obj:
            summary_parts.append(f"对象 {alarm_obj}")
        if alarm_id:
            summary_parts.append(f"告警 {alarm_id}")
            alarm_desc = alarm_description or alarm_description_label(alarm_id)
            if alarm_desc and alarm_desc != alarm_id:
                summary_parts.append(f"说明 {alarm_desc}")
        if severity:
            summary_parts.append(f"级别 {severity_label(severity)}")
        if status:
            summary_parts.append(f"状态 {status_label(status)}")
    elif trap_name or trap_type:
        summary_parts.append(
            f"{trap_name_label(trap_name) if trap_name else trap_type_label(trap_type)}：设备 {device_name_label(device_name)}"
        )
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
