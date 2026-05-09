from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from repeater_nms.collector.snmp_client import SnmpV2cClient
from repeater_nms.db.models import Device, MibEnum, SnmpControlTemplate
from repeater_nms.web.utils import format_dt


@dataclass(slots=True)
class ControlReadResult:
    ok: bool
    payload: dict[str, Any]


def request_oid(oid: str) -> str:
    oid_text = (oid or "").strip()
    if not oid_text:
        return oid_text
    return oid_text if oid_text.endswith(".0") else f"{oid_text}.0"


def resolve_enum_options(session: Session, control: SnmpControlTemplate) -> list[dict[str, str]]:
    if isinstance(control.enum_map_json, dict) and control.enum_map_json:
        options: list[dict[str, str]] = []
        for code, meta in control.enum_map_json.items():
            if isinstance(meta, dict):
                label = str(meta.get("label") or meta.get("text") or code)
                description = str(meta.get("description") or label)
            else:
                label = str(meta)
                description = str(meta)
            options.append({"code": str(code), "label": label, "description": description})
        return sorted(options, key=lambda item: item["code"])

    if not control.enum_name:
        return []

    rows = session.execute(
        select(MibEnum)
        .where(MibEnum.profile_code == control.profile_code, MibEnum.enum_name == control.enum_name)
        .order_by(MibEnum.code.asc())
    ).scalars().all()
    return [
        {"code": str(item.code), "label": item.label, "description": item.description}
        for item in rows
    ]


def explain_value(raw_value: str | None, enum_options: list[dict[str, str]]) -> tuple[str | None, str | None]:
    if raw_value is None:
        return None, None
    for item in enum_options:
        if item["code"] == str(raw_value):
            return item["label"], item["description"]
    return None, None


def evaluate_normal_rule(normal_rule: str | None, *, raw_value: str | None, display_value: str | None, value_num: float | None) -> tuple[str, str]:
    if not normal_rule:
        return "unknown", "未配置正常判断规则"

    rule = normal_rule.strip()
    if ":" in rule:
        rule_type, raw_expected = rule.split(":", 1)
    else:
        rule_type, raw_expected = rule, ""
    expected_values = [item.strip() for item in raw_expected.split(",") if item.strip()]
    current_display = str(display_value or "").strip()
    current_raw = str(raw_value or "").strip()

    matched = False
    if rule_type == "enum_equals":
        matched = any(item in {current_raw, current_display} for item in expected_values)
    elif rule_type == "equals":
        matched = current_raw in expected_values or current_display in expected_values
    elif rule_type in {"number_gt", "number_gte", "number_lt", "number_lte", "number_between"}:
        numbers: list[float] = []
        for item in expected_values:
            try:
                numbers.append(float(item))
            except ValueError:
                continue
        if value_num is not None:
            if rule_type == "number_gt" and len(numbers) >= 1:
                matched = value_num > numbers[0]
            elif rule_type == "number_gte" and len(numbers) >= 1:
                matched = value_num >= numbers[0]
            elif rule_type == "number_lt" and len(numbers) >= 1:
                matched = value_num < numbers[0]
            elif rule_type == "number_lte" and len(numbers) >= 1:
                matched = value_num <= numbers[0]
            elif rule_type == "number_between" and len(numbers) >= 2:
                lower, upper = sorted(numbers[:2])
                matched = lower <= value_num <= upper

    if matched:
        return "normal", "命中正常判断规则"
    return "warning", f"当前值 {display_value or raw_value or '-'} 未命中规则 {normal_rule}"


def serialize_control_read(
    session: Session,
    control: SnmpControlTemplate,
    read_result: dict[str, Any],
) -> dict[str, Any]:
    read_at = datetime.now(timezone.utc)
    enum_options = resolve_enum_options(session, control)
    raw_value = None if not read_result.get("ok") else str(read_result.get("value_raw") or "")
    enum_label, enum_description = explain_value(raw_value, enum_options)
    display_value = enum_label or raw_value or "-"
    value_num = read_result.get("value_num")
    normal_status, normal_message = evaluate_normal_rule(
        control.normal_rule,
        raw_value=raw_value,
        display_value=display_value,
        value_num=None if value_num is None else float(value_num),
    )
    read_status = "ok" if read_result.get("ok") else "error"
    read_message = "读取成功" if read_result.get("ok") else str(read_result.get("error") or "SNMP 读取失败")
    return {
        "id": control.id,
        "oid_name": control.oid_name,
        "oid": control.oid,
        "request_oid": request_oid(control.oid),
        "oid_suffix": control.oid_suffix,
        "display_name": control.display_name,
        "description": control.description,
        "access": control.access,
        "data_type": control.data_type,
        "value_type": control.value_type,
        "unit": control.unit,
        "enum_name": control.enum_name,
        "enum_options": enum_options,
        "writable": bool(control.writable and control.access == "read-write"),
        "enabled": control.enabled,
        "sort_order": control.sort_order,
        "current_value_raw": raw_value,
        "current_value_display": display_value,
        "value_explained": enum_description or enum_label,
        "normal_status": normal_status if read_result.get("ok") else "error",
        "normal_message": normal_message if read_result.get("ok") else read_message,
        "last_read_at": read_at.isoformat(),
        "last_read_at_display": format_dt(read_at),
        "read_status": read_status,
        "read_message": read_message,
    }


def read_control(session: Session, client: SnmpV2cClient, device: Device, control: SnmpControlTemplate) -> ControlReadResult:
    result = client.get_oid_sync(
        device.ip,
        device.snmp_port,
        device.read_community,
        request_oid(control.oid),
    )
    return ControlReadResult(ok=bool(result.get("ok")), payload=serialize_control_read(session, control, result))


def validate_write_value(control: SnmpControlTemplate, value: Any, enum_options: list[dict[str, str]]) -> str:
    raw = "" if value is None else str(value).strip()
    if not raw:
        raise ValueError("目标值不能为空")

    if control.value_type == "switch":
        lowered = raw.lower()
        if lowered in {"1", "true", "enable", "enabled", "on"}:
            return "1"
        if lowered in {"0", "false", "disable", "disabled", "off"}:
            return "0"
        raise ValueError("开关值仅支持 0/1 或 enable/disable")

    if control.value_type == "enum":
        allowed_codes = {item["code"] for item in enum_options}
        if raw in allowed_codes:
            return raw
        for item in enum_options:
            if raw.lower() in {item["label"].lower(), item["description"].lower()}:
                return item["code"]
        raise ValueError("目标值不在模板允许的枚举范围内")

    if control.value_type == "number":
        number = int(raw)
        if control.data_type.lower() == "unsigned32" and number < 0:
            raise ValueError("Unsigned32 不允许负数")
        return str(number)

    if control.value_type == "ip":
        return str(ip_address(raw))

    return raw
