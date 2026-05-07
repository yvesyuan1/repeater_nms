from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


def mask_secret(value: str | None) -> str | None:
    if not value:
        return None
    if len(value) <= 2:
        return "*" * len(value)
    return f"{value[0]}{'*' * (len(value) - 2)}{value[-1]}"


@dataclass(slots=True)
class TrapVarBind:
    oid: str
    value: str | int

    def to_dict(self) -> dict[str, Any]:
        return {"oid": self.oid, "value": self.value}


@dataclass(slots=True)
class TrapPdu:
    source_ip: str
    source_port: int
    local_ip: str
    local_port: int
    snmp_version: str
    community: str | None
    sys_uptime: str | None
    trap_oid: str | None
    received_at: datetime
    varbinds: list[TrapVarBind]
    pdu_id: str

    def raw_json(self) -> dict[str, Any]:
        return {
            "pdu_id": self.pdu_id,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "local_ip": self.local_ip,
            "local_port": self.local_port,
            "snmp_version": self.snmp_version,
            "community_masked": mask_secret(self.community),
            "sys_uptime": self.sys_uptime,
            "snmp_trap_oid": self.trap_oid,
            "varbinds": [item.to_dict() for item in self.varbinds],
        }


@dataclass(slots=True)
class NormalizedTrapEvent:
    pdu_id: str
    trap_oid: str | None
    trap_name: str
    trap_type: str
    alarm_index: str | None = None
    alarm_obj: str | None = None
    alarm_id: str | None = None
    severity_code: int | None = None
    severity: str | None = None
    status_code: int | None = None
    status: str | None = None
    device_alarm_time_raw: str | None = None
    alarm_obj_desc: str | None = None
    is_active_alarm: bool = False
    should_popup: bool = False
    performance_index: str | None = None
    performance_desc: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def translated_json(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "pdu_id": self.pdu_id,
            "alarm_index": self.alarm_index,
            "alarm_obj": self.alarm_obj,
            "alarm_id": self.alarm_id,
            "severity_code": self.severity_code,
            "severity": self.severity,
            "status_code": self.status_code,
            "status": self.status,
            "device_alarm_time_raw": self.device_alarm_time_raw,
            "alarm_obj_desc": self.alarm_obj_desc,
            "is_active_alarm": self.is_active_alarm,
            "should_popup": self.should_popup,
            "trap_type": self.trap_type,
        }
        if self.performance_index is not None:
            payload["performance_index"] = self.performance_index
        if self.performance_desc is not None:
            payload["performance_desc"] = self.performance_desc
        payload.update(self.extra)
        return payload

    def raw_summary(self) -> str:
        if self.trap_type == "alarm":
            return (
                f"{self.trap_name} obj={self.alarm_obj or '-'} alarm={self.alarm_id or '-'} "
                f"severity={self.severity or '-'} status={self.status or '-'} pdu_id={self.pdu_id}"
            )
        if self.trap_type == "performance":
            return (
                f"{self.trap_name} idx={self.performance_index or '-'} "
                f"desc={self.performance_desc or '-'} pdu_id={self.pdu_id}"
            )
        return f"{self.trap_name} pdu_id={self.pdu_id}"


@dataclass(slots=True)
class ParsedTrapBundle:
    pdu: TrapPdu
    trap_oid: str | None
    trap_name: str
    trap_type: str
    parse_status: str
    events: list[NormalizedTrapEvent]
    parse_error: str | None = None


@dataclass(slots=True)
class PublishedTrapEvent:
    trap_event_id: int
    pdu_id: str | None
    received_at: str
    source_ip: str
    device_id: int | None
    device_name: str
    trap_type: str | None
    trap_name: str | None
    alarm_obj: str | None
    alarm_id: str | None
    severity: str | None
    status: str | None
    device_alarm_time_raw: str | None
    raw_summary: str | None
    translated_json: dict[str, Any] | list[Any] | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "trap_event_id": self.trap_event_id,
            "pdu_id": self.pdu_id,
            "received_at": self.received_at,
            "source_ip": self.source_ip,
            "device_id": self.device_id,
            "device_name": self.device_name,
            "trap_type": self.trap_type,
            "trap_name": self.trap_name,
            "alarm_obj": self.alarm_obj,
            "alarm_id": self.alarm_id,
            "severity": self.severity,
            "status": self.status,
            "device_alarm_time_raw": self.device_alarm_time_raw,
            "raw_summary": self.raw_summary,
            "translated_json": self.translated_json,
        }


@dataclass(slots=True)
class PollTarget:
    oid: str
    name: str
    scalar_suffix_zero: bool

    @property
    def request_oid(self) -> str:
        if self.scalar_suffix_zero and not self.oid.endswith(".0"):
            return f"{self.oid}.0"
        return self.oid


@dataclass(slots=True)
class PollResult:
    device_id: int
    device_name: str
    oid: str
    oid_name: str
    request_oid: str
    poll_status: str
    collected_at: datetime
    value_raw: str | None = None
    value_text: str | None = None
    value_num: float | None = None
    error_message: str | None = None

