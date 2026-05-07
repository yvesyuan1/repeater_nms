from __future__ import annotations

import ast
import hashlib
import shlex
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from repeater_nms.collector.constants import ACTIVE_ALARM_SEVERITIES, ACTIVE_ALARM_STATUSES, ALMCHG_TRAP_OID, PERFORMANCE_TRAP_OID, POPUP_SEVERITIES, POPUP_STATUSES, SNMP_TRAP_OID_FIELD, SYS_UPTIME_OID
from repeater_nms.collector.mib import MibResolver
from repeater_nms.collector.schemas import NormalizedTrapEvent, ParsedTrapBundle, TrapPdu, TrapVarBind


def _parse_scalar(value: str) -> str | int:
    stripped = value.strip()
    if stripped.startswith('"') and stripped.endswith('"'):
        return ast.literal_eval(stripped)
    if stripped.isdigit():
        return int(stripped)
    return stripped


def build_pdu_id(meta: dict[str, str], varbinds: list[TrapVarBind]) -> str:
    if pdu_id := meta.get("pdu_id"):
        return pdu_id
    basis = "|".join(
        [
            meta.get("source_ip", ""),
            meta.get("source_port", ""),
            meta.get("trap_oid", ""),
            meta.get("sys_uptime", ""),
            *(f"{item.oid}={item.value}" for item in varbinds),
        ]
    )
    digest = hashlib.sha1(basis.encode("utf-8")).hexdigest()
    return digest[:16]


def load_fixture_pdus(path: str | Path) -> list[TrapPdu]:
    return parse_fixture_text(Path(path).read_text(encoding="utf-8"))


def parse_fixture_text(text: str) -> list[TrapPdu]:
    pdus: list[TrapPdu] = []
    meta: dict[str, str] | None = None
    varbinds: list[TrapVarBind] = []

    def finalize() -> None:
        nonlocal meta, varbinds
        if meta is None:
            return
        trap_oid = meta.get("trap_oid")
        sys_uptime = meta.get("sys_uptime")
        for item in varbinds:
            if item.oid == SNMP_TRAP_OID_FIELD and trap_oid is None:
                trap_oid = str(item.value)
            elif item.oid == SYS_UPTIME_OID and sys_uptime is None:
                sys_uptime = str(item.value)
        received_at = datetime.fromisoformat(meta["received_at"]) if "received_at" in meta else datetime.now(timezone.utc)
        pdu = TrapPdu(
            pdu_id=build_pdu_id(meta, varbinds),
            source_ip=meta["source_ip"],
            source_port=int(meta.get("source_port", "162")),
            local_ip=meta.get("local_ip", "0.0.0.0"),
            local_port=int(meta.get("local_port", "1162")),
            snmp_version=meta.get("snmp_version", "v2c"),
            community=meta.get("community"),
            sys_uptime=sys_uptime,
            trap_oid=trap_oid,
            received_at=received_at,
            varbinds=list(varbinds),
        )
        pdus.append(pdu)
        meta = None
        varbinds = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("PDU "):
            finalize()
            meta = {}
            for token in shlex.split(line[4:]):
                key, value = token.split("=", 1)
                meta[key] = value
            continue
        if line == "END":
            finalize()
            continue
        if meta is None:
            raise ValueError(f"Unexpected fixture line outside PDU block: {line}")
        oid, raw_value = line.split("=", 1)
        varbinds.append(TrapVarBind(oid=oid.strip(), value=_parse_scalar(raw_value)))

    finalize()
    return pdus


class TrapParser:
    def __init__(self, resolver: MibResolver | None = None) -> None:
        self.resolver = resolver or MibResolver()

    def parse_pdu(self, pdu: TrapPdu) -> ParsedTrapBundle:
        trap_oid = pdu.trap_oid or self._find_special_varbind(pdu, SNMP_TRAP_OID_FIELD)
        trap_name = self.resolver.trap_name(trap_oid)

        if trap_oid == ALMCHG_TRAP_OID:
            return self._parse_alarm_bundle(pdu, trap_oid, trap_name)
        if trap_oid == PERFORMANCE_TRAP_OID:
            return self._parse_performance_bundle(pdu, trap_oid, trap_name)

        event = NormalizedTrapEvent(
            pdu_id=pdu.pdu_id,
            trap_oid=trap_oid,
            trap_name=trap_name,
            trap_type="generic",
        )
        return ParsedTrapBundle(
            pdu=pdu,
            trap_oid=trap_oid,
            trap_name=trap_name,
            trap_type="generic",
            parse_status="parsed",
            events=[event],
        )

    def _parse_alarm_bundle(self, pdu: TrapPdu, trap_oid: str | None, trap_name: str) -> ParsedTrapBundle:
        grouped: dict[str, dict[str, Any]] = defaultdict(dict)
        for item in pdu.varbinds:
            match = self.resolver.match_alarm_field(item.oid)
            if not match:
                continue
            grouped[match.suffix][match.field_name] = item.value

        if not grouped:
            return ParsedTrapBundle(
                pdu=pdu,
                trap_oid=trap_oid,
                trap_name=trap_name,
                trap_type="alarm",
                parse_status="failed",
                parse_error="almchg trap does not contain parsable alarm varbind groups",
                events=[],
            )

        events: list[NormalizedTrapEvent] = []
        for alarm_index in sorted(grouped):
            fields = grouped[alarm_index]
            severity_code = self._to_int(fields.get("severity_code"))
            status_code = self._to_int(fields.get("status_code"))
            severity = self.resolver.translate_enum("EALARMLVL", severity_code)
            status = self.resolver.translate_enum("EALARMSTAT", status_code)
            alarm_id = self._to_text(fields.get("alarm_id"))
            is_active_alarm = (
                bool(severity in ACTIVE_ALARM_SEVERITIES)
                and bool(status in ACTIVE_ALARM_STATUSES)
            )
            should_popup = (
                bool(severity in POPUP_SEVERITIES)
                and bool(status in POPUP_STATUSES)
            )
            event = NormalizedTrapEvent(
                pdu_id=pdu.pdu_id,
                trap_oid=trap_oid,
                trap_name=trap_name,
                trap_type="alarm",
                alarm_index=alarm_index,
                alarm_obj=self._to_text(fields.get("alarm_obj")),
                alarm_id=alarm_id,
                severity_code=severity_code,
                severity=severity,
                status_code=status_code,
                status=status,
                device_alarm_time_raw=self._to_text(fields.get("device_alarm_time_raw")),
                alarm_obj_desc=self._to_text(fields.get("alarm_obj_desc")),
                is_active_alarm=is_active_alarm,
                should_popup=should_popup,
                extra={
                    "rule_severity": (self.resolver.alarm_rule(alarm_id) or {}).get("default_severity"),
                },
            )
            events.append(event)

        return ParsedTrapBundle(
            pdu=pdu,
            trap_oid=trap_oid,
            trap_name=trap_name,
            trap_type="alarm",
            parse_status="parsed",
            events=events,
        )

    def _parse_performance_bundle(self, pdu: TrapPdu, trap_oid: str | None, trap_name: str) -> ParsedTrapBundle:
        grouped: dict[str, dict[str, Any]] = defaultdict(dict)
        for item in pdu.varbinds:
            match = self.resolver.match_performance_field(item.oid)
            if not match:
                continue
            grouped[match.suffix][match.field_name] = item.value

        if not grouped:
            return ParsedTrapBundle(
                pdu=pdu,
                trap_oid=trap_oid,
                trap_name=trap_name,
                trap_type="performance",
                parse_status="failed",
                parse_error="performance trap does not contain parsable performance varbind groups",
                events=[],
            )

        events = [
            NormalizedTrapEvent(
                pdu_id=pdu.pdu_id,
                trap_oid=trap_oid,
                trap_name=trap_name,
                trap_type="performance",
                performance_index=self._to_text(fields.get("performance_index")),
                performance_desc=self._to_text(fields.get("performance_desc")),
            )
            for _, fields in sorted(grouped.items())
        ]

        return ParsedTrapBundle(
            pdu=pdu,
            trap_oid=trap_oid,
            trap_name=trap_name,
            trap_type="performance",
            parse_status="parsed",
            events=events,
        )

    @staticmethod
    def _find_special_varbind(pdu: TrapPdu, oid: str) -> str | None:
        for item in pdu.varbinds:
            if item.oid == oid:
                return str(item.value)
        return None

    @staticmethod
    def _to_int(value: Any) -> int | None:
        if value is None:
            return None
        if isinstance(value, int):
            return value
        text = str(value).strip()
        return int(text) if text.isdigit() else None

    @staticmethod
    def _to_text(value: Any) -> str | None:
        if value is None:
            return None
        return str(value)

