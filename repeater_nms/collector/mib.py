from __future__ import annotations

from dataclasses import dataclass

from repeater_nms.collector.constants import ALMCHG_TABLE_PREFIX, ALMCHG_TRAP_OID, ALMCHG_FIELDS, PERFORMANCE_FIELDS, PERFORMANCE_TABLE_PREFIX, PERFORMANCE_TRAP_OID
from repeater_nms.collector.schemas import PollTarget
from repeater_nms.db.seed_data import ALARM_RULE_SEEDS, MIB_ENUM_SEEDS, MIB_NODE_SEEDS


@dataclass(frozen=True, slots=True)
class OidMatch:
    field_name: str
    suffix: str


class MibResolver:
    def __init__(self) -> None:
        self.nodes_by_oid = {item["oid"]: item for item in MIB_NODE_SEEDS}
        self.enums_by_name = {}
        for enum_name, code, label, description in MIB_ENUM_SEEDS:
            self.enums_by_name.setdefault(enum_name, {})[int(code)] = {
                "label": label,
                "description": description,
            }
        self.alarm_rules = {item["alarm_id"]: item for item in ALARM_RULE_SEEDS}
        self.trap_names = {
            ALMCHG_TRAP_OID: "almchg",
            PERFORMANCE_TRAP_OID: "performance",
        }

    def trap_name(self, trap_oid: str | None) -> str:
        if not trap_oid:
            return "unknown"
        return self.trap_names.get(trap_oid, self.nodes_by_oid.get(trap_oid, {}).get("name", "unknown"))

    def translate_enum(self, enum_name: str, code: int | None) -> str | None:
        if code is None:
            return None
        entry = self.enums_by_name.get(enum_name, {}).get(int(code))
        return None if entry is None else entry["label"]

    def alarm_rule(self, alarm_id: str | None) -> dict | None:
        if not alarm_id:
            return None
        return self.alarm_rules.get(alarm_id)

    def match_alarm_field(self, oid: str) -> OidMatch | None:
        prefix = f"{ALMCHG_TABLE_PREFIX}."
        if not oid.startswith(prefix):
            return None
        tail = oid[len(prefix):].lstrip(".")
        field_number, _, suffix = tail.partition(".")
        field_name = ALMCHG_FIELDS.get(field_number)
        if not field_name or not suffix:
            return None
        return OidMatch(field_name=field_name, suffix=suffix)

    def match_performance_field(self, oid: str) -> OidMatch | None:
        prefix = f"{PERFORMANCE_TABLE_PREFIX}."
        if not oid.startswith(prefix):
            return None
        tail = oid[len(prefix):].lstrip(".")
        field_number, _, suffix = tail.partition(".")
        field_name = PERFORMANCE_FIELDS.get(field_number)
        if not field_name or not suffix:
            return None
        return OidMatch(field_name=field_name, suffix=suffix)

    def poll_targets(self) -> list[PollTarget]:
        targets = []
        for item in MIB_NODE_SEEDS:
            if item.get("is_pollable"):
                targets.append(
                    PollTarget(
                        oid=item["oid"],
                        name=item["name"],
                        scalar_suffix_zero=bool(item.get("scalar_suffix_zero")),
                    )
                )
        return targets

