from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from repeater_nms.collector.constants import (
    ALMCHG_FIELDS,
    ALMCHG_TABLE_PREFIX,
    ALMCHG_TRAP_OID,
    PERFORMANCE_FIELDS,
    PERFORMANCE_TABLE_PREFIX,
    PERFORMANCE_TRAP_OID,
)
from repeater_nms.collector.schemas import PollTarget
from repeater_nms.db.seed_data import (
    ALARM_RULE_SEEDS,
    DEFAULT_PROFILE_CODE,
    MIB_ENUM_SEEDS,
    MIB_NODE_SEEDS,
    POLLING_STRATEGY_SEEDS,
)


@dataclass(frozen=True, slots=True)
class OidMatch:
    field_name: str
    suffix: str


class MibResolver:
    def __init__(self, profile_code: str = DEFAULT_PROFILE_CODE) -> None:
        self.profile_code = profile_code or DEFAULT_PROFILE_CODE
        self.nodes_by_oid = {
            item["oid"]: item
            for item in MIB_NODE_SEEDS
            if item.get("profile_code", DEFAULT_PROFILE_CODE) == self.profile_code
        }
        self.nodes_by_name = {
            item["name"]: item
            for item in MIB_NODE_SEEDS
            if item.get("profile_code", DEFAULT_PROFILE_CODE) == self.profile_code
        }
        self.enums_by_name: dict[str, dict[int, dict[str, str]]] = {}
        for seed_profile, enum_name, code, label, description in MIB_ENUM_SEEDS:
            if seed_profile != self.profile_code:
                continue
            self.enums_by_name.setdefault(enum_name, {})[int(code)] = {
                "label": label,
                "description": description,
            }
        self.alarm_rules = {
            (item["profile_code"], item["alarm_id"]): item
            for item in ALARM_RULE_SEEDS
            if item["profile_code"] == self.profile_code
        }
        self.trap_names = {
            ALMCHG_TRAP_OID: "almchg",
            PERFORMANCE_TRAP_OID: "performance",
        }
        self.polling_strategies = [
            item for item in POLLING_STRATEGY_SEEDS if item["profile_code"] == self.profile_code and item["is_enabled"]
        ]

    def trap_name(self, trap_oid: str | None) -> str:
        if not trap_oid:
            return "unknown"
        return self.trap_names.get(trap_oid, self.nodes_by_oid.get(trap_oid, {}).get("name", "unknown"))

    def translate_enum(self, enum_name: str | None, code: int | None) -> str | None:
        if not enum_name or code is None:
            return None
        entry = self.enums_by_name.get(enum_name, {}).get(int(code))
        return None if entry is None else entry["label"]

    def enum_description(self, enum_name: str | None, code: int | None) -> str | None:
        if not enum_name or code is None:
            return None
        entry = self.enums_by_name.get(enum_name, {}).get(int(code))
        return None if entry is None else entry["description"]

    def alarm_rule(self, alarm_id: str | None) -> dict | None:
        if not alarm_id:
            return None
        return self.alarm_rules.get((self.profile_code, alarm_id))

    def node_by_name(self, node_name: str | None) -> dict[str, Any] | None:
        if not node_name:
            return None
        return self.nodes_by_name.get(node_name)

    def node_by_oid(self, oid: str | None) -> dict[str, Any] | None:
        if not oid:
            return None
        return self.nodes_by_oid.get(oid.rstrip(".0")) or self.nodes_by_oid.get(oid)

    def strategy_by_node_name(self, node_name: str | None) -> dict[str, Any] | None:
        if not node_name:
            return None
        for item in self.polling_strategies:
            if item["node_name"] == node_name:
                return item
        return None

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
        targets: list[PollTarget] = []
        for item in sorted(self.polling_strategies, key=lambda row: row.get("display_order", 100)):
            node = self.nodes_by_name.get(item["node_name"])
            if not node:
                continue
            targets.append(
                PollTarget(
                    oid=item["oid"],
                    name=item["node_name"],
                    scalar_suffix_zero=bool(node.get("scalar_suffix_zero")),
                )
            )
        return targets
