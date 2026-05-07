from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session
from werkzeug.security import generate_password_hash

from repeater_nms.db.models import AlarmRule, MibEnum, MibNode, User
from repeater_nms.db.seed_data import ALARM_RULE_SEEDS, MIB_ENUM_SEEDS, MIB_NODE_SEEDS


@dataclass
class SeedStats:
    inserted: int = 0
    updated: int = 0
    unchanged: int = 0


def _upsert_one(
    session: Session,
    model: type[Any],
    lookup: dict[str, Any],
    values: dict[str, Any],
    *,
    update_existing: bool = True,
) -> str:
    instance = session.execute(select(model).filter_by(**lookup)).scalar_one_or_none()
    if instance is None:
        session.add(model(**lookup, **values))
        return "inserted"

    changed = False
    if update_existing:
        for key, value in values.items():
            if getattr(instance, key) != value:
                setattr(instance, key, value)
                changed = True
    return "updated" if changed else "unchanged"


def _apply_stats(stats: SeedStats, result: str) -> None:
    if result == "inserted":
        stats.inserted += 1
    elif result == "updated":
        stats.updated += 1
    else:
        stats.unchanged += 1


def seed_mib_nodes(session: Session) -> SeedStats:
    stats = SeedStats()
    for item in MIB_NODE_SEEDS:
        lookup = {"oid": item["oid"]}
        values = {key: value for key, value in item.items() if key != "oid"}
        _apply_stats(stats, _upsert_one(session, MibNode, lookup, values))
    return stats


def seed_mib_enums(session: Session) -> SeedStats:
    stats = SeedStats()
    for enum_name, code, label, description in MIB_ENUM_SEEDS:
        lookup = {"enum_name": enum_name, "code": code}
        values = {"label": label, "description": description}
        _apply_stats(stats, _upsert_one(session, MibEnum, lookup, values))
    return stats


def seed_alarm_rules(session: Session) -> SeedStats:
    stats = SeedStats()
    for item in ALARM_RULE_SEEDS:
        lookup = {"alarm_id": item["alarm_id"]}
        values = {key: value for key, value in item.items() if key != "alarm_id"}
        _apply_stats(stats, _upsert_one(session, AlarmRule, lookup, values))
    return stats


def ensure_admin_user(session: Session, username: str, admin_password: str | None) -> SeedStats:
    stats = SeedStats()
    admin = session.execute(select(User).filter_by(username=username)).scalar_one_or_none()

    if admin is None:
        if not admin_password:
            raise RuntimeError("ADMIN_PASSWORD is required when creating the initial admin user.")
        session.add(
            User(
                username=username,
                password_hash=generate_password_hash(admin_password),
                role="admin",
                is_active=True,
            )
        )
        stats.inserted += 1
        return stats

    changed = False
    if admin.role != "admin":
        admin.role = "admin"
        changed = True
    if not admin.is_active:
        admin.is_active = True
        changed = True
    stats.updated += 1 if changed else 0
    stats.unchanged += 0 if changed else 1
    return stats


def seed_everything(session: Session, admin_username: str, admin_password: str | None) -> dict[str, SeedStats]:
    return {
        "mib_nodes": seed_mib_nodes(session),
        "mib_enums": seed_mib_enums(session),
        "alarm_rules": seed_alarm_rules(session),
        "admin_user": ensure_admin_user(session, admin_username, admin_password),
    }
