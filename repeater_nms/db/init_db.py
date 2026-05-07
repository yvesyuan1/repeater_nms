from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import inspect, text
from sqlalchemy.engine import make_url

from repeater_nms.db.base import Base
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
    SnmpMetricSample,
    TrapEvent,
    User,
)
from repeater_nms.db.seed_data import DEFAULT_PROFILE_CODE
from repeater_nms.db.seeds import SeedStats, seed_everything
from repeater_nms.db.session import get_engine, session_scope


EXPECTED_TABLES = tuple(sorted(Base.metadata.tables))

ADDITIVE_COLUMN_SPECS: dict[str, dict[str, str]] = {
    "repeater_devices": {
        "device_profile_code": f"VARCHAR(64) DEFAULT '{DEFAULT_PROFILE_CODE}'",
    },
    "repeater_mib_nodes": {
        "profile_code": f"VARCHAR(64) DEFAULT '{DEFAULT_PROFILE_CODE}'",
        "name_zh": "VARCHAR(128)",
        "category_zh": "VARCHAR(64)",
        "unit": "VARCHAR(32)",
        "overview_order": "INTEGER",
    },
    "repeater_mib_enums": {
        "profile_code": f"VARCHAR(64) DEFAULT '{DEFAULT_PROFILE_CODE}'",
    },
    "repeater_alarm_rules": {
        "profile_code": f"VARCHAR(64) DEFAULT '{DEFAULT_PROFILE_CODE}'",
    },
    "repeater_trap_events": {
        "profile_code": "VARCHAR(64)",
    },
    "repeater_snmp_metric_samples": {
        "profile_code": "VARCHAR(64)",
        "oid_name_zh": "VARCHAR(128)",
        "category": "VARCHAR(64)",
        "display_value": "TEXT",
        "enum_text": "VARCHAR(255)",
        "value_unit": "VARCHAR(32)",
        "health_status": "VARCHAR(32)",
        "health_text": "VARCHAR(64)",
        "health_reason": "TEXT",
    },
    "repeater_device_latest_values": {
        "profile_code": "VARCHAR(64)",
        "oid_name_zh": "VARCHAR(128)",
        "category": "VARCHAR(64)",
        "display_value": "TEXT",
        "enum_text": "VARCHAR(255)",
        "value_unit": "VARCHAR(32)",
        "health_status": "VARCHAR(32)",
        "health_text": "VARCHAR(64)",
        "health_reason": "TEXT",
        "last_success_at": "DATETIME",
        "last_failure_at": "DATETIME",
        "last_failure_message": "TEXT",
    },
}


@dataclass
class InitSummary:
    database_target: str
    existing_tables: list[str]
    created_tables: list[str]
    seeded: dict[str, SeedStats]


def mask_database_url(database_url: str) -> str:
    if database_url.startswith("sqlite"):
        return database_url
    return make_url(database_url).render_as_string(hide_password=True)


def _validate_database_target(database_url: str) -> None:
    if database_url.startswith("sqlite"):
        return

    database_name = make_url(database_url).database
    if database_name != "zjq_admin":
        raise RuntimeError(
            f"Refusing to initialize database '{database_name}'. Expected schema 'zjq_admin'."
        )


def _ensure_additive_columns(database_url: str) -> None:
    engine = get_engine(database_url)
    inspector = inspect(engine)
    with engine.begin() as conn:
        for table_name, columns in ADDITIVE_COLUMN_SPECS.items():
            existing = {item["name"] for item in inspector.get_columns(table_name)} if table_name in inspector.get_table_names() else set()
            for column_name, column_type in columns.items():
                if column_name in existing:
                    continue
                conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"))


def _backfill_profile_columns(database_url: str) -> None:
    engine = get_engine(database_url)
    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE repeater_devices "
                "SET device_profile_code = :profile "
                "WHERE device_profile_code IS NULL OR device_profile_code = ''"
            ),
            {"profile": DEFAULT_PROFILE_CODE},
        )
        for table_name in [
            "repeater_mib_nodes",
            "repeater_mib_enums",
            "repeater_alarm_rules",
        ]:
            conn.execute(
                text(
                    f"UPDATE {table_name} "
                    "SET profile_code = :profile "
                    "WHERE profile_code IS NULL OR profile_code = ''"
                ),
                {"profile": DEFAULT_PROFILE_CODE},
            )


def initialize_database(
    database_url: str,
    *,
    admin_username: str = "admin",
    admin_password: str | None = None,
) -> InitSummary:
    _validate_database_target(database_url)
    engine = get_engine(database_url)
    inspector = inspect(engine)
    existing_tables = sorted(table for table in inspector.get_table_names() if table.startswith("repeater_"))
    missing_tables = sorted(set(EXPECTED_TABLES) - set(existing_tables))

    if missing_tables:
        Base.metadata.create_all(
            engine,
            tables=[Base.metadata.tables[name] for name in missing_tables],
            checkfirst=True,
        )

    _ensure_additive_columns(database_url)
    _backfill_profile_columns(database_url)

    with session_scope(database_url) as session:
        seeded = seed_everything(session, admin_username, admin_password)

    return InitSummary(
        database_target=mask_database_url(database_url),
        existing_tables=existing_tables,
        created_tables=missing_tables,
        seeded=seeded,
    )
