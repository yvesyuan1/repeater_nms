from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.engine import make_url
from sqlalchemy import inspect

from repeater_nms.db.base import Base
from repeater_nms.db.models import ActiveAlarm, AlarmAckLog, AlarmEvent, AlarmRule, Device, DeviceLatestValue, MibEnum, MibNode, OperationLog, PopupNotification, SnmpMetricSample, TrapEvent, User
from repeater_nms.db.seeds import SeedStats, seed_everything
from repeater_nms.db.session import get_engine, session_scope


EXPECTED_TABLES = tuple(sorted(Base.metadata.tables))


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

    with session_scope(database_url) as session:
        seeded = seed_everything(session, admin_username, admin_password)

    return InitSummary(
        database_target=mask_database_url(database_url),
        existing_tables=existing_tables,
        created_tables=missing_tables,
        seeded=seeded,
    )
