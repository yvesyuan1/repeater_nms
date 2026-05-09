from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine, inspect, select
from sqlalchemy.orm import Session

from repeater_nms.db.init_db import EXPECTED_TABLES, initialize_database
from repeater_nms.db.models import AlarmRule, MibEnum, MibNode, SnmpControlTemplate, User
from repeater_nms.db.seed_data import ALARM_RULE_SEEDS, MIB_ENUM_SEEDS, MIB_NODE_SEEDS, SNMP_CONTROL_SEEDS
from repeater_nms.db.session import reset_engine_cache


def test_initialize_database_creates_expected_tables_and_seeds(tmp_path: Path) -> None:
    database_path = tmp_path / "phase2.sqlite"
    database_url = f"sqlite:///{database_path.as_posix()}"

    reset_engine_cache()
    summary = initialize_database(
        database_url,
        admin_username="admin",
        admin_password="Phase2-Admin-Password",
    )

    assert set(summary.created_tables) == set(EXPECTED_TABLES)

    engine = create_engine(database_url)
    inspector = inspect(engine)
    assert set(inspector.get_table_names()) == set(EXPECTED_TABLES)

    with Session(engine) as session:
        assert session.scalar(select(User).where(User.username == "admin")) is not None
        assert session.query(MibNode).count() == len(MIB_NODE_SEEDS)
        assert session.query(MibEnum).count() == len(MIB_ENUM_SEEDS)
        assert session.query(SnmpControlTemplate).count() == len(SNMP_CONTROL_SEEDS)
        assert session.query(AlarmRule).count() == len(ALARM_RULE_SEEDS)


def test_initialize_database_is_idempotent(tmp_path: Path) -> None:
    database_path = tmp_path / "phase2-idempotent.sqlite"
    database_url = f"sqlite:///{database_path.as_posix()}"

    reset_engine_cache()
    initialize_database(
        database_url,
        admin_username="admin",
        admin_password="Phase2-Admin-Password",
    )
    summary = initialize_database(
        database_url,
        admin_username="admin",
        admin_password="Another-Password-Should-Not-Overwrite",
    )

    assert summary.created_tables == []
    assert summary.seeded["mib_nodes"].inserted == 0
    assert summary.seeded["mib_enums"].inserted == 0
    assert summary.seeded["alarm_rules"].inserted == 0
    assert summary.seeded["admin_user"].inserted == 0

    engine = create_engine(database_url)
    with Session(engine) as session:
        admin = session.scalar(select(User).where(User.username == "admin"))
        assert admin is not None
        assert admin.password_hash != "Another-Password-Should-Not-Overwrite"
