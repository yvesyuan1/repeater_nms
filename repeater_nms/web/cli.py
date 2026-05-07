from __future__ import annotations

import os

import click
from flask import Flask

from repeater_nms.db.demo_data import seed_local_demo_data
from repeater_nms.db.init_db import initialize_database
from repeater_nms.db.session import session_scope


def register_cli(app: Flask) -> None:
    @app.cli.command("init-db")
    def init_db_command() -> None:
        """Create repeater_ tables and seed baseline data."""

        summary = initialize_database(
            app.config["DATABASE_URL"],
            admin_username=app.config["ADMIN_USERNAME"],
            admin_password=os.getenv("ADMIN_PASSWORD"),
        )
        click.echo(f"database_target={summary.database_target}")
        click.echo(f"existing_tables={len(summary.existing_tables)}")
        click.echo(f"created_tables={len(summary.created_tables)}")
        for name, stats in summary.seeded.items():
            click.echo(
                f"{name}: inserted={stats.inserted} updated={stats.updated} unchanged={stats.unchanged}"
            )

    @app.cli.command("seed-local-demo")
    def seed_local_demo_command() -> None:
        """Seed one local demo device and sample trap/alarm rows."""

        with session_scope(app.config["DATABASE_URL"]) as session:
            summary = seed_local_demo_data(session)
        click.echo(
            "demo_seed "
            f"device_created={summary.device_created} "
            f"trap_created={summary.trap_created} "
            f"active_alarm_created={summary.active_alarm_created} "
            f"popup_created={summary.popup_created}"
        )
