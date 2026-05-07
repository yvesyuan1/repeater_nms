from __future__ import annotations

import os

import click
from flask import Flask

from repeater_nms.db.init_db import initialize_database


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
