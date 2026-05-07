from __future__ import annotations

import argparse
import os

from repeater_nms.config import Config
from repeater_nms.db.init_db import initialize_database


def main() -> int:
    parser = argparse.ArgumentParser(description="repeater-nms database utilities")
    parser.add_argument("command", choices=["init-db"])
    args = parser.parse_args()

    if args.command == "init-db":
        summary = initialize_database(
            Config.DATABASE_URL,
            admin_username=Config.ADMIN_USERNAME,
            admin_password=os.getenv("ADMIN_PASSWORD"),
        )
        print(f"database_target={summary.database_target}")
        print(f"existing_tables={len(summary.existing_tables)}")
        print(f"created_tables={len(summary.created_tables)}")
        for name, stats in summary.seeded.items():
            print(
                f"{name}: inserted={stats.inserted} updated={stats.updated} unchanged={stats.unchanged}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
