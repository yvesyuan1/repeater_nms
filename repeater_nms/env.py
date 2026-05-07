from __future__ import annotations

from dotenv import load_dotenv


def load_environment() -> None:
    load_dotenv(override=False)
