from __future__ import annotations

from flask import current_app, g
from sqlalchemy.orm import Session

from repeater_nms.db.session import get_session_factory


def get_db_session() -> Session:
    if "db_session" not in g:
        factory = get_session_factory(current_app.config["DATABASE_URL"])
        g.db_session = factory()
    return g.db_session


def close_db_session(_error=None) -> None:
    session: Session | None = g.pop("db_session", None)
    if session is None:
        return
    session.close()
