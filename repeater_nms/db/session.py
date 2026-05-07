from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker


_ENGINE_CACHE: dict[str, Engine] = {}
_SESSIONMAKER_CACHE: dict[str, sessionmaker[Session]] = {}


def get_engine(database_url: str) -> Engine:
    engine = _ENGINE_CACHE.get(database_url)
    if engine is None:
        engine = create_engine(
            database_url,
            future=True,
            pool_pre_ping=not database_url.startswith("sqlite"),
        )
        _ENGINE_CACHE[database_url] = engine
    return engine


def get_session_factory(database_url: str) -> sessionmaker[Session]:
    factory = _SESSIONMAKER_CACHE.get(database_url)
    if factory is None:
        factory = sessionmaker(bind=get_engine(database_url), expire_on_commit=False, future=True)
        _SESSIONMAKER_CACHE[database_url] = factory
    return factory


@contextmanager
def session_scope(database_url: str) -> Iterator[Session]:
    session = get_session_factory(database_url)()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def reset_engine_cache() -> None:
    for engine in _ENGINE_CACHE.values():
        engine.dispose()
    _ENGINE_CACHE.clear()
    _SESSIONMAKER_CACHE.clear()
