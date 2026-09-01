"""SQLAlchemy engine and session management."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache
from typing import Any

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from zentra.config import get_settings


@lru_cache(maxsize=8)
def engine_for(url: str) -> Engine:
    settings = get_settings()
    kwargs: dict[str, Any] = {
        "pool_pre_ping": True,
        "future": True,
        "echo": False,
    }
    if not url.startswith("sqlite"):
        kwargs["pool_size"] = settings.db_pool_size
        kwargs["max_overflow"] = settings.db_max_overflow
        kwargs["connect_args"] = {
            "application_name": settings.service_name,
            "connect_timeout": 10,
        }
    return create_engine(url, **kwargs)


def get_engine() -> Engine:
    return engine_for(get_settings().effective_database_url)


@lru_cache(maxsize=8)
def _session_factory(url: str) -> sessionmaker[Session]:
    return sessionmaker(bind=engine_for(url), expire_on_commit=False, autoflush=False)


def SessionLocal() -> Session:  # noqa: N802 - factory reads as a class
    return _session_factory(get_settings().effective_database_url)()


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional scope for worker/service code."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def db_dependency() -> Iterator[Session]:
    """FastAPI dependency; commits on success, rolls back on error."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def ping(url: str | None = None, timeout_seconds: int = 3) -> bool:
    """Cheap readiness probe. Returns False instead of raising."""
    try:
        eng = engine_for(url or get_settings().effective_database_url)
        with eng.connect() as conn:
            conn.execute(text("select 1"))
        return True
    except Exception:  # noqa: BLE001 - readiness must never raise
        return False


__all__ = [
    "SessionLocal",
    "db_dependency",
    "engine_for",
    "get_engine",
    "ping",
    "session_scope",
]
