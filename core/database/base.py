import asyncio
from datetime import datetime
from pathlib import Path

from sqlalchemy import DateTime, func
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from core.config import settings

PROJECT_ROOT = Path(__file__).resolve().parents[2]

engine = create_async_engine(settings.postgres_url, echo=False, pool_pre_ping=True)
AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


def alembic_config(url: str | None = None):
    """Alembic config rooted at the project, independent of the current directory."""
    from alembic.config import Config

    cfg = Config(str(PROJECT_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(PROJECT_ROOT / "alembic"))
    if url:
        cfg.attributes["sqlalchemy_url"] = url
    cfg.attributes["skip_logging_config"] = True
    return cfg


def _upgrade_head() -> None:
    from alembic import command
    command.upgrade(alembic_config(), "head")


async def init_db() -> None:
    """
    Bring the schema to the latest Alembic revision.

    Alembic is the single source of truth for the schema. `Base.metadata.create_all`
    used to run here too, and whichever of the two ran first produced a schema the
    other one then refused (enum labels, "table already exists").

    alembic/env.py drives its own event loop with asyncio.run(), so the upgrade runs
    on a worker thread rather than inside the server's loop.
    """
    if not settings.enable_persistence or not settings.run_migrations_on_startup:
        return
    await asyncio.to_thread(_upgrade_head)
