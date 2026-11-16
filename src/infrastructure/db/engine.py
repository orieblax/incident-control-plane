"""Async SQLAlchemy engine tuned for Supavisor transaction pooling."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from src.domain.models import AuthPrincipal
from src.infrastructure.config import Settings


class DatabaseNotConfiguredError(RuntimeError):
    """Raised when database operations are requested without DATABASE_URL."""


def build_async_engine(settings: Settings) -> AsyncEngine | None:
    """Build an async SQLAlchemy engine configured for Supavisor transaction mode."""
    clean_url, connect_args = settings.parsed_asyncpg_target()
    if not clean_url:
        return None
    return create_async_engine(
        clean_url,
        poolclass=NullPool,
        connect_args=connect_args,
        pool_pre_ping=False,
    )


class DatabaseManager:
    """Lazy async SQLAlchemy engine & RLS-scoped session manager."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._engine: AsyncEngine | None = build_async_engine(settings)
        self._session_factory: async_sessionmaker[AsyncSession] | None = (
            async_sessionmaker(
                self._engine,
                class_=AsyncSession,
                expire_on_commit=False,
                autoflush=False,
            )
            if self._engine is not None
            else None
        )

    @property
    def engine(self) -> AsyncEngine | None:
        """Expose underlying SQLAlchemy engine (used for health checks & assertions)."""
        return self._engine

    @property
    def is_configured(self) -> bool:
        """Return True if an async engine is initialized."""
        return self._engine is not None and self._session_factory is not None

    async def check_health(self) -> None:
        """Verify live PostgreSQL / Supavisor connectivity."""
        if self._engine is None:
            raise DatabaseNotConfiguredError("DATABASE_URL is not configured.")
        async with self._engine.connect() as conn:
            await conn.execute(text("SELECT 1"))

    @asynccontextmanager
    async def session_scope(
        self,
        principal: AuthPrincipal | None = None,
    ) -> AsyncIterator[AsyncSession]:
        """Yield a transaction-scoped AsyncSession with local Supabase RLS claims."""
        if self._session_factory is None:
            raise DatabaseNotConfiguredError("DATABASE_URL is not configured.")

        async with self._session_factory() as session:
            async with session.begin():
                if principal is not None and self._settings.db_enforce_rls_context:
                    claims_json = json.dumps(principal.to_claims_dict())
                    await session.execute(text("SET LOCAL ROLE authenticated"))
                    await session.execute(
                        text(
                            "SELECT "
                            "set_config('request.jwt.claims', :claims, true), "
                            "set_config('request.jwt.claim.sub', :sub, true)"
                        ),
                        {"claims": claims_json, "sub": str(principal.user_id)},
                    )
                yield session

    async def dispose(self) -> None:
        """Dispose engine connections on application shutdown."""
        if self._engine is not None:
            await self._engine.dispose()
