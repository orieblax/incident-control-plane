"""SQLAlchemy 2.0 ORM mappings for Supabase PostgreSQL + pgvector."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pgvector.sqlalchemy import Vector
from sqlalchemy import Boolean, DateTime, ForeignKey, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Declarative base for control-plane ORM tables."""


class IncidentORM(Base):
    """ORM model for public.incidents."""

    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="triggered")
    severity: Mapped[str] = mapped_column(Text, nullable=False)
    service_name: Mapped[str] = mapped_column(Text, nullable=False)
    telemetry: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    owner_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class RunbookORM(Base):
    """ORM model for public.runbooks."""

    __tablename__ = "runbooks"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    slug: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    service_name: Mapped[str] = mapped_column(Text, nullable=False)
    symptom_summary: Mapped[str] = mapped_column(Text, nullable=False)
    steps: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    embedding: Mapped[list[float] | None] = mapped_column(Vector(1536), nullable=True)
    is_shared: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    owner_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class PostmortemORM(Base):
    """ORM model for public.postmortems."""

    __tablename__ = "postmortems"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True
    )
    title: Mapped[str] = mapped_column(Text, nullable=False)
    service_name: Mapped[str] = mapped_column(Text, nullable=False)
    root_cause: Mapped[str] = mapped_column(Text, nullable=False)
    resolution_summary: Mapped[str] = mapped_column(Text, nullable=False)
    action_items: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    embedding: Mapped[list[float] | None] = mapped_column(Vector(1536), nullable=True)
    is_shared: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    owner_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    published_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class IncidentEventORM(Base):
    """ORM model for public.incident_events (append-only)."""

    __tablename__ = "incident_events"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    from_status: Mapped[str | None] = mapped_column(Text, nullable=True)
    to_status: Mapped[str | None] = mapped_column(Text, nullable=True)
    actor_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    actor_type: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
