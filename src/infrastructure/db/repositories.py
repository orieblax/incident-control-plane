"""Async SQLAlchemy repository implementations and Unit of Work."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import asdict
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.domain.models import (
    ActorType,
    AuthPrincipal,
    Incident,
    IncidentEvent,
    IncidentSeverity,
    IncidentStatus,
    Postmortem,
    Runbook,
    RunbookStep,
    SimilarPostmortemMatch,
    SimilarRunbookMatch,
    StepRiskLevel,
)
from src.domain.ports import ControlPlaneUnitOfWork
from src.infrastructure.db.engine import DatabaseManager
from src.infrastructure.db.orm import (
    IncidentEventORM,
    IncidentORM,
    PostmortemORM,
    RunbookORM,
)


def _to_incident(row: IncidentORM) -> Incident:
    return Incident(
        id=row.id,
        title=row.title,
        description=row.description,
        status=IncidentStatus(row.status),
        severity=IncidentSeverity(row.severity),
        service_name=row.service_name,
        telemetry=dict(row.telemetry or {}),
        owner_id=row.owner_id,
        created_at=row.created_at,
        updated_at=row.updated_at,
        resolved_at=row.resolved_at,
    )


def _to_runbook(row: RunbookORM) -> Runbook:
    steps = [
        RunbookStep(
            step_number=int(item["step_number"]),
            title=str(item["title"]),
            instruction=str(item["instruction"]),
            command_template=item.get("command_template"),
            risk_level=StepRiskLevel(item.get("risk_level", "low")),
            requires_approval=bool(item.get("requires_approval", False)),
            blast_radius=str(
                item.get(
                    "blast_radius", "Single service instance or read-only diagnostic."
                )
            ),
        )
        for item in (row.steps or [])
    ]
    return Runbook(
        id=row.id,
        slug=row.slug,
        title=row.title,
        service_name=row.service_name,
        symptom_summary=row.symptom_summary,
        steps=steps,
        owner_id=row.owner_id,
        is_shared=row.is_shared,
        created_at=row.created_at,
        updated_at=row.updated_at,
        embedding=list(row.embedding) if row.embedding is not None else None,
    )


def _to_postmortem(row: PostmortemORM) -> Postmortem:
    return Postmortem(
        id=row.id,
        incident_id=row.incident_id,
        title=row.title,
        service_name=row.service_name,
        root_cause=row.root_cause,
        resolution_summary=row.resolution_summary,
        action_items=list(row.action_items or []),
        owner_id=row.owner_id,
        is_shared=row.is_shared,
        published_at=row.published_at,
        embedding=list(row.embedding) if row.embedding is not None else None,
    )


def _to_event(row: IncidentEventORM) -> IncidentEvent:
    return IncidentEvent(
        id=row.id,
        incident_id=row.incident_id,
        event_type=row.event_type,
        from_status=row.from_status,
        to_status=row.to_status,
        actor_id=row.actor_id,
        actor_type=ActorType(row.actor_type),
        payload=dict(row.payload or {}),
        created_at=row.created_at,
    )


class SqlAlchemyIncidentRepository:
    """Async SQLAlchemy repository for incidents."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        *,
        title: str,
        description: str,
        severity: IncidentSeverity,
        service_name: str,
        telemetry: dict[str, Any],
        owner_id: UUID,
    ) -> Incident:
        """Insert and flush a new incident row."""
        row = IncidentORM(
            title=title,
            description=description,
            status=IncidentStatus.TRIGGERED.value,
            severity=severity.value,
            service_name=service_name,
            telemetry=telemetry,
            owner_id=owner_id,
        )
        self._session.add(row)
        await self._session.flush()
        await self._session.refresh(row)
        return _to_incident(row)

    async def get_by_id(self, incident_id: UUID) -> Incident | None:
        """Fetch an incident by UUID."""
        stmt = select(IncidentORM).where(IncidentORM.id == incident_id)
        row = (await self._session.execute(stmt)).scalar_one_or_none()
        return _to_incident(row) if row is not None else None

    async def list_incidents(
        self,
        *,
        status: IncidentStatus | None = None,
        severity: IncidentSeverity | None = None,
        service_name: str | None = None,
        limit: int = 50,
    ) -> list[Incident]:
        """Query incidents with optional filters."""
        stmt = select(IncidentORM)
        if status is not None:
            stmt = stmt.where(IncidentORM.status == status.value)
        if severity is not None:
            stmt = stmt.where(IncidentORM.severity == severity.value)
        if service_name is not None:
            stmt = stmt.where(IncidentORM.service_name == service_name)
        stmt = stmt.order_by(IncidentORM.created_at.desc()).limit(limit)
        rows = (await self._session.execute(stmt)).scalars().all()
        return [_to_incident(row) for row in rows]

    async def update_status(
        self,
        *,
        incident_id: UUID,
        status: IncidentStatus,
        resolved_at: datetime | None,
    ) -> Incident:
        """Update incident status and return refreshed aggregate."""
        stmt = (
            update(IncidentORM)
            .where(IncidentORM.id == incident_id)
            .values(status=status.value, resolved_at=resolved_at)
            .returning(IncidentORM)
        )
        row = (await self._session.execute(stmt)).scalar_one()
        return _to_incident(row)


class SqlAlchemyRunbookRepository:
    """Async SQLAlchemy repository for runbooks with pgvector HNSW search."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        *,
        slug: str,
        title: str,
        service_name: str,
        symptom_summary: str,
        steps: list[RunbookStep],
        embedding: list[float] | None,
        is_shared: bool,
        owner_id: UUID,
    ) -> Runbook:
        """Insert a runbook with serialized JSONB steps and vector embedding."""
        serialized_steps = []
        for step in steps:
            data = asdict(step)
            data["risk_level"] = step.risk_level.value
            serialized_steps.append(data)

        row = RunbookORM(
            slug=slug,
            title=title,
            service_name=service_name,
            symptom_summary=symptom_summary,
            steps=serialized_steps,
            embedding=embedding,
            is_shared=is_shared,
            owner_id=owner_id,
        )
        self._session.add(row)
        await self._session.flush()
        await self._session.refresh(row)
        return _to_runbook(row)

    async def get_by_slug(self, slug: str) -> Runbook | None:
        """Fetch a runbook by its unique slug."""
        stmt = select(RunbookORM).where(RunbookORM.slug == slug)
        row = (await self._session.execute(stmt)).scalar_one_or_none()
        return _to_runbook(row) if row is not None else None

    async def list_runbooks(
        self,
        *,
        service_name: str | None = None,
        limit: int = 50,
    ) -> list[Runbook]:
        """List accessible runbooks."""
        stmt = select(RunbookORM)
        if service_name is not None:
            stmt = stmt.where(RunbookORM.service_name == service_name)
        stmt = stmt.order_by(RunbookORM.updated_at.desc()).limit(limit)
        rows = (await self._session.execute(stmt)).scalars().all()
        return [_to_runbook(row) for row in rows]

    async def search_similar(
        self,
        *,
        query_embedding: list[float],
        service_name: str | None = None,
        limit: int = 5,
        min_similarity: float = 0.0,
    ) -> list[SimilarRunbookMatch]:
        """Execute cosine similarity search ordered by <=> so HNSW index is used."""
        distance_expr = RunbookORM.embedding.cosine_distance(query_embedding)
        similarity_expr = (1.0 - distance_expr).label("similarity")
        stmt = select(RunbookORM, similarity_expr).where(RunbookORM.embedding.is_not(None))
        if service_name is not None:
            stmt = stmt.where(RunbookORM.service_name == service_name)
        if min_similarity > 0.0:
            stmt = stmt.where(distance_expr <= (1.0 - min_similarity))
        stmt = stmt.order_by(distance_expr.asc()).limit(limit)
        rows = (await self._session.execute(stmt)).all()
        return [
            SimilarRunbookMatch(runbook=_to_runbook(rb), similarity=float(sim))
            for rb, sim in rows
        ]


class SqlAlchemyPostmortemRepository:
    """Async SQLAlchemy repository for historical postmortems."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        *,
        incident_id: UUID | None,
        title: str,
        service_name: str,
        root_cause: str,
        resolution_summary: str,
        action_items: list[str],
        embedding: list[float] | None,
        is_shared: bool,
        owner_id: UUID,
    ) -> Postmortem:
        """Insert a postmortem with embedding."""
        row = PostmortemORM(
            incident_id=incident_id,
            title=title,
            service_name=service_name,
            root_cause=root_cause,
            resolution_summary=resolution_summary,
            action_items=action_items,
            embedding=embedding,
            is_shared=is_shared,
            owner_id=owner_id,
        )
        self._session.add(row)
        await self._session.flush()
        await self._session.refresh(row)
        return _to_postmortem(row)

    async def search_similar(
        self,
        *,
        query_embedding: list[float],
        service_name: str | None = None,
        limit: int = 5,
        min_similarity: float = 0.0,
    ) -> list[SimilarPostmortemMatch]:
        """Execute cosine similarity search against postmortem HNSW index."""
        distance_expr = PostmortemORM.embedding.cosine_distance(query_embedding)
        similarity_expr = (1.0 - distance_expr).label("similarity")
        stmt = select(PostmortemORM, similarity_expr).where(
            PostmortemORM.embedding.is_not(None)
        )
        if service_name is not None:
            stmt = stmt.where(PostmortemORM.service_name == service_name)
        if min_similarity > 0.0:
            stmt = stmt.where(distance_expr <= (1.0 - min_similarity))
        stmt = stmt.order_by(distance_expr.asc()).limit(limit)
        rows = (await self._session.execute(stmt)).all()
        return [
            SimilarPostmortemMatch(postmortem=_to_postmortem(pm), similarity=float(sim))
            for pm, sim in rows
        ]


class SqlAlchemyEventRepository:
    """Append-only repository for public.incident_events."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def append(
        self,
        *,
        incident_id: UUID,
        event_type: str,
        actor_id: UUID,
        actor_type: ActorType,
        from_status: str | None = None,
        to_status: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> IncidentEvent:
        """Append an immutable audit log entry."""
        row = IncidentEventORM(
            incident_id=incident_id,
            event_type=event_type,
            from_status=from_status,
            to_status=to_status,
            actor_id=actor_id,
            actor_type=actor_type.value,
            payload=payload or {},
        )
        self._session.add(row)
        await self._session.flush()
        await self._session.refresh(row)
        return _to_event(row)

    async def list_for_incident(
        self,
        incident_id: UUID,
        *,
        limit: int = 100,
    ) -> list[IncidentEvent]:
        """List audit events for an incident in chronological order."""
        stmt = (
            select(IncidentEventORM)
            .where(IncidentEventORM.incident_id == incident_id)
            .order_by(IncidentEventORM.created_at.asc())
            .limit(limit)
        )
        rows = (await self._session.execute(stmt)).scalars().all()
        return [_to_event(row) for row in rows]

    async def is_approval_jti_consumed(self, token_jti: str) -> bool:
        """Return True if an approval token JTI was already used."""
        stmt = (
            select(IncidentEventORM.id)
            .where(IncidentEventORM.event_type == "runbook_step_executed")
            .where(IncidentEventORM.payload["token_jti"].astext == token_jti)
            .limit(1)
        )
        return (await self._session.execute(stmt)).scalar_one_or_none() is not None


class SqlAlchemyUnitOfWork:
    """Transaction-scoped Unit of Work backed by an RLS-bound AsyncSession."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self.incidents = SqlAlchemyIncidentRepository(session)
        self.runbooks = SqlAlchemyRunbookRepository(session)
        self.postmortems = SqlAlchemyPostmortemRepository(session)
        self.events = SqlAlchemyEventRepository(session)

    async def commit(self) -> None:
        """Flush pending ORM writes; transaction commits on context exit."""
        await self._session.flush()

    async def rollback(self) -> None:
        """Rollback current transaction."""
        await self._session.rollback()


def build_uow_factory(db_manager: DatabaseManager):
    """Build a UnitOfWorkFactory bound to a DatabaseManager."""

    @asynccontextmanager
    async def factory(principal: AuthPrincipal) -> AsyncIterator[ControlPlaneUnitOfWork]:
        async with db_manager.session_scope(principal) as session:
            yield SqlAlchemyUnitOfWork(session)

    return factory
