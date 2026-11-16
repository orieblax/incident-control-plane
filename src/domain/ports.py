"""Hexagonal ports (protocols) implemented by infrastructure adapters."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from datetime import datetime
from typing import Any, Protocol
from uuid import UUID

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
)


class IncidentRepository(Protocol):
    """Persistence contract for incident aggregates."""

    async def create(
        self,
        *,
        title: str,
        description: str,
        severity: IncidentSeverity,
        service_name: str,
        telemetry: dict[str, Any],
        owner_id: UUID,
    ) -> Incident: ...

    async def get_by_id(self, incident_id: UUID) -> Incident | None: ...

    async def list_incidents(
        self,
        *,
        status: IncidentStatus | None = None,
        severity: IncidentSeverity | None = None,
        service_name: str | None = None,
        limit: int = 50,
    ) -> list[Incident]: ...

    async def update_status(
        self,
        *,
        incident_id: UUID,
        status: IncidentStatus,
        resolved_at: datetime | None,
    ) -> Incident: ...


class RunbookRepository(Protocol):
    """Persistence and vector-search contract for runbooks."""

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
    ) -> Runbook: ...

    async def get_by_slug(self, slug: str) -> Runbook | None: ...

    async def list_runbooks(
        self,
        *,
        service_name: str | None = None,
        limit: int = 50,
    ) -> list[Runbook]: ...

    async def search_similar(
        self,
        *,
        query_embedding: list[float],
        service_name: str | None = None,
        limit: int = 5,
        min_similarity: float = 0.0,
    ) -> list[SimilarRunbookMatch]: ...


class PostmortemRepository(Protocol):
    """Persistence and vector-search contract for historical postmortems."""

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
    ) -> Postmortem: ...

    async def search_similar(
        self,
        *,
        query_embedding: list[float],
        service_name: str | None = None,
        limit: int = 5,
        min_similarity: float = 0.0,
    ) -> list[SimilarPostmortemMatch]: ...


class EventRepository(Protocol):
    """Append-only audit log contract for incident_events."""

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
    ) -> IncidentEvent: ...

    async def list_for_incident(
        self,
        incident_id: UUID,
        *,
        limit: int = 100,
    ) -> list[IncidentEvent]: ...

    async def is_approval_jti_consumed(self, token_jti: str) -> bool: ...


class ControlPlaneUnitOfWork(Protocol):
    """Transactional unit of work combining repositories under RLS context."""

    incidents: IncidentRepository
    runbooks: RunbookRepository
    postmortems: PostmortemRepository
    events: EventRepository

    async def commit(self) -> None: ...

    async def rollback(self) -> None: ...


UnitOfWorkFactory = Callable[
    [AuthPrincipal], AbstractAsyncContextManager[ControlPlaneUnitOfWork]
]


class EmbeddingProvider(Protocol):
    """Port for generating fixed-dimension text embeddings."""

    @property
    def dimensions(self) -> int: ...

    async def embed_text(self, text: str) -> list[float]: ...


class ApprovalTokenSigner(Protocol):
    """Port for issuing and verifying stateless HITL confirmation tokens."""

    def issue(
        self,
        *,
        incident_id: UUID,
        runbook_slug: str,
        step_number: int,
        actor_id: UUID,
    ) -> tuple[str, datetime]: ...

    def verify(
        self,
        token: str,
        *,
        incident_id: UUID,
        runbook_slug: str,
        step_number: int,
        actor_id: UUID,
    ) -> str: ...
