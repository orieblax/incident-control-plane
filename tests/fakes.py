"""In-memory hexagonal test fakes mirroring RLS and pgvector cosine similarity."""

from __future__ import annotations

import math
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

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
from src.domain.ports import ControlPlaneUnitOfWork


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Compute exact cosine similarity between two equal-length vectors."""
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)


@dataclass
class InMemoryStore:
    """Shared in-memory state across transactions."""

    incidents: dict[UUID, Incident] = field(default_factory=dict)
    runbooks: dict[str, Runbook] = field(default_factory=dict)
    postmortems: dict[UUID, Postmortem] = field(default_factory=dict)
    events: list[IncidentEvent] = field(default_factory=list)


class FakeIncidentRepo:
    def __init__(self, store: InMemoryStore, principal: AuthPrincipal) -> None:
        self._store = store
        self._principal = principal

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
        now = datetime.now(UTC)
        inc = Incident(
            id=uuid4(),
            title=title,
            description=description,
            status=IncidentStatus.TRIGGERED,
            severity=severity,
            service_name=service_name,
            telemetry=dict(telemetry),
            owner_id=owner_id,
            created_at=now,
            updated_at=now,
            resolved_at=None,
        )
        self._store.incidents[inc.id] = inc
        return inc

    async def get_by_id(self, incident_id: UUID) -> Incident | None:
        inc = self._store.incidents.get(incident_id)
        if inc is None or inc.owner_id != self._principal.user_id:
            return None
        return inc

    async def list_incidents(
        self,
        *,
        status: IncidentStatus | None = None,
        severity: IncidentSeverity | None = None,
        service_name: str | None = None,
        limit: int = 50,
    ) -> list[Incident]:
        items = [
            inc
            for inc in self._store.incidents.values()
            if inc.owner_id == self._principal.user_id
        ]
        if status is not None:
            items = [i for i in items if i.status == status]
        if severity is not None:
            items = [i for i in items if i.severity == severity]
        if service_name is not None:
            items = [i for i in items if i.service_name == service_name]
        items.sort(key=lambda i: i.created_at, reverse=True)
        return items[:limit]

    async def update_status(
        self,
        *,
        incident_id: UUID,
        status: IncidentStatus,
        resolved_at: datetime | None,
    ) -> Incident:
        inc = self._store.incidents[incident_id]
        inc.status = status
        inc.resolved_at = resolved_at
        inc.updated_at = datetime.now(UTC)
        return inc


class FakeRunbookRepo:
    def __init__(self, store: InMemoryStore, principal: AuthPrincipal) -> None:
        self._store = store
        self._principal = principal

    def _visible(self, rb: Runbook) -> bool:
        return rb.owner_id == self._principal.user_id or rb.is_shared

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
        now = datetime.now(UTC)
        rb = Runbook(
            id=uuid4(),
            slug=slug,
            title=title,
            service_name=service_name,
            symptom_summary=symptom_summary,
            steps=list(steps),
            embedding=embedding,
            is_shared=is_shared,
            owner_id=owner_id,
            created_at=now,
            updated_at=now,
        )
        self._store.runbooks[slug] = rb
        return rb

    async def get_by_slug(self, slug: str) -> Runbook | None:
        rb = self._store.runbooks.get(slug)
        if rb is None or not self._visible(rb):
            return None
        return rb

    async def list_runbooks(
        self,
        *,
        service_name: str | None = None,
        limit: int = 50,
    ) -> list[Runbook]:
        items = [rb for rb in self._store.runbooks.values() if self._visible(rb)]
        if service_name is not None:
            items = [rb for rb in items if rb.service_name == service_name]
        return items[:limit]

    async def search_similar(
        self,
        *,
        query_embedding: list[float],
        service_name: str | None = None,
        limit: int = 5,
        min_similarity: float = 0.0,
    ) -> list[SimilarRunbookMatch]:
        hits: list[SimilarRunbookMatch] = []
        for rb in self._store.runbooks.values():
            if not self._visible(rb) or rb.embedding is None:
                continue
            if service_name is not None and rb.service_name != service_name:
                continue
            sim = cosine_similarity(query_embedding, rb.embedding)
            if sim >= min_similarity:
                hits.append(SimilarRunbookMatch(runbook=rb, similarity=sim))
        hits.sort(key=lambda h: h.similarity, reverse=True)
        return hits[:limit]


class FakePostmortemRepo:
    def __init__(self, store: InMemoryStore, principal: AuthPrincipal) -> None:
        self._store = store
        self._principal = principal

    def _visible(self, pm: Postmortem) -> bool:
        return pm.owner_id == self._principal.user_id or pm.is_shared

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
        pm = Postmortem(
            id=uuid4(),
            incident_id=incident_id,
            title=title,
            service_name=service_name,
            root_cause=root_cause,
            resolution_summary=resolution_summary,
            action_items=list(action_items),
            embedding=embedding,
            is_shared=is_shared,
            owner_id=owner_id,
            published_at=datetime.now(UTC),
        )
        self._store.postmortems[pm.id] = pm
        return pm

    async def search_similar(
        self,
        *,
        query_embedding: list[float],
        service_name: str | None = None,
        limit: int = 5,
        min_similarity: float = 0.0,
    ) -> list[SimilarPostmortemMatch]:
        hits: list[SimilarPostmortemMatch] = []
        for pm in self._store.postmortems.values():
            if not self._visible(pm) or pm.embedding is None:
                continue
            if service_name is not None and pm.service_name != service_name:
                continue
            sim = cosine_similarity(query_embedding, pm.embedding)
            if sim >= min_similarity:
                hits.append(SimilarPostmortemMatch(postmortem=pm, similarity=sim))
        hits.sort(key=lambda h: h.similarity, reverse=True)
        return hits[:limit]


class FakeEventRepo:
    def __init__(self, store: InMemoryStore, principal: AuthPrincipal) -> None:
        self._store = store
        self._principal = principal

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
        ev = IncidentEvent(
            id=uuid4(),
            incident_id=incident_id,
            event_type=event_type,
            from_status=from_status,
            to_status=to_status,
            actor_id=actor_id,
            actor_type=actor_type,
            payload=dict(payload or {}),
            created_at=datetime.now(UTC),
        )
        self._store.events.append(ev)
        return ev

    async def list_for_incident(
        self,
        incident_id: UUID,
        *,
        limit: int = 100,
    ) -> list[IncidentEvent]:
        inc = self._store.incidents.get(incident_id)
        if inc is None or inc.owner_id != self._principal.user_id:
            return []
        return [e for e in self._store.events if e.incident_id == incident_id][:limit]

    async def is_approval_jti_consumed(self, token_jti: str) -> bool:
        return any(
            e.event_type == "runbook_step_executed"
            and e.payload.get("token_jti") == token_jti
            for e in self._store.events
        )


class FakeUnitOfWork:
    def __init__(self, store: InMemoryStore, principal: AuthPrincipal) -> None:
        self.incidents = FakeIncidentRepo(store, principal)
        self.runbooks = FakeRunbookRepo(store, principal)
        self.postmortems = FakePostmortemRepo(store, principal)
        self.events = FakeEventRepo(store, principal)
        self.committed = False

    async def commit(self) -> None:
        self.committed = True

    async def rollback(self) -> None:
        self.committed = False


def build_fake_uow_factory(store: InMemoryStore):
    @asynccontextmanager
    async def factory(principal: AuthPrincipal) -> AsyncIterator[ControlPlaneUnitOfWork]:
        yield FakeUnitOfWork(store, principal)

    return factory
