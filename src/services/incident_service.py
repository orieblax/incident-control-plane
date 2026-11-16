"""Incident lifecycle and diagnostic orchestration service."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from src.domain.exceptions import NotFoundError, ValidationError
from src.domain.models import (
    AuthPrincipal,
    DiagnosisResult,
    Incident,
    IncidentEvent,
    IncidentSeverity,
    IncidentStatus,
)
from src.domain.ports import EmbeddingProvider, UnitOfWorkFactory
from src.domain.state_machine import validate_transition


class IncidentService:
    """Application service shared by both REST and MCP adapters."""

    def __init__(
        self,
        uow_factory: UnitOfWorkFactory,
        embedder: EmbeddingProvider,
    ) -> None:
        self._uow_factory = uow_factory
        self._embedder = embedder

    async def create_incident(
        self,
        *,
        title: str,
        description: str,
        severity: IncidentSeverity,
        service_name: str,
        telemetry: dict[str, Any] | None,
        principal: AuthPrincipal,
    ) -> Incident:
        """Create a new incident in 'triggered' state with an initial audit event."""
        cleaned_title = title.strip()
        cleaned_service = service_name.strip()
        if not cleaned_title:
            raise ValidationError("Incident title must not be empty.")
        if not cleaned_service:
            raise ValidationError("Incident service_name must not be empty.")

        async with self._uow_factory(principal) as uow:
            incident = await uow.incidents.create(
                title=cleaned_title,
                description=description.strip(),
                severity=severity,
                service_name=cleaned_service,
                telemetry=telemetry or {},
                owner_id=principal.user_id,
            )
            await uow.events.append(
                incident_id=incident.id,
                event_type="incident_created",
                to_status=incident.status.value,
                actor_id=principal.user_id,
                actor_type=principal.actor_type,
                payload={
                    "severity": severity.value,
                    "service_name": cleaned_service,
                },
            )
            await uow.commit()
            return incident

    async def get_incident(
        self,
        incident_id: UUID,
        principal: AuthPrincipal,
    ) -> tuple[Incident, list[IncidentEvent]]:
        """Fetch an incident and its chronological audit events."""
        async with self._uow_factory(principal) as uow:
            incident = await uow.incidents.get_by_id(incident_id)
            if incident is None:
                raise NotFoundError(f"Incident '{incident_id}' not found.")
            events = await uow.events.list_for_incident(incident_id)
            return incident, events

    async def list_incidents(
        self,
        *,
        principal: AuthPrincipal,
        status: IncidentStatus | None = None,
        severity: IncidentSeverity | None = None,
        service_name: str | None = None,
        limit: int = 50,
    ) -> list[Incident]:
        """List incidents filtered by status, severity, or service."""
        bounded_limit = max(1, min(limit, 100))
        async with self._uow_factory(principal) as uow:
            return await uow.incidents.list_incidents(
                status=status,
                severity=severity,
                service_name=service_name,
                limit=bounded_limit,
            )

    async def transition_incident(
        self,
        *,
        incident_id: UUID,
        target_status: IncidentStatus,
        reason: str,
        principal: AuthPrincipal,
    ) -> Incident:
        """Transition an incident state and atomically emit an immutable audit log."""
        cleaned_reason = reason.strip()
        if not cleaned_reason:
            raise ValidationError("A transition reason is required for the audit log.")

        async with self._uow_factory(principal) as uow:
            incident = await uow.incidents.get_by_id(incident_id)
            if incident is None:
                raise NotFoundError(f"Incident '{incident_id}' not found.")

            validate_transition(incident.status, target_status)
            resolved_at = (
                datetime.now(UTC)
                if target_status == IncidentStatus.RESOLVED
                else None
            )
            previous_status = incident.status
            updated = await uow.incidents.update_status(
                incident_id=incident_id,
                status=target_status,
                resolved_at=resolved_at,
            )
            await uow.events.append(
                incident_id=incident_id,
                event_type="status_changed",
                from_status=previous_status.value,
                to_status=target_status.value,
                actor_id=principal.user_id,
                actor_type=principal.actor_type,
                payload={"reason": cleaned_reason},
            )
            await uow.commit()
            return updated

    async def diagnose_incident(
        self,
        *,
        incident_id: UUID,
        principal: AuthPrincipal,
        top_k: int = 3,
        record_audit_event: bool = True,
    ) -> DiagnosisResult:
        """Synthesize diagnosis by correlating telemetry with pgvector runbooks & postmortems."""
        async with self._uow_factory(principal) as uow:
            incident = await uow.incidents.get_by_id(incident_id)
            if incident is None:
                raise NotFoundError(f"Incident '{incident_id}' not found.")

        query_text = _build_diagnosis_query(incident)
        query_embedding = await self._embedder.embed_text(query_text)

        bounded_k = max(1, min(top_k, 10))
        async with self._uow_factory(principal) as uow:
            runbooks = await uow.runbooks.search_similar(
                query_embedding=query_embedding,
                service_name=incident.service_name,
                limit=bounded_k,
            )
            if not runbooks:
                runbooks = await uow.runbooks.search_similar(
                    query_embedding=query_embedding,
                    service_name=None,
                    limit=bounded_k,
                )

            postmortems = await uow.postmortems.search_similar(
                query_embedding=query_embedding,
                service_name=incident.service_name,
                limit=bounded_k,
            )
            if not postmortems:
                postmortems = await uow.postmortems.search_similar(
                    query_embedding=query_embedding,
                    service_name=None,
                    limit=bounded_k,
                )

            recommendation = _derive_recommendation(incident, runbooks, postmortems)
            if record_audit_event:
                await uow.events.append(
                    incident_id=incident.id,
                    event_type="incident_diagnosed",
                    actor_id=principal.user_id,
                    actor_type=principal.actor_type,
                    payload={
                        "matched_runbook_slugs": [m.runbook.slug for m in runbooks],
                        "matched_postmortem_ids": [
                            str(m.postmortem.id) for m in postmortems
                        ],
                    },
                )
                await uow.commit()

            return DiagnosisResult(
                incident=incident,
                matched_runbooks=runbooks,
                similar_postmortems=postmortems,
                recommended_next_action=recommendation,
            )


def _build_diagnosis_query(incident: Incident) -> str:
    telemetry_summary = ", ".join(
        f"{key}={value}" for key, value in sorted(incident.telemetry.items())
    )
    return (
        f"Service: {incident.service_name}\n"
        f"Severity: {incident.severity.value}\n"
        f"Title: {incident.title}\n"
        f"Description: {incident.description}\n"
        f"Telemetry: {telemetry_summary}"
    )


def _derive_recommendation(
    incident: Incident,
    runbooks: list[Any],
    postmortems: list[Any],
) -> str:
    if runbooks:
        top_rb = runbooks[0].runbook
        return (
            f"Execute runbook '{top_rb.slug}' ({top_rb.title}) starting at step 1; "
            f"transition incident '{incident.id}' to 'investigating' if still triggered."
        )
    if postmortems:
        top_pm = postmortems[0].postmortem
        return (
            f"No service-specific runbook matched; inspect historical postmortem "
            f"'{top_pm.title}' (resolution: {top_pm.resolution_summary})."
        )
    return (
        f"No matching runbooks or postmortems found for '{incident.service_name}'. "
        "Begin manual triage and capture telemetry."
    )
