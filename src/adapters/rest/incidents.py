"""REST endpoints for incident CRUD, state transitions, and diagnostics."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Query, status
from pydantic import BaseModel, Field

from src.adapters.rest.dependencies import ContainerDep, CurrentPrincipal
from src.domain.models import (
    DiagnosisResult,
    Incident,
    IncidentEvent,
    IncidentSeverity,
    IncidentStatus,
)

router = APIRouter(prefix="/incidents", tags=["Incidents"])


class IncidentCreateRequest(BaseModel):
    """Payload to trigger a new incident."""

    title: str = Field(..., min_length=1, max_length=200)
    description: str = Field(..., min_length=1, max_length=4000)
    severity: IncidentSeverity
    service_name: str = Field(..., min_length=1, max_length=120)
    telemetry: dict[str, Any] = Field(default_factory=dict)


class IncidentTransitionRequest(BaseModel):
    """Payload to advance or re-open an incident status."""

    target_status: IncidentStatus
    reason: str = Field(..., min_length=1, max_length=1000)


class IncidentResponse(BaseModel):
    """Serialized incident representation."""

    id: UUID
    title: str
    description: str
    status: IncidentStatus
    severity: IncidentSeverity
    service_name: str
    telemetry: dict[str, Any]
    owner_id: UUID
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None = None


class IncidentEventResponse(BaseModel):
    """Serialized immutable audit log event."""

    id: UUID
    incident_id: UUID
    event_type: str
    from_status: str | None = None
    to_status: str | None = None
    actor_id: UUID
    actor_type: str
    payload: dict[str, Any]
    created_at: datetime


class IncidentDetailResponse(BaseModel):
    """Incident paired with chronological audit trail."""

    incident: IncidentResponse
    events: list[IncidentEventResponse]


class MatchedRunbookSummary(BaseModel):
    """Runbook similarity hit returned by diagnosis."""

    slug: str
    title: str
    service_name: str
    symptom_summary: str
    similarity: float


class MatchedPostmortemSummary(BaseModel):
    """Postmortem similarity hit returned by diagnosis."""

    id: UUID
    title: str
    service_name: str
    root_cause: str
    resolution_summary: str
    similarity: float


class DiagnosisResponse(BaseModel):
    """Structured incident diagnosis output."""

    incident: IncidentResponse
    matched_runbooks: list[MatchedRunbookSummary]
    similar_postmortems: list[MatchedPostmortemSummary]
    recommended_next_action: str


def _serialize_incident(incident: Incident) -> IncidentResponse:
    return IncidentResponse(
        id=incident.id,
        title=incident.title,
        description=incident.description,
        status=incident.status,
        severity=incident.severity,
        service_name=incident.service_name,
        telemetry=incident.telemetry,
        owner_id=incident.owner_id,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
        resolved_at=incident.resolved_at,
    )


def _serialize_event(event: IncidentEvent) -> IncidentEventResponse:
    return IncidentEventResponse(
        id=event.id,
        incident_id=event.incident_id,
        event_type=event.event_type,
        from_status=event.from_status,
        to_status=event.to_status,
        actor_id=event.actor_id,
        actor_type=event.actor_type.value,
        payload=event.payload,
        created_at=event.created_at,
    )


def _serialize_diagnosis(result: DiagnosisResult) -> DiagnosisResponse:
    return DiagnosisResponse(
        incident=_serialize_incident(result.incident),
        matched_runbooks=[
            MatchedRunbookSummary(
                slug=m.runbook.slug,
                title=m.runbook.title,
                service_name=m.runbook.service_name,
                symptom_summary=m.runbook.symptom_summary,
                similarity=round(m.similarity, 4),
            )
            for m in result.matched_runbooks
        ],
        similar_postmortems=[
            MatchedPostmortemSummary(
                id=m.postmortem.id,
                title=m.postmortem.title,
                service_name=m.postmortem.service_name,
                root_cause=m.postmortem.root_cause,
                resolution_summary=m.postmortem.resolution_summary,
                similarity=round(m.similarity, 4),
            )
            for m in result.similar_postmortems
        ],
        recommended_next_action=result.recommended_next_action,
    )


@router.post(
    "",
    response_model=IncidentResponse,
    status_code=status.HTTP_201_CREATED,
    operation_id="create_incident",
)
async def create_incident(
    body: IncidentCreateRequest,
    principal: CurrentPrincipal,
    container: ContainerDep,
) -> IncidentResponse:
    """Create a new incident in 'triggered' state."""
    incident = await container.incident_service.create_incident(
        title=body.title,
        description=body.description,
        severity=body.severity,
        service_name=body.service_name,
        telemetry=body.telemetry,
        principal=principal,
    )
    return _serialize_incident(incident)


@router.get("", response_model=list[IncidentResponse], operation_id="list_incidents")
async def list_incidents(
    principal: CurrentPrincipal,
    container: ContainerDep,
    status_filter: Annotated[IncidentStatus | None, Query(alias="status")] = None,
    severity: Annotated[IncidentSeverity | None, Query()] = None,
    service_name: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> list[IncidentResponse]:
    """List incidents matching optional filters."""
    items = await container.incident_service.list_incidents(
        principal=principal,
        status=status_filter,
        severity=severity,
        service_name=service_name,
        limit=limit,
    )
    return [_serialize_incident(item) for item in items]


@router.get(
    "/{incident_id}",
    response_model=IncidentDetailResponse,
    operation_id="get_incident",
)
async def get_incident(
    incident_id: UUID,
    principal: CurrentPrincipal,
    container: ContainerDep,
) -> IncidentDetailResponse:
    """Fetch a single incident and its immutable audit event log."""
    incident, events = await container.incident_service.get_incident(
        incident_id=incident_id,
        principal=principal,
    )
    return IncidentDetailResponse(
        incident=_serialize_incident(incident),
        events=[_serialize_event(ev) for ev in events],
    )


@router.post(
    "/{incident_id}/transition",
    response_model=IncidentResponse,
    operation_id="transition_incident_status",
)
async def transition_incident(
    incident_id: UUID,
    body: IncidentTransitionRequest,
    principal: CurrentPrincipal,
    container: ContainerDep,
) -> IncidentResponse:
    """Transition an incident through the state machine."""
    updated = await container.incident_service.transition_incident(
        incident_id=incident_id,
        target_status=body.target_status,
        reason=body.reason,
        principal=principal,
    )
    return _serialize_incident(updated)


@router.post(
    "/{incident_id}/diagnose",
    response_model=DiagnosisResponse,
    operation_id="diagnose_incident",
)
async def diagnose_incident(
    incident_id: UUID,
    principal: CurrentPrincipal,
    container: ContainerDep,
    top_k: Annotated[int, Query(ge=1, le=10)] = 3,
) -> DiagnosisResponse:
    """Diagnose an incident using telemetry and pgvector runbook/postmortem search."""
    result = await container.incident_service.diagnose_incident(
        incident_id=incident_id,
        principal=principal,
        top_k=top_k,
    )
    return _serialize_diagnosis(result)
