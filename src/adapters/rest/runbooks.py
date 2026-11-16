"""REST endpoints for runbooks, postmortem vector search, and step execution."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query, status
from pydantic import BaseModel, Field

from src.adapters.rest.dependencies import ContainerDep, CurrentPrincipal
from src.domain.models import (
    Postmortem,
    Runbook,
    RunbookStep,
    RunbookStepExecutionResult,
    StepRiskLevel,
)

router = APIRouter(tags=["Runbooks & Postmortems"])


class RunbookStepPayload(BaseModel):
    """Input/output model for an individual runbook step."""

    step_number: int = Field(..., ge=1)
    title: str = Field(..., min_length=1, max_length=200)
    instruction: str = Field(..., min_length=1, max_length=2000)
    command_template: str | None = None
    risk_level: StepRiskLevel = StepRiskLevel.LOW
    requires_approval: bool = False
    blast_radius: str = "Single service instance or read-only diagnostic."


class RunbookCreateRequest(BaseModel):
    """Payload to register an indexed runbook."""

    slug: str = Field(..., min_length=2, max_length=100, pattern=r"^[a-z0-9-]+$")
    title: str = Field(..., min_length=1, max_length=200)
    service_name: str = Field(..., min_length=1, max_length=120)
    symptom_summary: str = Field(..., min_length=1, max_length=4000)
    steps: list[RunbookStepPayload] = Field(..., min_length=1)
    is_shared: bool = False


class RunbookResponse(BaseModel):
    """Serialized runbook."""

    id: UUID
    slug: str
    title: str
    service_name: str
    symptom_summary: str
    steps: list[RunbookStepPayload]
    is_shared: bool
    owner_id: UUID
    created_at: datetime
    updated_at: datetime


class PostmortemCreateRequest(BaseModel):
    """Payload to publish a historical post-mortem with vector indexing."""

    incident_id: UUID | None = None
    title: str = Field(..., min_length=1, max_length=200)
    service_name: str = Field(..., min_length=1, max_length=120)
    root_cause: str = Field(..., min_length=1, max_length=4000)
    resolution_summary: str = Field(..., min_length=1, max_length=4000)
    action_items: list[str] = Field(default_factory=list)
    is_shared: bool = False


class PostmortemResponse(BaseModel):
    """Serialized historical post-mortem."""

    id: UUID
    incident_id: UUID | None = None
    title: str
    service_name: str
    root_cause: str
    resolution_summary: str
    action_items: list[str]
    is_shared: bool
    owner_id: UUID
    published_at: datetime


class PostmortemSearchRequest(BaseModel):
    """Semantic similarity search parameters."""

    query: str = Field(..., min_length=1, max_length=2000)
    service_name: str | None = None
    limit: int = Field(default=5, ge=1, le=25)
    min_similarity: float = Field(default=0.0, ge=-1.0, le=1.0)


class PostmortemSearchHit(BaseModel):
    """Postmortem paired with cosine similarity score."""

    postmortem: PostmortemResponse
    similarity: float


class ExecuteStepRequest(BaseModel):
    """Payload to execute or confirm a runbook remediation step."""

    incident_id: UUID
    step_number: int = Field(..., ge=1)
    approval_token: str | None = None
    justification: str | None = None


class ExecuteStepResponse(BaseModel):
    """Execution result or HITL approval challenge."""

    status: str
    incident_id: UUID
    runbook_slug: str
    step_number: int
    step_title: str
    risk_level: StepRiskLevel
    event_id: UUID | None = None
    approval_token: str | None = None
    expires_at: datetime | None = None
    blast_radius: str | None = None
    instructions: str | None = None
    output_summary: str


def _serialize_step(step: RunbookStep) -> RunbookStepPayload:
    return RunbookStepPayload(
        step_number=step.step_number,
        title=step.title,
        instruction=step.instruction,
        command_template=step.command_template,
        risk_level=step.risk_level,
        requires_approval=step.requires_approval,
        blast_radius=step.blast_radius,
    )


def _serialize_runbook(rb: Runbook) -> RunbookResponse:
    return RunbookResponse(
        id=rb.id,
        slug=rb.slug,
        title=rb.title,
        service_name=rb.service_name,
        symptom_summary=rb.symptom_summary,
        steps=[_serialize_step(step) for step in rb.steps],
        is_shared=rb.is_shared,
        owner_id=rb.owner_id,
        created_at=rb.created_at,
        updated_at=rb.updated_at,
    )


def _serialize_postmortem(pm: Postmortem) -> PostmortemResponse:
    return PostmortemResponse(
        id=pm.id,
        incident_id=pm.incident_id,
        title=pm.title,
        service_name=pm.service_name,
        root_cause=pm.root_cause,
        resolution_summary=pm.resolution_summary,
        action_items=pm.action_items,
        is_shared=pm.is_shared,
        owner_id=pm.owner_id,
        published_at=pm.published_at,
    )


def serialize_execution_result(result: RunbookStepExecutionResult) -> ExecuteStepResponse:
    """Convert domain execution outcome to API response model."""
    challenge = result.challenge
    return ExecuteStepResponse(
        status=result.status,
        incident_id=result.incident_id,
        runbook_slug=result.runbook_slug,
        step_number=result.step.step_number,
        step_title=result.step.title,
        risk_level=result.step.risk_level,
        event_id=result.event_id,
        approval_token=challenge.approval_token if challenge else None,
        expires_at=challenge.expires_at if challenge else None,
        blast_radius=challenge.step.blast_radius if challenge else None,
        instructions=challenge.instructions if challenge else None,
        output_summary=result.output_summary,
    )


@router.post(
    "/runbooks",
    response_model=RunbookResponse,
    status_code=status.HTTP_201_CREATED,
    operation_id="create_runbook",
)
async def create_runbook(
    body: RunbookCreateRequest,
    principal: CurrentPrincipal,
    container: ContainerDep,
) -> RunbookResponse:
    """Create and vector-index an operational runbook."""
    steps = [
        RunbookStep(
            step_number=s.step_number,
            title=s.title,
            instruction=s.instruction,
            command_template=s.command_template,
            risk_level=s.risk_level,
            requires_approval=s.requires_approval,
            blast_radius=s.blast_radius,
        )
        for s in body.steps
    ]
    rb = await container.runbook_service.create_runbook(
        slug=body.slug,
        title=body.title,
        service_name=body.service_name,
        symptom_summary=body.symptom_summary,
        steps=steps,
        is_shared=body.is_shared,
        principal=principal,
    )
    return _serialize_runbook(rb)


@router.get("/runbooks", response_model=list[RunbookResponse], operation_id="list_runbooks")
async def list_runbooks(
    principal: CurrentPrincipal,
    container: ContainerDep,
    service_name: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> list[RunbookResponse]:
    """List runbooks accessible to the caller."""
    items = await container.runbook_service.list_runbooks(
        principal=principal,
        service_name=service_name,
        limit=limit,
    )
    return [_serialize_runbook(rb) for rb in items]


@router.get(
    "/runbooks/{slug}",
    response_model=RunbookResponse,
    operation_id="get_runbook",
)
async def get_runbook(
    slug: str,
    principal: CurrentPrincipal,
    container: ContainerDep,
) -> RunbookResponse:
    """Retrieve a single runbook by slug."""
    rb = await container.runbook_service.get_runbook(slug=slug, principal=principal)
    return _serialize_runbook(rb)


@router.post(
    "/runbooks/{slug}/execute",
    response_model=ExecuteStepResponse,
    operation_id="execute_runbook_step",
)
async def execute_runbook_step(
    slug: str,
    body: ExecuteStepRequest,
    principal: CurrentPrincipal,
    container: ContainerDep,
) -> ExecuteStepResponse:
    """Execute a runbook step or return a confirmation challenge for high-risk steps."""
    result = await container.runbook_service.execute_runbook_step(
        incident_id=body.incident_id,
        runbook_slug=slug,
        step_number=body.step_number,
        principal=principal,
        approval_token=body.approval_token,
        justification=body.justification,
    )
    return serialize_execution_result(result)


@router.post(
    "/postmortems",
    response_model=PostmortemResponse,
    status_code=status.HTTP_201_CREATED,
    operation_id="create_postmortem",
)
async def create_postmortem(
    body: PostmortemCreateRequest,
    principal: CurrentPrincipal,
    container: ContainerDep,
) -> PostmortemResponse:
    """Publish a post-mortem and compute its pgvector embedding."""
    pm = await container.runbook_service.create_postmortem(
        incident_id=body.incident_id,
        title=body.title,
        service_name=body.service_name,
        root_cause=body.root_cause,
        resolution_summary=body.resolution_summary,
        action_items=body.action_items,
        is_shared=body.is_shared,
        principal=principal,
    )
    return _serialize_postmortem(pm)


@router.post(
    "/postmortems/search",
    response_model=list[PostmortemSearchHit],
    operation_id="search_similar_postmortems",
)
async def search_similar_postmortems(
    body: PostmortemSearchRequest,
    principal: CurrentPrincipal,
    container: ContainerDep,
) -> list[PostmortemSearchHit]:
    """Perform semantic similarity search over historical post-mortems."""
    matches = await container.runbook_service.search_similar_postmortems(
        query=body.query,
        principal=principal,
        service_name=body.service_name,
        limit=body.limit,
        min_similarity=body.min_similarity,
    )
    return [
        PostmortemSearchHit(
            postmortem=_serialize_postmortem(m.postmortem),
            similarity=round(m.similarity, 4),
        )
        for m in matches
    ]
