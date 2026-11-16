"""Pure domain entities and value objects."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID


class IncidentStatus(StrEnum):
    """Lifecycle states of an operational incident."""

    TRIGGERED = "triggered"
    INVESTIGATING = "investigating"
    MITIGATED = "mitigated"
    RESOLVED = "resolved"


class IncidentSeverity(StrEnum):
    """Standard incident severity classification."""

    SEV1 = "sev1"
    SEV2 = "sev2"
    SEV3 = "sev3"
    SEV4 = "sev4"


class ActorType(StrEnum):
    """Originator category for audit log events."""

    HUMAN = "human"
    MCP_AGENT = "mcp_agent"
    SYSTEM = "system"


class StepRiskLevel(StrEnum):
    """Risk classification for runbook remediation steps."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class AuthPrincipal:
    """Verified caller identity propagated into services and DB RLS."""

    user_id: UUID
    email: str | None = None
    role: str = "authenticated"
    actor_type: ActorType = ActorType.HUMAN
    scopes: tuple[str, ...] = ("incidents:read", "incidents:write", "runbooks:execute")
    expires_at: int | None = None
    raw_claims: dict[str, Any] = field(default_factory=dict)

    def to_claims_dict(self) -> dict[str, Any]:
        """Return normalized JWT-compatible claims dictionary."""
        return {
            "sub": str(self.user_id),
            "role": self.role,
            "aud": "authenticated",
            "email": self.email or "",
            "actor_type": self.actor_type.value,
            **self.raw_claims,
        }


@dataclass(slots=True)
class Incident:
    """Incident aggregate root."""

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


@dataclass(frozen=True, slots=True)
class RunbookStep:
    """Single executable or advisory step inside a runbook."""

    step_number: int
    title: str
    instruction: str
    command_template: str | None = None
    risk_level: StepRiskLevel = StepRiskLevel.LOW
    requires_approval: bool = False
    blast_radius: str = "Single service instance or read-only diagnostic."


@dataclass(slots=True)
class Runbook:
    """Operational runbook with vector-searchable symptom summary."""

    id: UUID
    slug: str
    title: str
    service_name: str
    symptom_summary: str
    steps: list[RunbookStep]
    owner_id: UUID
    is_shared: bool
    created_at: datetime
    updated_at: datetime
    embedding: list[float] | None = None


@dataclass(slots=True)
class Postmortem:
    """Historical incident post-mortem with vector embedding."""

    id: UUID
    incident_id: UUID | None
    title: str
    service_name: str
    root_cause: str
    resolution_summary: str
    action_items: list[str]
    owner_id: UUID
    is_shared: bool
    published_at: datetime
    embedding: list[float] | None = None


@dataclass(frozen=True, slots=True)
class SimilarPostmortemMatch:
    """Semantic similarity result for a historical post-mortem."""

    postmortem: Postmortem
    similarity: float


@dataclass(frozen=True, slots=True)
class SimilarRunbookMatch:
    """Semantic similarity result for an operational runbook."""

    runbook: Runbook
    similarity: float


@dataclass(frozen=True, slots=True)
class IncidentEvent:
    """Immutable audit trail entry for an incident."""

    id: UUID
    incident_id: UUID
    event_type: str
    from_status: str | None
    to_status: str | None
    actor_id: UUID
    actor_type: ActorType
    payload: dict[str, Any]
    created_at: datetime


@dataclass(frozen=True, slots=True)
class DiagnosisResult:
    """Structured triage synthesis combining telemetry and pgvector matches."""

    incident: Incident
    matched_runbooks: list[SimilarRunbookMatch]
    similar_postmortems: list[SimilarPostmortemMatch]
    recommended_next_action: str


@dataclass(frozen=True, slots=True)
class ApprovalChallenge:
    """Stateless HITL confirmation challenge returned before destructive steps."""

    status: str
    incident_id: UUID
    runbook_slug: str
    step: RunbookStep
    approval_token: str
    expires_at: datetime
    instructions: str


@dataclass(frozen=True, slots=True)
class RunbookStepExecutionResult:
    """Outcome of executing (or requesting approval for) a runbook step."""

    status: str
    incident_id: UUID
    runbook_slug: str
    step: RunbookStep
    event_id: UUID | None = None
    challenge: ApprovalChallenge | None = None
    output_summary: str = ""
