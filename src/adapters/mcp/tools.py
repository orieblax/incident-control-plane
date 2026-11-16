"""Purpose-built MCP tools, resources, prompts, and dual-mode HITL flows."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any
from uuid import UUID

from fastmcp import Context, FastMCP
from fastmcp.exceptions import ResourceError, ToolError
from fastmcp.server.context import AcceptedElicitation
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

from src.adapters.mcp.auth import principal_from_mcp_context
from src.domain.exceptions import DomainError
from src.domain.models import (
    IncidentSeverity,
    IncidentStatus,
    RunbookStepExecutionResult,
    StepRiskLevel,
)
from src.infrastructure.config import Settings
from src.services.incident_service import IncidentService
from src.services.runbook_service import RunbookService


class ElicitedStepApproval(BaseModel):
    """Schema presented during stateful MCP client elicitation."""

    confirm: bool = Field(
        description="Set true only after confirming blast radius and change safety."
    )
    justification: str = Field(
        default="",
        description="Brief reason or ticket reference authorizing this step.",
    )


def register_incident_tools(
    mcp: FastMCP,
    *,
    incident_service: IncidentService,
    runbook_service: RunbookService,
    settings: Settings,
) -> None:
    """Register domain-backed MCP tools, resources, and prompts on FastMCP."""

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Diagnose Incident",
            readOnlyHint=False,
            idempotentHint=False,
            openWorldHint=False,
        )
    )
    async def diagnose_incident(incident_id: str, top_k: int = 3) -> dict[str, Any]:
        """Correlate incident telemetry with pgvector runbooks and postmortems."""
        try:
            principal = principal_from_mcp_context()
            result = await incident_service.diagnose_incident(
                incident_id=UUID(incident_id),
                principal=principal,
                top_k=top_k,
            )
        except (DomainError, ValueError) as exc:
            raise ToolError(str(exc)) from exc

        return {
            "incident": {
                "id": str(result.incident.id),
                "title": result.incident.title,
                "status": result.incident.status.value,
                "severity": result.incident.severity.value,
                "service_name": result.incident.service_name,
                "telemetry": result.incident.telemetry,
            },
            "matched_runbooks": [
                {
                    "slug": m.runbook.slug,
                    "title": m.runbook.title,
                    "similarity": round(m.similarity, 4),
                    "steps": [
                        {
                            "step_number": s.step_number,
                            "title": s.title,
                            "risk_level": s.risk_level.value,
                            "requires_approval": s.requires_approval,
                        }
                        for s in m.runbook.steps
                    ],
                }
                for m in result.matched_runbooks
            ],
            "similar_postmortems": [
                {
                    "id": str(m.postmortem.id),
                    "title": m.postmortem.title,
                    "root_cause": m.postmortem.root_cause,
                    "resolution_summary": m.postmortem.resolution_summary,
                    "similarity": round(m.similarity, 4),
                }
                for m in result.similar_postmortems
            ],
            "recommended_next_action": result.recommended_next_action,
        }

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Search Similar Postmortems",
            readOnlyHint=True,
            idempotentHint=True,
            openWorldHint=False,
        )
    )
    async def search_similar_postmortems(
        query: str,
        service_name: str | None = None,
        limit: int = 5,
    ) -> dict[str, Any]:
        """Semantic search over historical incident postmortems via pgvector."""
        try:
            principal = principal_from_mcp_context()
            matches = await runbook_service.search_similar_postmortems(
                query=query,
                principal=principal,
                service_name=service_name,
                limit=limit,
            )
        except (DomainError, ValueError) as exc:
            raise ToolError(str(exc)) from exc

        return {
            "count": len(matches),
            "matches": [
                {
                    "id": str(m.postmortem.id),
                    "title": m.postmortem.title,
                    "service_name": m.postmortem.service_name,
                    "root_cause": m.postmortem.root_cause,
                    "resolution_summary": m.postmortem.resolution_summary,
                    "action_items": m.postmortem.action_items,
                    "similarity": round(m.similarity, 4),
                }
                for m in matches
            ],
        }

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Transition Incident Status",
            readOnlyHint=False,
            idempotentHint=False,
            openWorldHint=False,
        )
    )
    async def transition_incident_status(
        incident_id: str,
        target_status: str,
        reason: str,
    ) -> dict[str, Any]:
        """Advance an incident state machine and write an immutable audit event."""
        try:
            principal = principal_from_mcp_context()
            updated = await incident_service.transition_incident(
                incident_id=UUID(incident_id),
                target_status=IncidentStatus(target_status.strip().lower()),
                reason=reason,
                principal=principal,
            )
        except (DomainError, ValueError) as exc:
            raise ToolError(str(exc)) from exc

        return {
            "incident_id": str(updated.id),
            "status": updated.status.value,
            "severity": updated.severity.value,
            "resolved_at": (
                updated.resolved_at.isoformat() if updated.resolved_at else None
            ),
        }

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Trigger Incident",
            readOnlyHint=False,
            idempotentHint=False,
            openWorldHint=False,
        )
    )
    async def trigger_incident(
        title: str,
        description: str,
        severity: str,
        service_name: str,
        telemetry: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a new incident in 'triggered' state via the shared domain service."""
        try:
            principal = principal_from_mcp_context()
            created = await incident_service.create_incident(
                title=title,
                description=description,
                severity=IncidentSeverity(severity.strip().lower()),
                service_name=service_name,
                telemetry=telemetry or {},
                principal=principal,
            )
        except (DomainError, ValueError) as exc:
            raise ToolError(str(exc)) from exc

        return {
            "incident_id": str(created.id),
            "status": created.status.value,
            "severity": created.severity.value,
            "service_name": created.service_name,
        }

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Execute Runbook Step",
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=False,
            openWorldHint=False,
        )
    )
    async def execute_runbook_step(
        incident_id: str,
        runbook_slug: str,
        step_number: int,
        approval_token: str | None = None,
        justification: str | None = None,
        ctx: Context | None = None,
    ) -> dict[str, Any]:
        """Execute a runbook step with HITL confirmation gating for high-risk actions."""
        try:
            principal = principal_from_mcp_context()
            parsed_incident_id = UUID(incident_id)
            normalized_slug = runbook_slug.strip().lower()

            # Stateful local dev mode can attempt native MCP elicitation before falling back
            # to stateless two-phase approval tokens (required on Vercel Serverless).
            effective_token = approval_token
            effective_justification = justification
            if (
                not settings.mcp_stateless_http
                and effective_token is None
                and ctx is not None
            ):
                runbook = await runbook_service.get_runbook(
                    normalized_slug, principal
                )
                matching_step = next(
                    (s for s in runbook.steps if s.step_number == step_number),
                    None,
                )
                if matching_step is not None and (
                    matching_step.requires_approval
                    or matching_step.risk_level
                    in {StepRiskLevel.HIGH, StepRiskLevel.CRITICAL}
                ):
                    try:
                        elicitation = await ctx.elicit(
                            message=(
                                f"Approve runbook '{normalized_slug}' step {step_number} "
                                f"({matching_step.title})? Blast radius: "
                                f"{matching_step.blast_radius}"
                            ),
                            response_type=ElicitedStepApproval,
                        )
                    except Exception:
                        elicitation = None

                    if elicitation is not None:
                        if not isinstance(elicitation, AcceptedElicitation) or not (
                            elicitation.data.confirm
                        ):
                            await runbook_service.record_declined_step(
                                incident_id=parsed_incident_id,
                                runbook_slug=normalized_slug,
                                step_number=step_number,
                                principal=principal,
                                reason="Operator declined MCP elicitation prompt.",
                            )
                            return {
                                "status": "cancelled",
                                "incident_id": str(parsed_incident_id),
                                "runbook_slug": normalized_slug,
                                "step_number": step_number,
                                "output_summary": "Execution declined by operator.",
                            }
                        effective_token, _ = runbook_service.issue_step_approval_token(
                            incident_id=parsed_incident_id,
                            runbook_slug=normalized_slug,
                            step_number=step_number,
                            principal=principal,
                        )
                        effective_justification = (
                            elicitation.data.justification or justification
                        )

            result = await runbook_service.execute_runbook_step(
                incident_id=parsed_incident_id,
                runbook_slug=normalized_slug,
                step_number=step_number,
                principal=principal,
                approval_token=effective_token,
                justification=effective_justification,
            )
            return _format_execution_result(result)
        except (DomainError, ValueError) as exc:
            raise ToolError(str(exc)) from exc

    @mcp.resource(
        "incident://{incident_id}",
        name="Incident Detail",
        description="Read an incident snapshot and chronological audit events.",
        mime_type="application/json",
    )
    async def read_incident_resource(incident_id: str) -> str:
        """Expose incident + timeline as an MCP resource."""
        try:
            principal = principal_from_mcp_context()
            incident, events = await incident_service.get_incident(
                UUID(incident_id), principal
            )
        except (DomainError, ValueError) as exc:
            raise ResourceError(str(exc)) from exc

        payload = {
            "incident": {
                "id": str(incident.id),
                "title": incident.title,
                "description": incident.description,
                "status": incident.status.value,
                "severity": incident.severity.value,
                "service_name": incident.service_name,
                "telemetry": incident.telemetry,
                "created_at": incident.created_at.isoformat(),
                "updated_at": incident.updated_at.isoformat(),
                "resolved_at": (
                    incident.resolved_at.isoformat() if incident.resolved_at else None
                ),
            },
            "events": [
                {
                    "id": str(ev.id),
                    "event_type": ev.event_type,
                    "from_status": ev.from_status,
                    "to_status": ev.to_status,
                    "actor_type": ev.actor_type.value,
                    "payload": ev.payload,
                    "created_at": ev.created_at.isoformat(),
                }
                for ev in events
            ],
        }
        return json.dumps(payload, indent=2)

    @mcp.resource(
        "runbook://{slug}",
        name="Operational Runbook",
        description="Read structured remediation steps for a runbook slug.",
        mime_type="application/json",
    )
    async def read_runbook_resource(slug: str) -> str:
        """Expose runbook definition as an MCP resource."""
        try:
            principal = principal_from_mcp_context()
            rb = await runbook_service.get_runbook(slug, principal)
        except (DomainError, ValueError) as exc:
            raise ResourceError(str(exc)) from exc

        payload = {
            "id": str(rb.id),
            "slug": rb.slug,
            "title": rb.title,
            "service_name": rb.service_name,
            "symptom_summary": rb.symptom_summary,
            "steps": [
                {**asdict(step), "risk_level": step.risk_level.value}
                for step in rb.steps
            ],
        }
        return json.dumps(payload, indent=2)

    @mcp.prompt(
        name="triage_incident",
        description=(
            "Structured triage workflow combining diagnosis, postmortem search, "
            "and safe remediation."
        ),
    )
    def triage_incident_prompt(incident_id: str) -> str:
        """Guide an AI responder through diagnosing and safely remediating an incident."""
        return (
            f"Triage incident '{incident_id}' using these steps:\n"
            f"1. Read resource incident://{incident_id} and call diagnose_incident.\n"
            "2. Review similar historical postmortems via search_similar_postmortems.\n"
            "3. Transition the incident to 'investigating' via transition_incident_status.\n"
            "4. If executing a high-risk runbook step via execute_runbook_step, present the "
            "returned blast_radius and approval_token to the human operator before re-invoking."
        )


def _format_execution_result(result: RunbookStepExecutionResult) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "status": result.status,
        "incident_id": str(result.incident_id),
        "runbook_slug": result.runbook_slug,
        "step_number": result.step.step_number,
        "step_title": result.step.title,
        "risk_level": result.step.risk_level.value,
        "event_id": str(result.event_id) if result.event_id else None,
        "output_summary": result.output_summary,
    }
    if result.challenge is not None:
        payload["challenge"] = {
            "approval_token": result.challenge.approval_token,
            "expires_at": result.challenge.expires_at.isoformat(),
            "blast_radius": result.challenge.step.blast_radius,
            "command_template": result.challenge.step.command_template,
            "instructions": result.challenge.instructions,
        }
    return payload
