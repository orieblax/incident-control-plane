"""Unit tests for IncidentService and RunbookService orchestration."""

from __future__ import annotations

from uuid import uuid4

import pytest

from src.domain.exceptions import InvalidApprovalTokenError
from src.domain.models import (
    ActorType,
    AuthPrincipal,
    IncidentSeverity,
    IncidentStatus,
    RunbookStep,
    StepRiskLevel,
)
from src.infrastructure.embeddings.provider import DeterministicTestEmbedder
from src.infrastructure.security.approval_tokens import HmacApprovalSigner
from src.services.incident_service import IncidentService
from src.services.runbook_service import RunbookService
from tests.fakes import InMemoryStore, build_fake_uow_factory


async def test_incident_lifecycle_diagnosis_and_hitl_single_use() -> None:
    store = InMemoryStore()
    uow_factory = build_fake_uow_factory(store)
    embedder = DeterministicTestEmbedder(dimensions=128)
    signer = HmacApprovalSigner(secret="unit-test-secret", ttl_seconds=300)

    inc_svc = IncidentService(uow_factory=uow_factory, embedder=embedder)
    rb_svc = RunbookService(
        uow_factory=uow_factory, embedder=embedder, approval_signer=signer
    )
    principal = AuthPrincipal(
        user_id=uuid4(), email="sre@example.com", actor_type=ActorType.HUMAN
    )

    await rb_svc.create_runbook(
        slug="pg-pool-exhaustion",
        title="Recover Supavisor Pool Exhaustion",
        service_name="checkout-api",
        symptom_summary="asyncpg timeout waiting for Supavisor pooler port 6543 connections",
        steps=[
            RunbookStep(
                step_number=1,
                title="Inspect active pooler connections",
                instruction="Check pg_stat_activity counts",
                risk_level=StepRiskLevel.LOW,
                requires_approval=False,
            ),
            RunbookStep(
                step_number=2,
                title="Recycle stuck worker pool",
                instruction="Drain idle backend sockets",
                command_template="vercel rollback --yes",
                risk_level=StepRiskLevel.HIGH,
                requires_approval=True,
                blast_radius="Restarts checkout-api serverless warm workers.",
            ),
        ],
        is_shared=True,
        principal=principal,
    )
    await rb_svc.create_postmortem(
        incident_id=None,
        title="Checkout API Supavisor connection storm",
        service_name="checkout-api",
        root_cause="Prepared statement cache enabled against transaction pooler",
        resolution_summary="Disabled statement_cache_size and enabled NullPool",
        action_items=["Add CI check for NullPool"],
        is_shared=True,
        principal=principal,
    )

    incident = await inc_svc.create_incident(
        title="Checkout 503 pool timeout",
        description="asyncpg connection pooler timeout on port 6543",
        severity=IncidentSeverity.SEV1,
        service_name="checkout-api",
        telemetry={"error": "pool timeout", "p99_ms": 4800},
        principal=principal,
    )
    assert incident.status == IncidentStatus.TRIGGERED

    diagnosis = await inc_svc.diagnose_incident(
        incident_id=incident.id, principal=principal
    )
    assert diagnosis.matched_runbooks[0].runbook.slug == "pg-pool-exhaustion"
    assert len(diagnosis.similar_postmortems) == 1

    # Step 1 is low risk -> executes immediately
    step1 = await rb_svc.execute_runbook_step(
        incident_id=incident.id,
        runbook_slug="pg-pool-exhaustion",
        step_number=1,
        principal=principal,
    )
    assert step1.status == "executed"

    # Step 2 requires HITL confirmation -> returns challenge first
    step2_challenge = await rb_svc.execute_runbook_step(
        incident_id=incident.id,
        runbook_slug="pg-pool-exhaustion",
        step_number=2,
        principal=principal,
    )
    assert step2_challenge.status == "confirmation_required"
    assert step2_challenge.challenge is not None
    token = step2_challenge.challenge.approval_token

    # Re-invoking with approval_token executes once
    step2_done = await rb_svc.execute_runbook_step(
        incident_id=incident.id,
        runbook_slug="pg-pool-exhaustion",
        step_number=2,
        principal=principal,
        approval_token=token,
        justification="Approved by on-call IC",
    )
    assert step2_done.status == "executed"

    # Replaying the same token is rejected
    with pytest.raises(InvalidApprovalTokenError, match="already been used"):
        await rb_svc.execute_runbook_step(
            incident_id=incident.id,
            runbook_slug="pg-pool-exhaustion",
            step_number=2,
            principal=principal,
            approval_token=token,
        )

    # Transition triggered -> investigating -> mitigated -> resolved
    await inc_svc.transition_incident(
        incident_id=incident.id,
        target_status=IncidentStatus.INVESTIGATING,
        reason="Triaging pool timeout",
        principal=principal,
    )
    await inc_svc.transition_incident(
        incident_id=incident.id,
        target_status=IncidentStatus.MITIGATED,
        reason="Pool drained",
        principal=principal,
    )
    resolved = await inc_svc.transition_incident(
        incident_id=incident.id,
        target_status=IncidentStatus.RESOLVED,
        reason="Verified error rate 0%",
        principal=principal,
    )
    assert resolved.resolved_at is not None

    _, events = await inc_svc.get_incident(incident.id, principal)
    assert [e.event_type for e in events] == [
        "incident_created",
        "incident_diagnosed",
        "runbook_step_executed",
        "runbook_approval_requested",
        "runbook_step_executed",
        "status_changed",
        "status_changed",
        "status_changed",
    ]
