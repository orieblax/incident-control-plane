"""Runbook, postmortem search, and HITL execution service."""

from __future__ import annotations

from uuid import UUID

from src.domain.exceptions import (
    InvalidApprovalTokenError,
    NotFoundError,
    ValidationError,
)
from src.domain.models import (
    ApprovalChallenge,
    AuthPrincipal,
    Postmortem,
    Runbook,
    RunbookStep,
    RunbookStepExecutionResult,
    SimilarPostmortemMatch,
    StepRiskLevel,
)
from src.domain.ports import (
    ApprovalTokenSigner,
    EmbeddingProvider,
    UnitOfWorkFactory,
)


class RunbookService:
    """Application service for runbooks, postmortem vector retrieval, and HITL execution."""

    def __init__(
        self,
        uow_factory: UnitOfWorkFactory,
        embedder: EmbeddingProvider,
        approval_signer: ApprovalTokenSigner,
    ) -> None:
        self._uow_factory = uow_factory
        self._embedder = embedder
        self._approval_signer = approval_signer

    async def create_runbook(
        self,
        *,
        slug: str,
        title: str,
        service_name: str,
        symptom_summary: str,
        steps: list[RunbookStep],
        is_shared: bool,
        principal: AuthPrincipal,
    ) -> Runbook:
        """Create a runbook and generate its semantic symptom embedding."""
        cleaned_slug = slug.strip().lower()
        if not cleaned_slug:
            raise ValidationError("Runbook slug must not be empty.")
        if not steps:
            raise ValidationError("Runbook must contain at least one step.")

        embed_input = f"{title}\n{service_name}\n{symptom_summary}"
        embedding = await self._embedder.embed_text(embed_input)

        async with self._uow_factory(principal) as uow:
            runbook = await uow.runbooks.create(
                slug=cleaned_slug,
                title=title.strip(),
                service_name=service_name.strip(),
                symptom_summary=symptom_summary.strip(),
                steps=steps,
                embedding=embedding,
                is_shared=is_shared,
                owner_id=principal.user_id,
            )
            await uow.commit()
            return runbook

    async def get_runbook(self, slug: str, principal: AuthPrincipal) -> Runbook:
        """Retrieve a runbook by its unique slug."""
        async with self._uow_factory(principal) as uow:
            runbook = await uow.runbooks.get_by_slug(slug.strip().lower())
            if runbook is None:
                raise NotFoundError(f"Runbook '{slug}' not found.")
            return runbook

    async def list_runbooks(
        self,
        *,
        principal: AuthPrincipal,
        service_name: str | None = None,
        limit: int = 50,
    ) -> list[Runbook]:
        """List runbooks accessible to the principal."""
        bounded_limit = max(1, min(limit, 100))
        async with self._uow_factory(principal) as uow:
            return await uow.runbooks.list_runbooks(
                service_name=service_name,
                limit=bounded_limit,
            )

    async def create_postmortem(
        self,
        *,
        incident_id: UUID | None,
        title: str,
        service_name: str,
        root_cause: str,
        resolution_summary: str,
        action_items: list[str],
        is_shared: bool,
        principal: AuthPrincipal,
    ) -> Postmortem:
        """Persist a historical post-mortem and index its semantic embedding."""
        embed_input = (
            f"{title}\n{service_name}\nRoot cause: {root_cause}\n"
            f"Resolution: {resolution_summary}"
        )
        embedding = await self._embedder.embed_text(embed_input)

        async with self._uow_factory(principal) as uow:
            if incident_id is not None:
                incident = await uow.incidents.get_by_id(incident_id)
                if incident is None:
                    raise NotFoundError(f"Incident '{incident_id}' not found.")
            pm = await uow.postmortems.create(
                incident_id=incident_id,
                title=title.strip(),
                service_name=service_name.strip(),
                root_cause=root_cause.strip(),
                resolution_summary=resolution_summary.strip(),
                action_items=action_items,
                embedding=embedding,
                is_shared=is_shared,
                owner_id=principal.user_id,
            )
            await uow.commit()
            return pm

    async def search_similar_postmortems(
        self,
        *,
        query: str,
        principal: AuthPrincipal,
        service_name: str | None = None,
        limit: int = 5,
        min_similarity: float = 0.0,
    ) -> list[SimilarPostmortemMatch]:
        """Embed a natural-language query and search postmortems via pgvector cosine distance."""
        cleaned_query = query.strip()
        if not cleaned_query:
            raise ValidationError("Search query must not be empty.")

        query_embedding = await self._embedder.embed_text(cleaned_query)
        bounded_limit = max(1, min(limit, 25))
        bounded_min_sim = max(-1.0, min(min_similarity, 1.0))

        async with self._uow_factory(principal) as uow:
            return await uow.postmortems.search_similar(
                query_embedding=query_embedding,
                service_name=service_name,
                limit=bounded_limit,
                min_similarity=bounded_min_sim,
            )

    def issue_step_approval_token(
        self,
        *,
        incident_id: UUID,
        runbook_slug: str,
        step_number: int,
        principal: AuthPrincipal,
    ) -> tuple[str, object]:
        """Issue a signed confirmation token bound to actor, incident, runbook, and step."""
        return self._approval_signer.issue(
            incident_id=incident_id,
            runbook_slug=runbook_slug.strip().lower(),
            step_number=step_number,
            actor_id=principal.user_id,
        )

    async def record_declined_step(
        self,
        *,
        incident_id: UUID,
        runbook_slug: str,
        step_number: int,
        principal: AuthPrincipal,
        reason: str,
    ) -> None:
        """Record an operator cancellation/denial in the immutable audit log."""
        async with self._uow_factory(principal) as uow:
            await uow.events.append(
                incident_id=incident_id,
                event_type="runbook_step_declined",
                actor_id=principal.user_id,
                actor_type=principal.actor_type,
                payload={
                    "runbook_slug": runbook_slug,
                    "step_number": step_number,
                    "reason": reason,
                },
            )
            await uow.commit()

    async def execute_runbook_step(
        self,
        *,
        incident_id: UUID,
        runbook_slug: str,
        step_number: int,
        principal: AuthPrincipal,
        approval_token: str | None = None,
        justification: str | None = None,
    ) -> RunbookStepExecutionResult:
        """Execute a runbook step, enforcing HITL confirmation for high-risk steps."""
        normalized_slug = runbook_slug.strip().lower()
        async with self._uow_factory(principal) as uow:
            incident = await uow.incidents.get_by_id(incident_id)
            if incident is None:
                raise NotFoundError(f"Incident '{incident_id}' not found.")

            runbook = await uow.runbooks.get_by_slug(normalized_slug)
            if runbook is None:
                raise NotFoundError(f"Runbook '{normalized_slug}' not found.")

            step = _find_step(runbook, step_number)
            needs_gate = step.requires_approval or step.risk_level in {
                StepRiskLevel.HIGH,
                StepRiskLevel.CRITICAL,
            }

            if needs_gate and not approval_token:
                token, expires_at = self._approval_signer.issue(
                    incident_id=incident_id,
                    runbook_slug=normalized_slug,
                    step_number=step.step_number,
                    actor_id=principal.user_id,
                )
                event = await uow.events.append(
                    incident_id=incident_id,
                    event_type="runbook_approval_requested",
                    actor_id=principal.user_id,
                    actor_type=principal.actor_type,
                    payload={
                        "runbook_slug": normalized_slug,
                        "step_number": step.step_number,
                        "risk_level": step.risk_level.value,
                    },
                )
                await uow.commit()
                challenge = ApprovalChallenge(
                    status="confirmation_required",
                    incident_id=incident_id,
                    runbook_slug=normalized_slug,
                    step=step,
                    approval_token=token,
                    expires_at=expires_at,
                    instructions=(
                        "Human confirmation required before executing this step. "
                        "Review blast_radius and re-invoke execute_runbook_step with "
                        "the provided approval_token and an optional justification."
                    ),
                )
                return RunbookStepExecutionResult(
                    status="confirmation_required",
                    incident_id=incident_id,
                    runbook_slug=normalized_slug,
                    step=step,
                    event_id=event.id,
                    challenge=challenge,
                    output_summary="Awaiting human confirmation via approval_token.",
                )

            token_jti: str | None = None
            if needs_gate and approval_token:
                token_jti = self._approval_signer.verify(
                    approval_token,
                    incident_id=incident_id,
                    runbook_slug=normalized_slug,
                    step_number=step.step_number,
                    actor_id=principal.user_id,
                )
                if await uow.events.is_approval_jti_consumed(token_jti):
                    raise InvalidApprovalTokenError(
                        "Approval token has already been used."
                    )

            payload: dict[str, object] = {
                "runbook_slug": normalized_slug,
                "step_number": step.step_number,
                "step_title": step.title,
                "risk_level": step.risk_level.value,
                "command_template": step.command_template,
                "justification": (justification or "").strip() or None,
            }
            if token_jti is not None:
                payload["token_jti"] = token_jti

            event = await uow.events.append(
                incident_id=incident_id,
                event_type="runbook_step_executed",
                actor_id=principal.user_id,
                actor_type=principal.actor_type,
                payload=payload,
            )
            await uow.commit()
            return RunbookStepExecutionResult(
                status="executed",
                incident_id=incident_id,
                runbook_slug=normalized_slug,
                step=step,
                event_id=event.id,
                output_summary=(
                    f"Recorded execution of step {step.step_number} ('{step.title}') "
                    f"for incident '{incident_id}'."
                ),
            )


def _find_step(runbook: Runbook, step_number: int) -> RunbookStep:
    for step in runbook.steps:
        if step.step_number == step_number:
            return step
    raise NotFoundError(
        f"Step {step_number} not found in runbook '{runbook.slug}'."
    )
