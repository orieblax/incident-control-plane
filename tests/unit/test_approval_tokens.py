"""Unit tests for stateless HMAC approval tokens."""

from __future__ import annotations

from uuid import uuid4

import pytest

from src.domain.exceptions import InvalidApprovalTokenError
from src.infrastructure.security.approval_tokens import HmacApprovalSigner


def test_issue_and_verify_approval_token() -> None:
    signer = HmacApprovalSigner(secret="super-secret-signing-key", ttl_seconds=300)
    incident_id = uuid4()
    actor_id = uuid4()

    token, expires_at = signer.issue(
        incident_id=incident_id,
        runbook_slug="db-pool-exhaustion",
        step_number=2,
        actor_id=actor_id,
    )
    assert expires_at is not None

    jti = signer.verify(
        token,
        incident_id=incident_id,
        runbook_slug="db-pool-exhaustion",
        step_number=2,
        actor_id=actor_id,
    )
    assert isinstance(jti, str) and len(jti) > 10


def test_tampered_or_mismatched_token_fails() -> None:
    signer = HmacApprovalSigner(secret="super-secret-signing-key", ttl_seconds=300)
    incident_id = uuid4()
    actor_id = uuid4()
    token, _ = signer.issue(
        incident_id=incident_id,
        runbook_slug="db-pool-exhaustion",
        step_number=2,
        actor_id=actor_id,
    )

    with pytest.raises(InvalidApprovalTokenError):
        signer.verify(
            token + "tamper",
            incident_id=incident_id,
            runbook_slug="db-pool-exhaustion",
            step_number=2,
            actor_id=actor_id,
        )

    with pytest.raises(InvalidApprovalTokenError):
        signer.verify(
            token,
            incident_id=uuid4(),
            runbook_slug="db-pool-exhaustion",
            step_number=2,
            actor_id=actor_id,
        )

    with pytest.raises(InvalidApprovalTokenError):
        signer.verify(
            token,
            incident_id=incident_id,
            runbook_slug="db-pool-exhaustion",
            step_number=3,
            actor_id=actor_id,
        )

    with pytest.raises(InvalidApprovalTokenError):
        signer.verify(
            token,
            incident_id=incident_id,
            runbook_slug="db-pool-exhaustion",
            step_number=2,
            actor_id=uuid4(),
        )


def test_expired_token_fails() -> None:
    signer = HmacApprovalSigner(secret="super-secret-signing-key", ttl_seconds=-10)
    incident_id = uuid4()
    actor_id = uuid4()
    token, _ = signer.issue(
        incident_id=incident_id,
        runbook_slug="db-pool-exhaustion",
        step_number=1,
        actor_id=actor_id,
    )
    with pytest.raises(InvalidApprovalTokenError, match="expired"):
        signer.verify(
            token,
            incident_id=incident_id,
            runbook_slug="db-pool-exhaustion",
            step_number=1,
            actor_id=actor_id,
        )
