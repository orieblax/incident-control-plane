"""Stateless HMAC-signed HITL confirmation tokens for serverless MCP execution."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from uuid import UUID

from src.domain.exceptions import InvalidApprovalTokenError


class LazyApprovalSigner:
    """Defer secret resolution until token issuance/verification so ASGI import stays safe."""

    def __init__(self, secret_provider: Callable[[], str], ttl_seconds: int = 600) -> None:
        self._secret_provider = secret_provider
        self._ttl_seconds = ttl_seconds

    def _signer(self) -> HmacApprovalSigner:
        return HmacApprovalSigner(
            secret=self._secret_provider(),
            ttl_seconds=self._ttl_seconds,
        )

    def issue(
        self,
        *,
        incident_id: UUID,
        runbook_slug: str,
        step_number: int,
        actor_id: UUID,
    ) -> tuple[str, datetime]:
        """Issue a signed confirmation token."""
        return self._signer().issue(
            incident_id=incident_id,
            runbook_slug=runbook_slug,
            step_number=step_number,
            actor_id=actor_id,
        )

    def verify(
        self,
        token: str,
        *,
        incident_id: UUID,
        runbook_slug: str,
        step_number: int,
        actor_id: UUID,
    ) -> str:
        """Verify a signed confirmation token."""
        return self._signer().verify(
            token,
            incident_id=incident_id,
            runbook_slug=runbook_slug,
            step_number=step_number,
            actor_id=actor_id,
        )


class HmacApprovalSigner:
    """Issue and verify time-bounded, context-bound confirmation tokens."""

    def __init__(self, secret: str, ttl_seconds: int = 600) -> None:
        if not secret:
            raise ValueError("Signing secret must not be empty.")
        self._secret = secret.encode("utf-8")
        self._ttl_seconds = ttl_seconds

    def issue(
        self,
        *,
        incident_id: UUID,
        runbook_slug: str,
        step_number: int,
        actor_id: UUID,
    ) -> tuple[str, datetime]:
        """Mint a signed approval token bound to incident, runbook step, and actor."""
        now = datetime.now(UTC)
        expires_at = now + timedelta(seconds=self._ttl_seconds)
        jti = secrets.token_urlsafe(16)
        claims = {
            "jti": jti,
            "inc": str(incident_id),
            "rb": runbook_slug,
            "step": step_number,
            "sub": str(actor_id),
            "exp": int(expires_at.timestamp()),
        }
        payload_b64 = _b64encode(
            json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8")
        )
        sig_b64 = _b64encode(self._sign(payload_b64.encode("ascii")))
        return f"{payload_b64}.{sig_b64}", expires_at

    def verify(
        self,
        token: str,
        *,
        incident_id: UUID,
        runbook_slug: str,
        step_number: int,
        actor_id: UUID,
    ) -> str:
        """Verify signature, TTL, and exact step binding; return unique token JTI."""
        parts = token.strip().split(".")
        if len(parts) != 2:
            raise InvalidApprovalTokenError("Malformed approval token.")

        payload_b64, sig_b64 = parts
        expected_sig = _b64encode(self._sign(payload_b64.encode("ascii")))
        if not hmac.compare_digest(sig_b64, expected_sig):
            raise InvalidApprovalTokenError("Invalid approval token signature.")

        try:
            claims = json.loads(_b64decode(payload_b64).decode("utf-8"))
        except Exception as exc:
            raise InvalidApprovalTokenError("Corrupt approval token payload.") from exc

        now_ts = int(datetime.now(UTC).timestamp())
        if int(claims.get("exp", 0)) < now_ts:
            raise InvalidApprovalTokenError("Approval token has expired.")

        if (
            claims.get("inc") != str(incident_id)
            or claims.get("rb") != runbook_slug
            or claims.get("step") != step_number
            or claims.get("sub") != str(actor_id)
        ):
            raise InvalidApprovalTokenError(
                "Approval token does not match the target incident, runbook step, or caller."
            )

        jti = claims.get("jti")
        if not isinstance(jti, str) or not jti:
            raise InvalidApprovalTokenError("Approval token missing JTI.")
        return jti

    def _sign(self, message: bytes) -> bytes:
        return hmac.new(self._secret, message, hashlib.sha256).digest()


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)
