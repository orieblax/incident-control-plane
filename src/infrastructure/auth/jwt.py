"""Supabase Auth JWT verification supporting JWKS (ES256/RS256) and HS256."""

from __future__ import annotations

import asyncio
import secrets
from typing import Any
from uuid import UUID

import jwt
from jwt import InvalidTokenError, PyJWKClient

from src.domain.exceptions import AuthorizationError
from src.domain.models import ActorType, AuthPrincipal
from src.infrastructure.config import Settings

SERVICE_PRINCIPAL_ID = UUID("00000000-0000-4000-8000-000000000001")
ASYMMETRIC_ALGORITHMS = frozenset({"ES256", "RS256", "EdDSA"})


class SupabaseJwtVerifier:
    """Verify Supabase user JWTs via JWKS or JWT secret, plus optional service bearer token."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._supabase_url = settings.supabase_url.strip().rstrip("/")
        self._issuer = f"{self._supabase_url}/auth/v1" if self._supabase_url else None
        self._jwks_url = (
            f"{self._issuer}/.well-known/jwks.json" if self._issuer else None
        )
        self._jwk_client: PyJWKClient | None = (
            PyJWKClient(self._jwks_url, cache_jwk_set=True, lifespan=300)
            if self._jwks_url
            else None
        )

    async def verify(
        self,
        token: str,
        *,
        default_actor_type: ActorType = ActorType.HUMAN,
    ) -> AuthPrincipal:
        """Validate bearer token and return a verified AuthPrincipal."""
        cleaned = token.strip()
        if not cleaned:
            raise AuthorizationError("Missing bearer token.")

        service_token = self._settings.mcp_service_token.strip()
        if service_token and secrets.compare_digest(cleaned, service_token):
            return AuthPrincipal(
                user_id=SERVICE_PRINCIPAL_ID,
                email="mcp-service@control-plane.local",
                role="authenticated",
                actor_type=ActorType.MCP_AGENT,
                scopes=("incidents:read", "incidents:write", "runbooks:execute"),
                raw_claims={"service_account": True},
            )

        try:
            header = jwt.get_unverified_header(cleaned)
        except InvalidTokenError as exc:
            raise AuthorizationError("Malformed JWT header.") from exc

        alg = str(header.get("alg") or "")
        payload = await self._decode_jwt(cleaned, alg)
        return _principal_from_claims(payload, default_actor_type=default_actor_type)

    async def _decode_jwt(self, token: str, alg: str) -> dict[str, Any]:
        decode_kwargs: dict[str, Any] = {
            "audience": self._settings.supabase_jwt_audience,
            "options": {"require": ["exp", "sub"]},
        }
        if self._issuer:
            decode_kwargs["issuer"] = self._issuer

        if alg in ASYMMETRIC_ALGORITHMS:
            if self._jwk_client is None:
                raise AuthorizationError(
                    "SUPABASE_URL is required to verify asymmetric Supabase JWTs."
                )
            try:
                signing_key = await asyncio.to_thread(
                    self._jwk_client.get_signing_key_from_jwt, token
                )
                return jwt.decode(
                    token,
                    signing_key.key,
                    algorithms=[alg],
                    **decode_kwargs,
                )
            except Exception as exc:
                raise AuthorizationError("Invalid or expired Supabase JWT.") from exc

        if alg == "HS256":
            secret = self._settings.supabase_jwt_secret.strip()
            if not secret:
                raise AuthorizationError(
                    "SUPABASE_JWT_SECRET is required to verify HS256 JWTs."
                )
            try:
                return jwt.decode(
                    token,
                    secret,
                    algorithms=["HS256"],
                    **decode_kwargs,
                )
            except InvalidTokenError as exc:
                raise AuthorizationError("Invalid or expired HS256 JWT.") from exc

        raise AuthorizationError(f"Unsupported JWT signing algorithm '{alg}'.")


def _principal_from_claims(
    claims: dict[str, Any],
    *,
    default_actor_type: ActorType,
) -> AuthPrincipal:
    try:
        user_id = UUID(str(claims["sub"]))
    except (KeyError, ValueError) as exc:
        raise AuthorizationError("JWT 'sub' claim must be a valid UUID.") from exc

    # Security rule: never trust user_metadata for authorization decisions.
    app_metadata = claims.get("app_metadata")
    scopes: list[str] = ["incidents:read", "incidents:write", "runbooks:execute"]
    if isinstance(app_metadata, dict) and isinstance(app_metadata.get("scopes"), list):
        scopes = [str(s) for s in app_metadata["scopes"]]

    role = str(claims.get("role") or "authenticated")
    email = claims.get("email")
    exp = claims.get("exp")

    return AuthPrincipal(
        user_id=user_id,
        email=str(email) if email is not None else None,
        role=role,
        actor_type=default_actor_type,
        scopes=tuple(scopes),
        expires_at=int(exp) if isinstance(exp, int | float) else None,
        raw_claims={
            k: v
            for k, v in claims.items()
            if k in {"sub", "role", "aud", "iss", "email", "client_id", "session_id"}
        },
    )
