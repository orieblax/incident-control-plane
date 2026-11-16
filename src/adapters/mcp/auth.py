"""FastMCP Bearer JWT authentication & Supabase OAuth provider integration."""

from __future__ import annotations

from uuid import UUID

from fastmcp.server.auth import AccessToken, AuthProvider, TokenVerifier
from fastmcp.server.auth.providers.supabase import SupabaseProvider
from fastmcp.server.dependencies import get_access_token

from src.domain.exceptions import AuthorizationError
from src.domain.models import ActorType, AuthPrincipal
from src.infrastructure.auth.jwt import SupabaseJwtVerifier
from src.infrastructure.config import Settings


class SupabaseTokenVerifier(TokenVerifier):
    """FastMCP TokenVerifier delegating JWT/service-token validation to SupabaseJwtVerifier."""

    def __init__(self, jwt_verifier: SupabaseJwtVerifier) -> None:
        super().__init__()
        self._jwt_verifier = jwt_verifier

    async def verify_token(self, token: str) -> AccessToken | None:
        """Verify incoming MCP Bearer token and return FastMCP AccessToken."""
        try:
            principal = await self._jwt_verifier.verify(
                token,
                default_actor_type=ActorType.MCP_AGENT,
            )
        except AuthorizationError:
            return None

        return AccessToken(
            token=token,
            client_id=str(principal.user_id),
            scopes=list(principal.scopes),
            expires_at=principal.expires_at,
            subject=str(principal.user_id),
            claims=principal.to_claims_dict(),
        )


def build_mcp_auth_provider(
    settings: Settings,
    jwt_verifier: SupabaseJwtVerifier,
) -> AuthProvider:
    """Build either SupabaseProvider (with OAuth DCR metadata) or TokenVerifier."""
    verifier = SupabaseTokenVerifier(jwt_verifier)
    if settings.enable_mcp_oauth_discovery and settings.supabase_url.strip():
        return SupabaseProvider(
            project_url=settings.supabase_url.strip(),
            base_url=settings.app_base_url.strip(),
            token_verifier=verifier,
        )
    return verifier


def principal_from_mcp_context() -> AuthPrincipal:
    """Extract verified AuthPrincipal from the current FastMCP request context."""
    access_token = get_access_token()
    if access_token is None or not access_token.subject:
        raise AuthorizationError("Authenticated MCP bearer token is required.")

    claims = dict(access_token.claims or {})
    return AuthPrincipal(
        user_id=UUID(access_token.subject),
        email=str(claims["email"]) if claims.get("email") else None,
        role=str(claims.get("role") or "authenticated"),
        actor_type=ActorType.MCP_AGENT,
        scopes=tuple(access_token.scopes),
        expires_at=access_token.expires_at,
        raw_claims=claims,
    )
