"""Unit tests for Supavisor SQLAlchemy configuration and JWT verification."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
import pytest
from sqlalchemy.pool import NullPool

from src.domain.exceptions import AuthorizationError
from src.infrastructure.auth.jwt import SERVICE_PRINCIPAL_ID, SupabaseJwtVerifier
from src.infrastructure.config import Settings
from src.infrastructure.db.engine import build_async_engine


def test_supavisor_url_normalization_and_null_pool() -> None:
    settings = Settings(
        database_url=(
            "postgres://postgres.projref:secret@"
            "aws-0-us-east-1.pooler.supabase.com:6543/postgres?sslmode=require&pgbouncer=true"
        ),
        environment="test",
    )
    clean_url, connect_args = settings.parsed_asyncpg_target()
    assert clean_url.startswith("postgresql+asyncpg://")
    assert "sslmode=" not in clean_url
    assert "pgbouncer=" not in clean_url
    assert connect_args["statement_cache_size"] == 0
    assert connect_args["prepared_statement_cache_size"] == 0
    assert connect_args["ssl"] == "require"

    engine = build_async_engine(settings)
    assert engine is not None
    assert isinstance(engine.pool, NullPool)


def test_production_requires_explicit_approval_secret() -> None:
    from src.main import create_app

    settings = Settings(environment="production", approval_signing_secret="")
    # App boots cleanly for /healthz even before secrets are injected
    app = create_app(settings=settings)
    assert app is not None
    with pytest.raises(RuntimeError, match="APPROVAL_SIGNING_SECRET"):
        _ = settings.effective_approval_secret


async def test_jwt_verifier_hs256_ignores_user_metadata_and_accepts_service_token() -> None:
    secret = "test-jwt-secret-with-at-least-32-bytes"
    settings = Settings(
        supabase_url="https://demo.supabase.co",
        supabase_jwt_secret=secret,
        mcp_service_token="scoped-service-token-xyz",
        environment="test",
    )
    verifier = SupabaseJwtVerifier(settings)

    user_id = uuid4()
    token = jwt.encode(
        {
            "sub": str(user_id),
            "aud": "authenticated",
            "iss": "https://demo.supabase.co/auth/v1",
            "role": "authenticated",
            "email": "oncall@example.com",
            "user_metadata": {"scopes": ["superadmin"]},
            "app_metadata": {"scopes": ["incidents:read", "incidents:write"]},
            "exp": int((datetime.now(UTC) + timedelta(minutes=10)).timestamp()),
        },
        secret,
        algorithm="HS256",
    )
    principal = await verifier.verify(token)
    assert principal.user_id == user_id
    assert principal.scopes == ("incidents:read", "incidents:write")
    assert "superadmin" not in principal.scopes

    service_principal = await verifier.verify("scoped-service-token-xyz")
    assert service_principal.user_id == SERVICE_PRINCIPAL_ID

    with pytest.raises(AuthorizationError):
        await verifier.verify("invalid.jwt.token")
