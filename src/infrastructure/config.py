"""Application configuration powered by pydantic-settings."""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import Literal
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    """Runtime settings loaded from environment variables and .env."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # Database
    database_url: str = ""
    direct_database_url: str = ""
    db_enforce_rls_context: bool = True

    # Supabase Auth
    supabase_url: str = ""
    supabase_publishable_key: str = ""
    supabase_jwt_secret: str = ""
    supabase_jwt_audience: str = "authenticated"

    # Embeddings
    embedding_provider: Literal["openai", "ai_gateway", "gemini", "deterministic"] = "openai"
    embedding_api_key: str = ""
    embedding_model: str = "text-embedding-3-small"
    embedding_dimensions: int = Field(default=1536, ge=64, le=2000)
    embedding_base_url: str = "https://api.openai.com/v1"

    # MCP & Security
    mcp_stateless_http: bool = True
    enable_mcp_oauth_discovery: bool = False
    approval_signing_secret: str = ""
    approval_ttl_seconds: int = Field(default=600, ge=30, le=3600)
    mcp_service_token: str = ""
    app_base_url: str = "http://localhost:8000"
    environment: Literal["development", "test", "preview", "production"] = "development"
    log_level: str = "INFO"

    @property
    def has_database(self) -> bool:
        """Return True when DATABASE_URL is configured."""
        return bool(self.database_url.strip())

    def parsed_asyncpg_target(self) -> tuple[str, dict[str, object]]:
        """Normalize DATABASE_URL for SQLAlchemy+asyncpg and extract SSL settings."""
        raw = self.database_url.strip()
        if not raw:
            return "", {}

        if raw.startswith("postgres://"):
            raw = "postgresql+asyncpg://" + raw.removeprefix("postgres://")
        elif raw.startswith("postgresql://"):
            raw = "postgresql+asyncpg://" + raw.removeprefix("postgresql://")

        parsed = urlparse(raw)
        query = parse_qs(parsed.query, keep_blank_values=True)
        sslmode_values = query.pop("sslmode", [])
        # Supavisor transaction mode handles pooling; remove pgbouncer flag if present
        query.pop("pgbouncer", None)

        clean_query = urlencode(query, doseq=True)
        clean_url = urlunparse(parsed._replace(query=clean_query))

        connect_args: dict[str, object] = {
            "statement_cache_size": 0,
            "prepared_statement_cache_size": 0,
        }

        sslmode = sslmode_values[0].lower() if sslmode_values else ""
        host = (parsed.hostname or "").lower()
        if sslmode in {"require", "verify-ca", "verify-full"} or (
            not sslmode and ("supabase.com" in host or "supabase.co" in host)
        ):
            connect_args["ssl"] = "require"

        if parsed.port == 5432 and "pooler.supabase.com" in host:
            logger.warning(
                "DATABASE_URL targets Supavisor session port 5432; port 6543 "
                "(transaction mode) is recommended for Vercel serverless functions."
            )

        return clean_url, connect_args

    @property
    def effective_approval_secret(self) -> str:
        """Return configured signing secret, falling back only outside production."""
        secret = self.approval_signing_secret.strip()
        if secret:
            return secret
        if self.environment == "production":
            raise RuntimeError(
                "APPROVAL_SIGNING_SECRET must be set in production environments."
            )
        return "dev-only-insecure-approval-signing-secret-do-not-use-in-prod"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached application settings."""
    return Settings()
