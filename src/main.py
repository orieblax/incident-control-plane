"""Unified FastAPI + FastMCP ASGI entrypoint for Vercel Python Functions."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastmcp import FastMCP

from src.adapters.mcp.auth import build_mcp_auth_provider
from src.adapters.mcp.tools import register_incident_tools
from src.adapters.rest.dependencies import AppContainer
from src.adapters.rest.health import router as health_router
from src.adapters.rest.incidents import router as incident_router
from src.adapters.rest.runbooks import router as runbook_router
from src.domain.exceptions import (
    ApprovalRequiredError,
    AuthorizationError,
    InvalidApprovalTokenError,
    InvalidStateTransitionError,
    NotFoundError,
    ValidationError,
)
from src.domain.ports import ApprovalTokenSigner, EmbeddingProvider, UnitOfWorkFactory
from src.infrastructure.auth.jwt import SupabaseJwtVerifier
from src.infrastructure.config import Settings, get_settings
from src.infrastructure.db.engine import DatabaseManager, DatabaseNotConfiguredError
from src.infrastructure.db.repositories import build_uow_factory
from src.infrastructure.embeddings.provider import build_embedding_provider
from src.infrastructure.security.approval_tokens import LazyApprovalSigner
from src.services.incident_service import IncidentService
from src.services.runbook_service import RunbookService


def create_app(
    *,
    settings: Settings | None = None,
    uow_factory: UnitOfWorkFactory | None = None,
    embedder: EmbeddingProvider | None = None,
    jwt_verifier: SupabaseJwtVerifier | None = None,
    approval_signer: ApprovalTokenSigner | None = None,
    db_manager: DatabaseManager | None = None,
) -> FastAPI:
    """Construct the unified FastAPI + FastMCP ASGI application."""
    active_settings = settings or get_settings()
    active_db_manager = (
        db_manager
        if db_manager is not None
        else (DatabaseManager(active_settings) if uow_factory is None else None)
    )
    active_uow_factory = uow_factory or build_uow_factory(active_db_manager)  # type: ignore[arg-type]
    active_embedder = embedder or build_embedding_provider(active_settings)
    active_jwt_verifier = jwt_verifier or SupabaseJwtVerifier(active_settings)
    active_signer = approval_signer or LazyApprovalSigner(
        secret_provider=lambda: active_settings.effective_approval_secret,
        ttl_seconds=active_settings.approval_ttl_seconds,
    )

    incident_service = IncidentService(
        uow_factory=active_uow_factory,
        embedder=active_embedder,
    )
    runbook_service = RunbookService(
        uow_factory=active_uow_factory,
        embedder=active_embedder,
        approval_signer=active_signer,
    )

    mcp_auth = build_mcp_auth_provider(active_settings, active_jwt_verifier)
    mcp = FastMCP(
        name="Incident-Control-Plane",
        instructions=(
            "Dual-Interface Incident and Runbook Control Plane. "
            "Use diagnose_incident and search_similar_postmortems before mutating state. "
            "High-risk runbook steps require HITL confirmation."
        ),
        auth=mcp_auth,
    )
    register_incident_tools(
        mcp,
        incident_service=incident_service,
        runbook_service=runbook_service,
        settings=active_settings,
    )
    mcp_asgi = mcp.http_app(
        path="/mcp",
        stateless_http=active_settings.mcp_stateless_http,
        host_origin_protection=False,
    )

    @asynccontextmanager
    async def combined_lifespan(_app: FastAPI) -> AsyncIterator[None]:
        async with mcp_asgi.lifespan(mcp_asgi):
            try:
                yield
            finally:
                if active_db_manager is not None:
                    await active_db_manager.dispose()

    app = FastAPI(
        title="Incident & Runbook Control Plane",
        version="0.1.0",
        description=(
            "Hexagonal FastAPI + Stateless Streamable HTTP FastMCP server "
            "backed by Supabase PostgreSQL + pgvector."
        ),
        lifespan=combined_lifespan,
    )
    app.state.container = AppContainer(
        settings=active_settings,
        db_manager=active_db_manager,
        jwt_verifier=active_jwt_verifier,
        incident_service=incident_service,
        runbook_service=runbook_service,
    )
    app.state.mcp = mcp

    _register_exception_handlers(app)
    app.include_router(health_router)
    app.include_router(incident_router, prefix="/api/v1")
    app.include_router(runbook_router, prefix="/api/v1")
    app.mount("/", mcp_asgi)
    return app


def _register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(NotFoundError)
    async def handle_not_found(_request: Request, exc: NotFoundError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND, content={"detail": str(exc)}
        )

    @app.exception_handler(InvalidStateTransitionError)
    async def handle_invalid_transition(
        _request: Request, exc: InvalidStateTransitionError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT, content={"detail": str(exc)}
        )

    @app.exception_handler(ValidationError)
    async def handle_validation(_request: Request, exc: ValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"detail": str(exc)},
        )

    @app.exception_handler(ApprovalRequiredError)
    async def handle_approval_required(
        _request: Request, exc: ApprovalRequiredError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT, content={"detail": str(exc)}
        )

    @app.exception_handler(InvalidApprovalTokenError)
    async def handle_invalid_approval(
        _request: Request, exc: InvalidApprovalTokenError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN, content={"detail": str(exc)}
        )

    @app.exception_handler(AuthorizationError)
    async def handle_authorization(
        _request: Request, exc: AuthorizationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": str(exc)},
            headers={"WWW-Authenticate": "Bearer"},
        )

    @app.exception_handler(DatabaseNotConfiguredError)
    async def handle_db_not_configured(
        _request: Request, exc: DatabaseNotConfiguredError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"detail": str(exc)},
        )


app = create_app()
