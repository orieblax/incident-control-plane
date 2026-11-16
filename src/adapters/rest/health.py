"""Platform liveness and readiness endpoints."""

from __future__ import annotations

from fastapi import APIRouter, status
from fastapi.responses import JSONResponse

from src.adapters.rest.dependencies import ContainerDep

router = APIRouter(tags=["Platform Operations"])


@router.get("/healthz", operation_id="liveness_probe")
async def liveness_probe(container: ContainerDep) -> dict[str, object]:
    """Liveness probe confirming ASGI process and MCP transport configuration."""
    return {
        "status": "alive",
        "environment": container.settings.environment,
        "mcp_stateless_http": container.settings.mcp_stateless_http,
    }


@router.get("/readyz", operation_id="readiness_probe")
async def readiness_probe(container: ContainerDep) -> JSONResponse:
    """Readiness probe verifying Supavisor/PostgreSQL connectivity."""
    if container.db_manager is None or not container.db_manager.is_configured:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "not_ready", "detail": "DATABASE_URL is not configured."},
        )
    try:
        await container.db_manager.check_health()
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"status": "ready", "dependencies": {"postgres": "ok"}},
        )
    except Exception as exc:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "not_ready", "detail": str(exc)},
        )
