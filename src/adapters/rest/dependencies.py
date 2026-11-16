"""FastAPI dependencies and request authentication helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from src.domain.exceptions import AuthorizationError
from src.domain.models import ActorType, AuthPrincipal
from src.infrastructure.auth.jwt import SupabaseJwtVerifier
from src.infrastructure.config import Settings
from src.infrastructure.db.engine import DatabaseManager
from src.services.incident_service import IncidentService
from src.services.runbook_service import RunbookService

_bearer_scheme = HTTPBearer(auto_error=False)


@dataclass(slots=True)
class AppContainer:
    """Dependency container shared across REST and MCP adapters."""

    settings: Settings
    db_manager: DatabaseManager | None
    jwt_verifier: SupabaseJwtVerifier
    incident_service: IncidentService
    runbook_service: RunbookService


def get_container(request: Request) -> AppContainer:
    """Resolve AppContainer from FastAPI application state."""
    container: AppContainer | None = getattr(request.app.state, "container", None)
    if container is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Application container is not initialized.",
        )
    return container


ContainerDep = Annotated[AppContainer, Depends(get_container)]


async def get_current_principal(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)
    ],
    container: ContainerDep,
) -> AuthPrincipal:
    """Authenticate Bearer JWT and extract verified AuthPrincipal."""
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        return await container.jwt_verifier.verify(
            credentials.credentials,
            default_actor_type=ActorType.HUMAN,
        )
    except AuthorizationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


CurrentPrincipal = Annotated[AuthPrincipal, Depends(get_current_principal)]
