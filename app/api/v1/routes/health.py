"""Health check and diagnostic route handlers."""

from typing import Annotated

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.db.session import get_db
from app.schemas.health import HealthResponse
from app.services.health import evaluate_system_health

router = APIRouter()


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Service health inspection",
    description="Inspects operational health of AEGIS-CORE, service uptime, and database connectivity.",
)
def get_health(
    response: Response,
    session: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> HealthResponse:
    """Return structured JSON describing system health and subsystem availability."""
    health_status = evaluate_system_health(session=session, settings=settings)
    if health_status.status == "unhealthy":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return health_status
