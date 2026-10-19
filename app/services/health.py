"""Health evaluation service for inspecting AEGIS-CORE runtime readiness."""

import time
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.db.session import check_db_health
from app.schemas.health import DatabaseHealth, HealthResponse

# Recorded application initialization monotonic timestamp
_START_TIME: float = time.time()


def set_start_time(start_timestamp: float) -> None:
    """Set or reset service start time (used during lifespan startup or testing)."""
    global _START_TIME
    _START_TIME = start_timestamp


def get_uptime_seconds() -> float:
    """Calculate elapsed uptime in seconds."""
    return round(time.time() - _START_TIME, 2)


def evaluate_system_health(session: Session, settings: Settings) -> HealthResponse:
    """Inspect core dependencies and return structured system diagnostics."""
    db_ok = check_db_health(session)

    status = "healthy" if db_ok else "degraded"
    db_status = "healthy" if db_ok else "unhealthy"

    return HealthResponse(
        status=status,
        project=settings.PROJECT_NAME,
        version=settings.VERSION,
        environment=settings.ENVIRONMENT,
        timestamp=datetime.now(UTC),
        uptime_seconds=get_uptime_seconds(),
        database=DatabaseHealth(
            status=db_status,
            dialect=session.bind.dialect.name if session.bind else "sqlite",
        ),
        components={
            "firewall_engine": "standby",
            "provenance_tracker": "standby",
            "policy_enforcer": "standby",
        },
    )
