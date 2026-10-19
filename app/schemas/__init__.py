"""Pydantic request and response schemas for AEGIS-CORE."""

from app.schemas.health import DatabaseHealth, HealthResponse

__all__ = ["DatabaseHealth", "HealthResponse"]
