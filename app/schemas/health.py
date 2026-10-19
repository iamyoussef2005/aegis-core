"""Pydantic v2 schemas for health and system diagnostic responses."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class DatabaseHealth(BaseModel):
    """Database connectivity status schema."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["healthy", "unhealthy"] = Field(
        ...,
        description="Current responsiveness state of the primary database",
        examples=["healthy"],
    )
    dialect: str = Field(
        default="sqlite",
        description="Database dialect / driver",
        examples=["sqlite"],
    )


class HealthResponse(BaseModel):
    """Structured response model for service health inspection."""

    model_config = ConfigDict(
        extra="ignore",
        json_schema_extra={
            "example": {
                "status": "healthy",
                "project": "AEGIS-CORE",
                "version": "0.1.0",
                "environment": "development",
                "timestamp": "2026-10-19T22:30:00Z",
                "uptime_seconds": 12.34,
                "database": {"status": "healthy", "dialect": "sqlite"},
                "components": {
                    "firewall_engine": "standby",
                    "provenance_tracker": "standby",
                },
            }
        },
    )

    status: Literal["healthy", "degraded", "unhealthy"] = Field(
        ...,
        description="Overall service operational health status",
        examples=["healthy"],
    )
    project: str = Field(
        ...,
        description="Service identifier",
        examples=["AEGIS-CORE"],
    )
    version: str = Field(
        ...,
        description="Service semantic release version",
        examples=["0.1.0"],
    )
    environment: str = Field(
        ...,
        description="Current runtime environment",
        examples=["development"],
    )
    timestamp: datetime = Field(
        ...,
        description="UTC timestamp of the health check evaluation",
    )
    uptime_seconds: float = Field(
        ge=0.0,
        description="Elapsed service uptime in seconds",
        examples=[42.5],
    )
    database: DatabaseHealth = Field(
        ...,
        description="Database subsystem status",
    )
    components: dict[str, Any] = Field(
        default_factory=dict,
        description="Status indicators for modular subsystems and future extensions",
    )
