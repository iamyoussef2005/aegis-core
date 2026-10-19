"""Test suite for GET /api/v1/health diagnostic endpoint."""

from unittest.mock import patch

import httpx
import pytest
from fastapi.testclient import TestClient

from app.schemas.health import HealthResponse


def test_health_endpoint_sync_client(sync_client: TestClient) -> None:
    """Verify health endpoint via synchronous TestClient."""
    response = sync_client.get("/api/v1/health")
    assert response.status_code == 200

    data = response.json()
    validated = HealthResponse.model_validate(data)

    assert validated.status == "healthy"
    assert validated.project == "AEGIS-CORE-TEST"
    assert validated.version == "0.1.0-test"
    assert validated.environment == "testing"
    assert validated.uptime_seconds >= 0.0
    assert validated.database.status == "healthy"
    assert validated.database.dialect == "sqlite"
    assert "firewall_engine" in validated.components

    # Verify security & provenance headers
    assert "x-correlation-id" in response.headers
    assert "x-response-time-ms" in response.headers
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"


@pytest.mark.asyncio
async def test_health_endpoint_async_client(async_client: httpx.AsyncClient) -> None:
    """Verify health endpoint via asynchronous httpx client."""
    response = await async_client.get("/api/v1/health")
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "healthy"
    assert data["database"]["status"] == "healthy"


def test_health_endpoint_degraded_when_db_fails(sync_client: TestClient) -> None:
    """Verify that when database health check fails, status becomes degraded."""
    with patch("app.services.health.check_db_health", return_value=False):
        response = sync_client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "degraded"
        assert data["database"]["status"] == "unhealthy"


def test_root_endpoint(sync_client: TestClient) -> None:
    """Verify root endpoint returns basic project discovery metadata."""
    response = sync_client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["project"] == "AEGIS-CORE-TEST"
    assert data["health"] == "/api/v1/health"
