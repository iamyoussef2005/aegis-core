"""Category 1 Tests: Application startup, routing table, OpenAPI schema, and health."""

from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app
from app.schemas.health import HealthResponse


def test_application_imports_and_creates() -> None:
    """Verify application factory instantiates without errors."""
    app = create_app()
    assert isinstance(app, FastAPI)
    assert app.title == "AEGIS-CORE"


def test_fastapi_routes_registered(test_app: FastAPI) -> None:
    """Verify all versioned API routes are registered in the FastAPI routing table."""
    openapi_paths = set(test_app.openapi()["paths"].keys())
    top_level_paths = {
        route.path for route in test_app.routes if hasattr(route, "path")
    }

    # System routes
    assert "/" in top_level_paths
    assert "/api/v1/health" in openapi_paths

    # User and mock email routes
    assert "/api/v1/users" in openapi_paths
    assert "/api/v1/users/{user_id}/emails" in openapi_paths
    assert "/api/v1/users/{user_id}/emails/count" in openapi_paths
    assert "/api/v1/users/{user_id}/emails/recent" in openapi_paths
    assert "/api/v1/users/{user_id}/emails/{email_id}" in openapi_paths


def test_openapi_schema_generation(test_app: FastAPI) -> None:
    """Verify OpenAPI 3.x schema can be generated dynamically and contains required endpoints."""
    openapi_schema = test_app.openapi()
    assert openapi_schema is not None
    assert "openapi" in openapi_schema
    assert openapi_schema["info"]["title"] == "AEGIS-CORE-TEST"
    assert "paths" in openapi_schema

    paths = openapi_schema["paths"]
    assert "/api/v1/health" in paths
    assert "/api/v1/users" in paths
    assert "/api/v1/users/{user_id}/emails" in paths
    assert "/api/v1/users/{user_id}/emails/count" in paths
    assert "/api/v1/users/{user_id}/emails/recent" in paths
    assert "/api/v1/users/{user_id}/emails/{email_id}" in paths


def test_health_endpoint_healthy_state(sync_client: TestClient) -> None:
    """Verify health endpoint returns 200 OK and validates with HealthResponse schema."""
    response = sync_client.get("/api/v1/health")
    assert response.status_code == 200

    payload = response.json()
    validated = HealthResponse.model_validate(payload)
    assert validated.status == "healthy"
    assert validated.database.status == "healthy"
    assert validated.database.dialect == "sqlite"


def test_health_endpoint_unhealthy_state_returns_503(
    test_app: FastAPI, test_settings: Settings
) -> None:
    """Verify health endpoint returns 503 Service Unavailable when subsystem status is unhealthy."""
    from datetime import UTC, datetime

    from app.schemas.health import DatabaseHealth

    unhealthy_response = HealthResponse(
        status="unhealthy",
        project=test_settings.PROJECT_NAME,
        version=test_settings.VERSION,
        environment=test_settings.ENVIRONMENT,
        timestamp=datetime.now(UTC),
        uptime_seconds=10.0,
        database=DatabaseHealth(status="unhealthy", dialect="sqlite"),
        components={"firewall_engine": "error"},
    )

    with (
        patch(
            "app.api.v1.routes.health.evaluate_system_health",
            return_value=unhealthy_response,
        ),
        TestClient(test_app) as client,
    ):
        response = client.get("/api/v1/health")
        assert response.status_code == 503
        assert response.json()["status"] == "unhealthy"
