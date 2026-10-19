"""Startup smoke test for AEGIS-CORE.

Verifies end-to-end server initialization, lifespan event handlers, database
creation, and HTTP health check resolution.
"""

import sys

from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.main import app


def run_smoke_test() -> int:
    """Execute smoke test against FastAPI application."""
    print("=" * 60)
    print("AEGIS-CORE Smoke Test Starting...")
    print("=" * 60)

    settings = get_settings()
    print(f"Project:     {settings.PROJECT_NAME}")
    print(f"Version:     {settings.VERSION}")
    print(f"Environment: {settings.ENVIRONMENT}")
    print(f"Database:    {settings.DATABASE_URL}")

    with TestClient(app) as client:
        # Test 1: Service Root
        root_res = client.get("/")
        print(f"\n[Test 1] GET / -> Status {root_res.status_code}")
        if root_res.status_code != 200:
            print("FAILED: Expected status 200 for root endpoint")
            return 1
        print(f"Payload: {root_res.json()}")

        # Test 2: GET /api/v1/health
        health_res = client.get("/api/v1/health")
        print(f"\n[Test 2] GET /api/v1/health -> Status {health_res.status_code}")
        if health_res.status_code != 200:
            print("FAILED: Expected status 200 for health endpoint")
            return 1

        health_data = health_res.json()
        print(f"Payload: {health_data}")

        # Assert key attributes
        assert health_data["status"] == "healthy", (
            f"Unexpected status: {health_data['status']}"
        )
        assert health_data["database"]["status"] == "healthy", (
            "Database reported unhealthy"
        )
        assert "x-correlation-id" in health_res.headers, (
            "Missing X-Correlation-ID header"
        )
        assert "x-response-time-ms" in health_res.headers, (
            "Missing X-Response-Time-MS header"
        )
        print(f"Correlation ID Header: {health_res.headers['x-correlation-id']}")
        print(f"Response Time Header:   {health_res.headers['x-response-time-ms']} ms")

    print("\n" + "=" * 60)
    print("ALL SMOKE CHECKS PASSED SUCCESSFULLY!")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(run_smoke_test())
