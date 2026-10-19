"""Startup smoke test for AEGIS-CORE.

Verifies end-to-end server initialization, lifespan event handlers, database
creation, and HTTP resolution for health and mock email endpoints.
"""

import sys

from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.db.session import SessionLocal
from app.main import app
from scripts.seed_mock_data import seed_mock_data


def run_smoke_test() -> int:
    """Execute smoke test against FastAPI application."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    print("=" * 60)
    print("AEGIS-CORE Smoke Test Starting...")
    print("=" * 60)

    settings = get_settings()
    print(f"Project:     {settings.PROJECT_NAME}")
    print(f"Version:     {settings.VERSION}")
    print(f"Environment: {settings.ENVIRONMENT}")
    print(f"Database:    {settings.DATABASE_URL}")

    # Ensure demo data exists for live endpoint verification
    session = SessionLocal()
    try:
        seed_mock_data(session)
    finally:
        session.close()

    with TestClient(app) as client:
        # Test 1: Service Root
        root_res = client.get("/")
        print(f"\n[Test 1] GET / -> Status {root_res.status_code}")
        assert root_res.status_code == 200, "Expected status 200 for root endpoint"
        print(f"Payload: {root_res.json()}")

        # Test 2: GET /api/v1/health
        health_res = client.get("/api/v1/health")
        print(f"\n[Test 2] GET /api/v1/health -> Status {health_res.status_code}")
        assert health_res.status_code == 200, "Expected status 200 for health endpoint"
        health_data = health_res.json()
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

        # Test 3: GET /api/v1/users
        users_res = client.get("/api/v1/users")
        print(f"\n[Test 3] GET /api/v1/users -> Status {users_res.status_code}")
        assert users_res.status_code == 200, "Expected status 200 for users endpoint"
        users = users_res.json()
        assert len(users) == 3, f"Expected 3 demo users, got {len(users)}"
        print(f"Found {len(users)} users: {[u['email'] for u in users]}")

        # Test 4: GET /api/v1/users/1/emails?limit=3
        emails_res = client.get("/api/v1/users/1/emails?limit=3")
        print(
            f"\n[Test 4] GET /api/v1/users/1/emails?limit=3 -> Status {emails_res.status_code}"
        )
        assert emails_res.status_code == 200
        emails_data = emails_res.json()
        assert emails_data["total"] == 10
        assert len(emails_data["items"]) == 3
        print(
            f"User 1 Total Emails: {emails_data['total']} (retrieved {len(emails_data['items'])})"
        )

        # Test 5: GET /api/v1/users/1/emails/count
        count_res = client.get("/api/v1/users/1/emails/count")
        print(
            f"\n[Test 5] GET /api/v1/users/1/emails/count -> Status {count_res.status_code}"
        )
        assert count_res.status_code == 200
        assert count_res.json()["count"] == 10
        print(f"User 1 Verified Count: {count_res.json()['count']}")

        # Test 6: GET /api/v1/users/1/emails/recent?count=2
        recent_res = client.get("/api/v1/users/1/emails/recent?count=2")
        print(
            f"\n[Test 6] GET /api/v1/users/1/emails/recent?count=2 -> Status {recent_res.status_code}"
        )
        assert recent_res.status_code == 200
        recent_data = recent_res.json()
        assert len(recent_data) == 2
        print(f"Recent subjects: {[e['subject'][:30] + '...' for e in recent_data]}")

        # Test 7: Isolation verification (Unknown email returns 404)
        missing_res = client.get("/api/v1/users/1/emails/999999")
        print(
            f"\n[Test 7] GET /api/v1/users/1/emails/999999 -> Status {missing_res.status_code}"
        )
        assert missing_res.status_code == 404
        print(f"Expected 404 response detail: {missing_res.json()['detail']}")

    print("\n" + "=" * 60)
    print("ALL 7 END-TO-END SMOKE CHECKS PASSED SUCCESSFULLY!")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(run_smoke_test())
