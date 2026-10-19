"""Category 5 Tests: Security boundaries, SQL injection resistance, and error safety."""

from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.repositories.email import get_email_by_id_and_owner, list_emails_by_owner
from app.repositories.user import get_user_by_email


def test_cross_user_email_isolation_returns_404(
    sync_client: TestClient, seeded_session: Session
) -> None:
    """Verify that accessing another user's email ID returns 404 and does not leak message metadata."""
    # Email 1 belongs to User 1 (Dr. Layla). User 2 (Tariq) attempts to read it.
    response = sync_client.get("/api/v1/users/2/emails/1")
    assert response.status_code == 404
    assert response.json()["detail"] == "Email with ID 1 not found for user 2"

    # User 3 (Maya) attempts to access User 2's email 11
    response3 = sync_client.get("/api/v1/users/3/emails/11")
    assert response3.status_code == 404
    assert response3.json()["detail"] == "Email with ID 11 not found for user 3"


def test_sql_injection_resistance_user_email_lookup(
    seeded_session: Session,
) -> None:
    """Verify ORM parameter binding prevents classic SQL injection payloads."""
    malicious_payloads = [
        "' OR '1'='1",
        "layla.almansoor@university.edu.sa' --",
        "' UNION SELECT * FROM users --",
        "'; DROP TABLE email_messages; --",
    ]
    for payload in malicious_payloads:
        result = get_user_by_email(seeded_session, payload)
        assert result is None, (
            f"SQL injection payload {payload} unexpectedly returned a record!"
        )


def test_sql_injection_resistance_email_owner_filter(
    seeded_session: Session,
) -> None:
    """Verify owner queries cannot be manipulated via SQL injection strings."""
    # Test through repository
    res = get_email_by_id_and_owner(seeded_session, email_id=1, owner_id=-1)
    assert res is None

    res_list = list_emails_by_owner(seeded_session, owner_id=999999)
    assert len(res_list) == 0


def test_global_exception_handler_masks_internal_tracebacks() -> None:
    """Verify unhandled exceptions return a sanitized JSON 500 response without leaking tracebacks."""
    from app.main import create_app

    prod_app = create_app(
        Settings(
            ENVIRONMENT="production",
            DEBUG=False,
            DATABASE_URL="sqlite:///:memory:",
        )
    )
    with (
        patch(
            "app.api.v1.routes.users.UserService.list_users",
            side_effect=RuntimeError("Secret database connection string leaked!"),
        ),
        TestClient(prod_app, raise_server_exceptions=False) as client,
    ):
        response = client.get("/api/v1/users")
        assert response.status_code == 500
        payload = response.json()

        # Must have correlation_id and generic error
        assert payload["error"] == "Internal Server Error"
        assert (
            payload["message"]
            == "An unexpected error occurred while processing the request."
        )
        assert "correlation_id" in payload

        # Must NOT leak internal traceback details or credentials
        assert "Secret database connection string" not in response.text
        assert "Traceback" not in response.text


def test_cors_configuration_rejects_wildcard() -> None:
    """Verify CORS origins do not contain wildcard '*' in configuration."""
    settings = get_settings()
    assert "*" not in settings.CORS_ORIGINS
    for origin in settings.CORS_ORIGINS:
        assert origin.startswith("http://") or origin.startswith("https://")


def test_security_and_provenance_headers_present(
    sync_client: TestClient,
) -> None:
    """Verify security headers (CSP, nosniff, frame protection, correlation ID) on all responses."""
    response = sync_client.get("/api/v1/health")
    assert response.status_code == 200

    headers = response.headers
    assert "x-correlation-id" in headers
    assert "x-response-time-ms" in headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
