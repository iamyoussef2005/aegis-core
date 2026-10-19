"""Category 6 Tests: Edge cases, boundary values, empty states, and malformed inputs."""

from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.email_message import EmailMessage
from app.models.user import User
from scripts.seed_mock_data import seed_mock_data


def test_empty_inbox_behavior(sync_client: TestClient, empty_user: User) -> None:
    """Verify behavior when a user exists but has zero emails in their inbox."""
    user_id = empty_user.id

    # 1. List emails
    res_list = sync_client.get(f"/api/v1/users/{user_id}/emails")
    assert res_list.status_code == 200
    data_list = res_list.json()
    assert data_list["owner_id"] == user_id
    assert data_list["total"] == 0
    assert data_list["items"] == []

    # 2. Count emails
    res_count = sync_client.get(f"/api/v1/users/{user_id}/emails/count")
    assert res_count.status_code == 200
    data_count = res_count.json()
    assert data_count["owner_id"] == user_id
    assert data_count["count"] == 0

    # 3. Recent emails
    res_recent = sync_client.get(f"/api/v1/users/{user_id}/emails/recent")
    assert res_recent.status_code == 200
    assert res_recent.json() == []


def test_invalid_path_parameter_types_return_422(
    sync_client: TestClient,
) -> None:
    """Verify non-integer path parameters trigger Pydantic validation errors (422)."""
    # Non-integer user_id
    res_user = sync_client.get("/api/v1/users/not-an-integer/emails")
    assert res_user.status_code == 422

    # Non-integer email_id
    res_email = sync_client.get("/api/v1/users/1/emails/not-an-integer")
    assert res_email.status_code == 422


def test_negative_id_returns_404(
    sync_client: TestClient,
) -> None:
    """Verify negative integer IDs return 404 rather than 500 error."""
    res = sync_client.get("/api/v1/users/-1/emails")
    assert res.status_code == 404
    assert "not found" in res.json()["detail"]


def test_boundary_limit_and_offset_values(
    sync_client: TestClient, seeded_session: Session
) -> None:
    """Verify minimum and maximum permissible limits and counts."""
    # Min boundary: limit=1
    res_min_limit = sync_client.get("/api/v1/users/1/emails?limit=1")
    assert res_min_limit.status_code == 200
    assert len(res_min_limit.json()["items"]) == 1

    # Max boundary: limit=100
    res_max_limit = sync_client.get("/api/v1/users/1/emails?limit=100")
    assert res_max_limit.status_code == 200
    assert len(res_max_limit.json()["items"]) == 10

    # Min count boundary: count=1
    res_min_count = sync_client.get("/api/v1/users/1/emails/recent?count=1")
    assert res_min_count.status_code == 200
    assert len(res_min_count.json()) == 1

    # Max count boundary: count=10
    res_max_count = sync_client.get("/api/v1/users/1/emails/recent?count=10")
    assert res_max_count.status_code == 200
    assert len(res_max_count.json()) == 10


def test_malformed_query_parameters_return_422(
    sync_client: TestClient,
) -> None:
    """Verify malformed query parameter values return 422."""
    test_cases = [
        "/api/v1/users/1/emails?limit=0",
        "/api/v1/users/1/emails?limit=101",
        "/api/v1/users/1/emails?limit=invalid_number",
        "/api/v1/users/1/emails?offset=-1",
        "/api/v1/users/1/emails?offset=abc",
        "/api/v1/users/1/emails?is_read=notabool",
        "/api/v1/users/1/emails/recent?count=0",
        "/api/v1/users/1/emails/recent?count=11",
        "/api/v1/users/1/emails/recent?count=abc",
        "/api/v1/users/1/emails/count?is_read=invalid",
    ]
    for url in test_cases:
        res = sync_client.get(url)
        assert res.status_code == 422, f"Expected 422 for {url}, got {res.status_code}"


def test_rich_unicode_and_emojis_storage_and_retrieval(
    sync_client: TestClient, db_session: Session
) -> None:
    """Verify rich unicode strings including emojis, math symbols, and mixed RTL/LTR are supported."""
    user = User(
        display_name="الباحث 🤖 Dr. Tariq",
        email="unicode.test@university.edu.sa",
        created_at=datetime.now(UTC),
    )
    db_session.add(user)
    db_session.flush()

    rich_email = EmailMessage(
        owner_id=user.id,
        sender="arabic.sender@university.edu.sa",
        recipient=user.email,
        subject="🔐 أمان النماذج اللغوية (Safety α & β): 100% نجاح",
        body="مرحباً د. طارق 👋\n\nنود إعلامكم بأن معادلة الأمان: ∀x ∈ S : P(x) = 1.0\nمع خالص التحية.",
        received_at=datetime(2026, 10, 15, 12, 0, tzinfo=UTC),
    )
    db_session.add(rich_email)
    db_session.commit()

    # Query via API
    response = sync_client.get(f"/api/v1/users/{user.id}/emails/{rich_email.id}")
    assert response.status_code == 200
    data = response.json()
    assert "🔐 أمان النماذج اللغوية" in data["subject"]
    assert "👋" in data["body"]
    assert "∀x ∈ S" in data["body"]


def test_duplicate_seed_execution_invariance(
    db_session: Session,
) -> None:
    """Verify that multiple consecutive seed executions preserve exact table row invariants."""
    stats1 = seed_mock_data(db_session)
    assert stats1["users_created"] == 3
    assert stats1["emails_created"] == 30

    stats2 = seed_mock_data(db_session)
    assert stats2["users_created"] == 0
    assert stats2["emails_created"] == 0
    assert stats2["users_skipped"] == 3
    assert stats2["emails_skipped"] == 30

    stats3 = seed_mock_data(db_session)
    assert stats3["users_created"] == 0
    assert stats3["emails_created"] == 0
    assert stats3["users_skipped"] == 3
    assert stats3["emails_skipped"] == 30


def test_sequential_api_calls_consistency(
    sync_client: TestClient, seeded_session: Session
) -> None:
    """Verify rapid sequential API requests do not leak connections or mutate state."""
    for _ in range(5):
        res1 = sync_client.get("/api/v1/users/1/emails/count")
        assert res1.status_code == 200
        assert res1.json()["count"] == 10

        res2 = sync_client.get("/api/v1/users/1/emails?limit=2")
        assert res2.status_code == 200
        assert len(res2.json()["items"]) == 2
