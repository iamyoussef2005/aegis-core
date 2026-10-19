"""Integration test suite for /api/v1/users and /api/v1/users/{user_id}/emails endpoints."""

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from scripts.seed_mock_data import seed_mock_data


def test_get_users_list(sync_client: TestClient, db_session: Session) -> None:
    """Verify GET /api/v1/users lists demo users without exposing sensitive credentials."""
    seed_mock_data(db_session)

    response = sync_client.get("/api/v1/users")
    assert response.status_code == 200
    data = response.json()

    assert isinstance(data, list)
    assert len(data) == 3

    emails = {u["email"] for u in data}
    assert "layla.almansoor@university.edu.sa" in emails
    assert "tariq.alghamdi@student.university.edu.sa" in emails
    assert "maya.chen@student.university.edu.sa" in emails

    for user in data:
        assert "id" in user
        assert "display_name" in user
        assert "email" in user
        assert "password" not in user
        assert "secret" not in user
        assert "token" not in user


def test_get_user_emails_known_user(
    sync_client: TestClient, db_session: Session
) -> None:
    """Verify GET /api/v1/users/{user_id}/emails returns emails for a known user."""
    seed_mock_data(db_session)

    response = sync_client.get("/api/v1/users/1/emails")
    assert response.status_code == 200
    data = response.json()

    assert data["owner_id"] == 1
    assert data["total"] == 10
    assert len(data["items"]) == 10
    assert data["limit"] == 10
    assert data["offset"] == 0

    first_email = data["items"][0]
    assert first_email["owner_id"] == 1
    assert "subject" in first_email
    assert "body" in first_email
    assert "received_at" in first_email


def test_get_user_emails_unknown_user(
    sync_client: TestClient, db_session: Session
) -> None:
    """Verify GET /api/v1/users/{user_id}/emails returns 404 for an unknown user."""
    seed_mock_data(db_session)

    response = sync_client.get("/api/v1/users/99999/emails")
    assert response.status_code == 404
    assert response.json()["detail"] == "User with ID 99999 not found"


def test_get_single_email_known(sync_client: TestClient, db_session: Session) -> None:
    """Verify GET /api/v1/users/{user_id}/emails/{email_id} returns the specific email."""
    seed_mock_data(db_session)

    # First fetch list to get a valid email ID for User 1
    list_res = sync_client.get("/api/v1/users/1/emails")
    email_id = list_res.json()["items"][0]["id"]

    response = sync_client.get(f"/api/v1/users/1/emails/{email_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == email_id
    assert data["owner_id"] == 1


def test_get_single_email_unknown_email(
    sync_client: TestClient, db_session: Session
) -> None:
    """Verify GET /api/v1/users/{user_id}/emails/{email_id} returns 404 for non-existent email."""
    seed_mock_data(db_session)

    response = sync_client.get("/api/v1/users/1/emails/999999")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"]


def test_cross_user_access_attempt_isolation(
    sync_client: TestClient, db_session: Session
) -> None:
    """Verify that User 1 cannot access User 2's email ID, returning 404 without leaking data."""
    seed_mock_data(db_session)

    # Fetch User 2's emails
    user2_list = sync_client.get("/api/v1/users/2/emails")
    user2_email_id = user2_list.json()["items"][0]["id"]

    # Attempt to fetch User 2's email under User 1's path
    cross_res = sync_client.get(f"/api/v1/users/1/emails/{user2_email_id}")
    assert cross_res.status_code == 404
    assert (
        cross_res.json()["detail"]
        == f"Email with ID {user2_email_id} not found for user 1"
    )


def test_pagination_limit_and_offset(
    sync_client: TestClient, db_session: Session
) -> None:
    """Verify pagination controls (limit and offset) return deterministic results."""
    seed_mock_data(db_session)

    # Fetch with limit=3, offset=0
    page1 = sync_client.get("/api/v1/users/1/emails?limit=3&offset=0")
    assert page1.status_code == 200
    data1 = page1.json()
    assert len(data1["items"]) == 3
    assert data1["limit"] == 3
    assert data1["offset"] == 0
    assert data1["total"] == 10

    # Fetch with limit=3, offset=3 (page 2)
    page2 = sync_client.get("/api/v1/users/1/emails?limit=3&offset=3")
    assert page2.status_code == 200
    data2 = page2.json()
    assert len(data2["items"]) == 3
    assert data2["limit"] == 3
    assert data2["offset"] == 3

    # Items on page 1 and page 2 must be distinct
    page1_ids = [item["id"] for item in data1["items"]]
    page2_ids = [item["id"] for item in data2["items"]]
    assert set(page1_ids).isdisjoint(set(page2_ids))


def test_read_unread_filtering(sync_client: TestClient, db_session: Session) -> None:
    """Verify filtering emails by read/unread status."""
    seed_mock_data(db_session)

    # Read emails
    read_res = sync_client.get("/api/v1/users/1/emails?is_read=true")
    assert read_res.status_code == 200
    read_items = read_res.json()["items"]
    assert len(read_items) > 0
    assert all(item["is_read"] is True for item in read_items)

    # Unread emails
    unread_res = sync_client.get("/api/v1/users/1/emails?is_read=false")
    assert unread_res.status_code == 200
    unread_items = unread_res.json()["items"]
    assert len(unread_items) > 0
    assert all(item["is_read"] is False for item in unread_items)

    # Total read + unread must equal 10
    assert len(read_items) + len(unread_items) == 10


def test_empty_search_result(sync_client: TestClient, db_session: Session) -> None:
    """Verify empty search returns status 200 with items=[] and total=0."""
    seed_mock_data(db_session)

    # Request high offset beyond total records
    response = sync_client.get("/api/v1/users/1/emails?offset=500")
    assert response.status_code == 200
    data = response.json()
    assert data["items"] == []
    assert data["total"] == 10
    assert data["offset"] == 500


def test_invalid_query_parameters_validation(
    sync_client: TestClient, db_session: Session
) -> None:
    """Verify invalid limit and offset values return 422 Unprocessable Entity."""
    seed_mock_data(db_session)

    # Limit = 0 (min is 1)
    res_zero_limit = sync_client.get("/api/v1/users/1/emails?limit=0")
    assert res_zero_limit.status_code == 422

    # Limit = 101 (max is 100)
    res_high_limit = sync_client.get("/api/v1/users/1/emails?limit=101")
    assert res_high_limit.status_code == 422

    # Negative offset
    res_neg_offset = sync_client.get("/api/v1/users/1/emails?offset=-5")
    assert res_neg_offset.status_code == 422

    # Count out of bounds for /recent
    res_recent_invalid = sync_client.get("/api/v1/users/1/emails/recent?count=0")
    assert res_recent_invalid.status_code == 422

    res_recent_too_large = sync_client.get("/api/v1/users/1/emails/recent?count=20")
    assert res_recent_too_large.status_code == 422


def test_arabic_utf8_content_preservation(
    sync_client: TestClient, db_session: Session
) -> None:
    """Verify that Arabic UTF-8 text is preserved properly in JSON responses without character corruption."""
    seed_mock_data(db_session)

    response = sync_client.get("/api/v1/users/1/emails")
    assert response.status_code == 200
    data = response.json()

    arabic_found = False
    for email in data["items"]:
        if "إعلان جامعي" in email["subject"]:
            arabic_found = True
            assert "عمادة البحث العلمي" in email["body"]
            break

    assert arabic_found, (
        "Arabic email subject was not preserved or found in JSON output"
    )


def test_recent_emails_ordering(sync_client: TestClient, db_session: Session) -> None:
    """Verify /recent endpoint returns bounded emails sorted by received_at descending."""
    seed_mock_data(db_session)

    response = sync_client.get("/api/v1/users/1/emails/recent?count=3")
    assert response.status_code == 200
    data = response.json()

    assert len(data) == 3
    # Check descending order of received_at
    timestamps = [item["received_at"] for item in data]
    assert timestamps == sorted(timestamps, reverse=True)


def test_email_count_endpoint(sync_client: TestClient, db_session: Session) -> None:
    """Verify /count endpoint returns exact email totals and respects is_read filtering."""
    seed_mock_data(db_session)

    # Total count
    total_res = sync_client.get("/api/v1/users/1/emails/count")
    assert total_res.status_code == 200
    assert total_res.json()["owner_id"] == 1
    assert total_res.json()["count"] == 10
    assert total_res.json()["is_read"] is None

    # Unread count
    unread_res = sync_client.get("/api/v1/users/1/emails/count?is_read=false")
    assert unread_res.status_code == 200
    unread_count = unread_res.json()["count"]
    assert unread_res.json()["is_read"] is False

    # Read count
    read_res = sync_client.get("/api/v1/users/1/emails/count?is_read=true")
    assert read_res.status_code == 200
    read_count = read_res.json()["count"]
    assert read_res.json()["is_read"] is True

    assert unread_count + read_count == 10

    # Count for non-existent user returns 404
    missing_user_res = sync_client.get("/api/v1/users/99999/emails/count")
    assert missing_user_res.status_code == 404
