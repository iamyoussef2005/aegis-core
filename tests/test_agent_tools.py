"""Unit and integration tests for AEGIS-CORE Mini AI Agent tool adapters.

Tests cover:
- Successful inbox reading with bounding and sorting.
- Single email details retrieval with ownership enforcement.
- Cross-user access isolation (preventing existence / metadata leakage).
- Keyword search across subject and body (English and Arabic UTF-8).
- Case-insensitivity in search queries.
- SQL LIKE wildcard escaping (%, _, /) preventing query injection.
- Input validation and structured error envelopes.
- Maximum limit bounds enforcement.
- Database session isolation and JSON serializability.
"""

import json
from datetime import UTC, datetime

import pytest
from sqlalchemy.orm import Session

from app.agent.schemas import (
    GetEmailDetailsInput,
    ReadInboxInput,
    SearchEmailsInput,
    ToolError,
    ToolResult,
)
from app.agent.tools.email_tools import (
    EMAIL_TOOLS,
    GET_EMAIL_DETAILS_TOOL_SPEC,
    READ_INBOX_TOOL_SPEC,
    SEARCH_EMAILS_TOOL_SPEC,
    get_email_details,
    get_session_context,
    get_tool_specs,
    read_inbox,
    search_emails,
)
from app.models.email_message import EmailMessage
from app.models.user import User
from app.repositories.email import escape_like_wildcards, search_emails_by_owner
from app.services.email import EmailService

# ==============================================================================
# Category 1: read_inbox Tool Adapter Tests
# ==============================================================================


def test_read_inbox_success_default_limit(seeded_session: Session) -> None:
    """Test read_inbox returns default 5 bounded, owner-scoped messages."""
    result = read_inbox(user_id=1, session=seeded_session)

    assert isinstance(result, ToolResult)
    assert result.success is True
    assert result.tool_name == "read_inbox"
    assert result.error is None
    assert result.data is not None

    data = result.data
    assert data.owner_id == 1
    assert data.limit == 5
    assert data.offset == 0
    assert data.count == 5
    assert data.total == 10
    assert len(data.emails) == 5

    # Verify descending ordering by received_at
    timestamps = [e.received_at for e in data.emails]
    assert timestamps == sorted(timestamps, reverse=True)


def test_read_inbox_custom_limit_and_offset(seeded_session: Session) -> None:
    """Test read_inbox respects custom limit and offset parameters."""
    result = read_inbox(user_id=1, limit=3, offset=2, session=seeded_session)

    assert result.success is True
    assert result.data is not None
    assert result.data.count == 3
    assert result.data.limit == 3
    assert result.data.offset == 2
    assert result.data.total == 10


def test_read_inbox_is_read_filter(seeded_session: Session) -> None:
    """Test read_inbox filters correctly by read status."""
    # Test unread filter
    unread_result = read_inbox(
        user_id=1, limit=10, is_read=False, session=seeded_session
    )
    assert unread_result.success is True
    assert unread_result.data is not None
    assert all(e.is_read is False for e in unread_result.data.emails)
    assert unread_result.data.count == 4
    assert unread_result.data.total == 4

    # Test read filter
    read_result = read_inbox(user_id=1, limit=10, is_read=True, session=seeded_session)
    assert read_result.success is True
    assert read_result.data is not None
    assert all(e.is_read is True for e in read_result.data.emails)
    assert read_result.data.count == 6
    assert read_result.data.total == 6


def test_read_inbox_empty_inbox(empty_user: User, db_session: Session) -> None:
    """Test read_inbox for a user with zero messages returns empty list."""
    result = read_inbox(user_id=empty_user.id, session=db_session)

    assert result.success is True
    assert result.data is not None
    assert result.data.emails == []
    assert result.data.count == 0
    assert result.data.total == 0


def test_read_inbox_nonexistent_user(db_session: Session) -> None:
    """Test read_inbox returns structured USER_NOT_FOUND error for invalid user."""
    result = read_inbox(user_id=9999, session=db_session)

    assert result.success is False
    assert result.data is None
    assert result.error is not None
    assert result.error.code == "USER_NOT_FOUND"
    assert "9999" in result.error.message


@pytest.mark.parametrize(
    ("user_id", "limit", "offset"),
    [
        (1, 0, 0),  # limit < 1
        (1, 21, 0),  # limit > 20
        (1, -5, 0),  # limit negative
        (1, 5, -1),  # offset negative
        (0, 5, 0),  # user_id < 1
        (-1, 5, 0),  # user_id negative
    ],
)
def test_read_inbox_validation_errors(
    seeded_session: Session, user_id: int, limit: int, offset: int
) -> None:
    """Test read_inbox returns structured VALIDATION_ERROR for out-of-bounds arguments."""
    result = read_inbox(
        user_id=user_id, limit=limit, offset=offset, session=seeded_session
    )

    assert result.success is False
    assert result.data is None
    assert result.error is not None
    assert result.error.code == "VALIDATION_ERROR"
    assert result.error.details is not None


# ==============================================================================
# Category 2: get_email_details Tool Adapter Tests
# ==============================================================================


def test_get_email_details_success(seeded_session: Session) -> None:
    """Test get_email_details retrieves complete email with valid metadata."""
    result = get_email_details(user_id=1, email_id=1, session=seeded_session)

    assert result.success is True
    assert result.tool_name == "get_email_details"
    assert result.error is None
    assert result.data is not None

    email = result.data
    assert email.id == 1
    assert email.owner_id == 1
    assert "deanship.research@university.edu.sa" in email.sender
    assert len(email.body) > 0
    assert isinstance(email.received_at, datetime)


def test_get_email_details_missing_email(seeded_session: Session) -> None:
    """Test get_email_details returns EMAIL_NOT_FOUND for nonexistent ID."""
    result = get_email_details(user_id=1, email_id=9999, session=seeded_session)

    assert result.success is False
    assert result.data is None
    assert result.error is not None
    assert result.error.code == "EMAIL_NOT_FOUND"
    assert "9999" in result.error.message
    assert "user 1" in result.error.message


def test_get_email_details_foreign_owned_isolation(seeded_session: Session) -> None:
    """Test cross-user email access returns EMAIL_NOT_FOUND, preventing existence probing."""
    # Email 11 belongs to User 2. User 1 must NOT be able to access it.
    result = get_email_details(user_id=1, email_id=11, session=seeded_session)

    assert result.success is False
    assert result.data is None
    assert result.error is not None
    assert result.error.code == "EMAIL_NOT_FOUND"
    # Never leaks that email 11 exists or belongs to another user
    assert "Email with ID 11 not found for user 1" in result.error.message


def test_get_email_details_nonexistent_user(db_session: Session) -> None:
    """Test get_email_details returns USER_NOT_FOUND when user does not exist."""
    result = get_email_details(user_id=9999, email_id=1, session=db_session)

    assert result.success is False
    assert result.data is None
    assert result.error is not None
    assert result.error.code == "USER_NOT_FOUND"


@pytest.mark.parametrize(
    ("user_id", "email_id"),
    [
        (0, 1),
        (-1, 1),
        (1, 0),
        (1, -1),
    ],
)
def test_get_email_details_validation_errors(
    seeded_session: Session, user_id: int, email_id: int
) -> None:
    """Test get_email_details returns VALIDATION_ERROR on non-positive IDs."""
    result = get_email_details(
        user_id=user_id, email_id=email_id, session=seeded_session
    )

    assert result.success is False
    assert result.data is None
    assert result.error is not None
    assert result.error.code == "VALIDATION_ERROR"


# ==============================================================================
# Category 3: search_emails Tool Adapter Tests
# ==============================================================================


def test_search_emails_english_subject(seeded_session: Session) -> None:
    """Test search_emails finds message by subject keyword."""
    result = search_emails(
        user_id=1, query="Teaching Evaluation", session=seeded_session
    )

    assert result.success is True
    assert result.tool_name == "search_emails"
    assert result.data is not None
    assert result.data.count >= 1
    assert any("Teaching Evaluation" in e.subject for e in result.data.emails)


def test_search_emails_english_body(seeded_session: Session) -> None:
    """Test search_emails finds message by body keyword."""
    result = search_emails(
        user_id=1, query="SYSTEM INSTRUCTION OVERRIDE", session=seeded_session
    )

    assert result.success is True
    assert result.data is not None
    assert result.data.count >= 1
    assert any("SYSTEM INSTRUCTION OVERRIDE" in e.body for e in result.data.emails)


def test_search_emails_case_insensitive(seeded_session: Session) -> None:
    """Test that search is case-insensitive across uppercase, lowercase, and mixed case."""
    lower_res = search_emails(
        user_id=1, query="evaluation", limit=5, session=seeded_session
    )
    upper_res = search_emails(
        user_id=1, query="EVALUATION", limit=5, session=seeded_session
    )
    mixed_res = search_emails(
        user_id=1, query="EvAlUaTiOn", limit=5, session=seeded_session
    )

    assert lower_res.success is True
    assert upper_res.success is True
    assert mixed_res.success is True

    assert lower_res.data is not None and upper_res.data is not None
    assert mixed_res.data is not None
    assert lower_res.data.count == upper_res.data.count == mixed_res.data.count
    assert [e.id for e in lower_res.data.emails] == [
        e.id for e in upper_res.data.emails
    ]


def test_search_emails_arabic_subject(seeded_session: Session) -> None:
    """Test search_emails accurately retrieves Arabic text by subject."""
    result = search_emails(user_id=1, query="المختبر", session=seeded_session)

    assert result.success is True
    assert result.data is not None
    assert result.data.count >= 1
    assert any("المختبر" in e.subject for e in result.data.emails)


def test_search_emails_arabic_body(seeded_session: Session) -> None:
    """Test search_emails accurately retrieves Arabic text by body keyword."""
    result = search_emails(user_id=1, query="التكليف الأول", session=seeded_session)

    assert result.success is True
    assert result.data is not None
    assert result.data.count >= 1
    assert any(
        "التكليف الأول" in e.body or "التكليف الأول" in e.subject
        for e in result.data.emails
    )


def test_search_emails_wildcard_escaping(db_session: Session) -> None:
    """Test that SQL LIKE wildcards (%, _, /) are escaped and matched literally."""
    user = User(display_name="Wildcard Tester", email="wildcard@test.edu.sa")
    db_session.add(user)
    db_session.flush()

    # Create two emails: one with "100%", one with "1000"
    email_percent = EmailMessage(
        owner_id=user.id,
        sender="billing@test.edu.sa",
        recipient=user.email,
        subject="Special 100% discount on tuition",
        body="Congratulations, your grant covers 100% of costs.",
        received_at=datetime.now(UTC),
        is_read=False,
    )
    email_digits = EmailMessage(
        owner_id=user.id,
        sender="billing@test.edu.sa",
        recipient=user.email,
        subject="Invoice for 1000 credit hours",
        body="Your student account has 1000 credit items.",
        received_at=datetime.now(UTC),
        is_read=False,
    )
    email_underscore = EmailMessage(
        owner_id=user.id,
        sender="dev@test.edu.sa",
        recipient=user.email,
        subject="Audit report for task_1_run",
        body="Execution completed for task_1_run pipeline.",
        received_at=datetime.now(UTC),
        is_read=False,
    )
    email_slash = EmailMessage(
        owner_id=user.id,
        sender="path@test.edu.sa",
        recipient=user.email,
        subject="Access granted to folder A/B",
        body="Path is located at /var/data/shared.",
        received_at=datetime.now(UTC),
        is_read=False,
    )
    db_session.add_all([email_percent, email_digits, email_underscore, email_slash])
    db_session.commit()

    # Search for "100%" - must match ONLY email_percent, NOT email_digits
    res_percent = search_emails(user_id=user.id, query="100%", session=db_session)
    assert res_percent.success is True
    assert res_percent.data is not None
    assert res_percent.data.count == 1
    assert res_percent.data.emails[0].id == email_percent.id

    # Search for "task_1" - must NOT match "taskX1" or anything where _ acts as wildcard
    res_under = search_emails(user_id=user.id, query="task_1", session=db_session)
    assert res_under.success is True
    assert res_under.data is not None
    assert res_under.data.count == 1
    assert res_under.data.emails[0].id == email_underscore.id

    # Search for "A/B" with forward slash
    res_slash = search_emails(user_id=user.id, query="A/B", session=db_session)
    assert res_slash.success is True
    assert res_slash.data is not None
    assert res_slash.data.count == 1
    assert res_slash.data.emails[0].id == email_slash.id


def test_search_emails_owner_isolation(seeded_session: Session) -> None:
    """Test search_emails never leaks emails belonging to another user."""
    # User 2 has student-specific emails. User 1 searches for User 2's specific text.
    result = search_emails(
        user_id=1, query="CS502 Advanced Algorithms", session=seeded_session
    )

    assert result.success is True
    assert result.data is not None
    # User 1 has no emails with this text; must not return User 2's email
    assert result.data.count == 0
    assert result.data.emails == []


def test_search_emails_nonexistent_user(db_session: Session) -> None:
    """Test search_emails returns USER_NOT_FOUND for invalid user ID."""
    result = search_emails(user_id=9999, query="test", session=db_session)

    assert result.success is False
    assert result.data is None
    assert result.error is not None
    assert result.error.code == "USER_NOT_FOUND"


@pytest.mark.parametrize(
    ("user_id", "query", "limit", "offset"),
    [
        (1, "", 5, 0),  # empty query
        (1, "   ", 5, 0),  # whitespace-only query
        (1, "valid", 0, 0),  # limit < 1
        (1, "valid", 11, 0),  # limit > 10
        (1, "valid", -1, 0),  # limit negative
        (1, "valid", 5, -1),  # offset negative
        (0, "valid", 5, 0),  # user_id < 1
        (-1, "valid", 5, 0),  # user_id negative
        (1, "a" * 201, 5, 0),  # query exceeds max_length 200
    ],
)
def test_search_emails_validation_errors(
    seeded_session: Session,
    user_id: int,
    query: str,
    limit: int,
    offset: int,
) -> None:
    """Test search_emails returns VALIDATION_ERROR for invalid parameters."""
    result = search_emails(
        user_id=user_id,
        query=query,
        limit=limit,
        offset=offset,
        session=seeded_session,
    )

    assert result.success is False
    assert result.data is None
    assert result.error is not None
    assert result.error.code == "VALIDATION_ERROR"


# ==============================================================================
# Category 4: Maximum Result Limits & Edge Cases
# ==============================================================================


def test_maximum_limits_enforced(seeded_session: Session) -> None:
    """Test upper limit bounds: read_inbox max 20, search_emails max 10."""
    # Valid maximum limits
    res_inbox_max = read_inbox(user_id=1, limit=20, session=seeded_session)
    assert res_inbox_max.success is True
    assert res_inbox_max.data is not None
    assert res_inbox_max.data.limit == 20

    res_search_max = search_emails(
        user_id=1, query="a", limit=10, session=seeded_session
    )
    assert res_search_max.success is True
    assert res_search_max.data is not None
    assert res_search_max.data.limit == 10

    # Exceeding maximum limits
    res_inbox_over = read_inbox(user_id=1, limit=21, session=seeded_session)
    assert res_inbox_over.success is False
    assert res_inbox_over.error is not None
    assert res_inbox_over.error.code == "VALIDATION_ERROR"

    res_search_over = search_emails(
        user_id=1, query="a", limit=11, session=seeded_session
    )
    assert res_search_over.success is False
    assert res_search_over.error is not None
    assert res_search_over.error.code == "VALIDATION_ERROR"


# ==============================================================================
# Category 5: Tool Specifications & Registry
# ==============================================================================


def test_tool_specs_and_registry() -> None:
    """Test that all tool specifications and registry definitions are valid."""
    specs = get_tool_specs()
    assert len(specs) == 3

    spec_names = [s["name"] for s in specs]
    assert "read_inbox" in spec_names
    assert "get_email_details" in spec_names
    assert "search_emails" in spec_names

    # Check individual specs
    assert READ_INBOX_TOOL_SPEC["name"] == "read_inbox"
    assert GET_EMAIL_DETAILS_TOOL_SPEC["name"] == "get_email_details"
    assert SEARCH_EMAILS_TOOL_SPEC["name"] == "search_emails"

    # Check registry mappings
    assert EMAIL_TOOLS["read_inbox"] is read_inbox
    assert EMAIL_TOOLS["get_email_details"] is get_email_details
    assert EMAIL_TOOLS["search_emails"] is search_emails


# ==============================================================================
# Category 6: JSON Serialization & Pydantic Schema Helpers
# ==============================================================================


def test_tool_result_json_serialization(seeded_session: Session) -> None:
    """Test that tool results serialize to valid, parseable JSON and dicts."""
    # Test successful result serialization
    success_result = read_inbox(user_id=1, limit=2, session=seeded_session)
    as_dict = success_result.to_dict()
    assert isinstance(as_dict, dict)
    assert as_dict["success"] is True
    assert as_dict["tool_name"] == "read_inbox"
    assert len(as_dict["data"]["emails"]) == 2

    as_json = success_result.to_json()
    assert isinstance(as_json, str)
    parsed = json.loads(as_json)
    assert parsed["success"] is True
    assert parsed["data"]["count"] == 2

    # Test error result serialization
    error_result = get_email_details(user_id=1, email_id=9999, session=seeded_session)
    err_dict = error_result.to_dict()
    assert err_dict["success"] is False
    assert err_dict["error"]["code"] == "EMAIL_NOT_FOUND"

    err_json = error_result.to_json()
    assert json.loads(err_json)["error"]["code"] == "EMAIL_NOT_FOUND"


# ==============================================================================
# Category 7: Database Isolation & Session Lifecycle
# ==============================================================================


def test_get_session_context_with_and_without_session(
    db_session: Session,
) -> None:
    """Test get_session_context respects external session and creates managed session."""
    # With external session: caller owns lifecycle, session stays open
    with get_session_context(db_session) as s:
        assert s is db_session
        assert s.is_active

    # Without external session: context manager creates and closes session
    with get_session_context(None) as new_s:
        assert isinstance(new_s, Session)
        assert new_s.is_active


def test_search_emails_by_owner_standalone(seeded_session: Session) -> None:
    """Test standalone repository helper function search_emails_by_owner."""
    emails = search_emails_by_owner(
        session=seeded_session, owner_id=1, query="security", limit=5
    )
    assert len(emails) >= 1
    assert all(e.owner_id == 1 for e in emails)


def test_escape_like_wildcards_helper() -> None:
    """Test escape_like_wildcards helper function."""
    assert escape_like_wildcards("abc") == "abc"
    assert escape_like_wildcards("100%") == "100/%"
    assert escape_like_wildcards("task_1") == "task/_1"
    assert escape_like_wildcards("dir/file") == "dir//file"
    assert escape_like_wildcards("%_/") == "/%/_//"


def test_email_service_search_nonexistent_user(db_session: Session) -> None:
    """Test EmailService search and count methods return None for nonexistent user."""
    service = EmailService(db_session)
    assert service.search_user_emails(user_id=9999, query="test") is None
    assert service.count_search_user_emails(user_id=9999, query="test") is None


def test_input_schemas_validation() -> None:
    """Test direct Pydantic validation on agent input schemas."""
    # ReadInboxInput
    inbox_input = ReadInboxInput(user_id=1, limit=10, offset=5, is_read=True)
    assert inbox_input.user_id == 1
    assert inbox_input.limit == 10
    assert inbox_input.offset == 5
    assert inbox_input.is_read is True

    # GetEmailDetailsInput
    details_input = GetEmailDetailsInput(user_id=1, email_id=42)
    assert details_input.user_id == 1
    assert details_input.email_id == 42

    # SearchEmailsInput
    search_input = SearchEmailsInput(user_id=1, query="  research  ", limit=5)
    assert search_input.user_id == 1
    assert search_input.query == "research"

    # ToolError model
    err = ToolError(code="TEST_ERROR", message="Test failure", details={"key": "val"})
    assert err.code == "TEST_ERROR"
    assert err.message == "Test failure"
    assert err.details == {"key": "val"}
