"""Test suite for mock email environment, models, repository functions, and idempotent seeding."""

from datetime import UTC, datetime

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.email_message import EmailMessage
from app.models.user import User
from app.repositories.email import (
    EmailRepository,
    count_emails_by_owner,
    get_email_by_id_and_owner,
    list_emails_by_owner,
)
from app.repositories.user import (
    UserRepository,
    get_user_by_email,
    get_user_by_id,
)
from scripts.seed_mock_data import seed_mock_data


def test_user_creation_and_constraints(db_session: Session) -> None:
    """Verify User model creation, uniqueness constraint, and default attributes."""
    user1 = User(
        display_name="Test Student",
        email="student@university.edu.sa",
        created_at=datetime.now(UTC),
    )
    db_session.add(user1)
    db_session.commit()
    assert user1.id is not None
    assert user1.email == "student@university.edu.sa"

    # Verify unique email constraint
    user2 = User(
        display_name="Duplicate Student",
        email="student@university.edu.sa",
        created_at=datetime.now(UTC),
    )
    db_session.add(user2)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_sqlite_foreign_key_constraint_enforcement(db_session: Session) -> None:
    """Verify that SQLite foreign-key constraints are strictly enforced."""
    # Attempt to insert an EmailMessage with an invalid/non-existent owner_id
    invalid_email = EmailMessage(
        owner_id=99999,  # Non-existent user ID
        sender="attacker@external.org",
        recipient="target@university.edu.sa",
        subject="Phishing simulation",
        body="Test body",
        received_at=datetime.now(UTC),
    )
    db_session.add(invalid_email)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_cascade_delete_user_removes_emails(db_session: Session) -> None:
    """Verify that deleting a User cascades to delete all their owned EmailMessages."""
    user = User(
        display_name="Ephemeral User",
        email="ephemeral@university.edu.sa",
        created_at=datetime.now(UTC),
    )
    db_session.add(user)
    db_session.flush()

    email = EmailMessage(
        owner_id=user.id,
        sender="admin@university.edu.sa",
        recipient=user.email,
        subject="Welcome",
        body="Welcome to the academic platform.",
        received_at=datetime.now(UTC),
    )
    db_session.add(email)
    db_session.commit()

    email_id = email.id
    user_id = user.id

    # Delete user
    db_session.delete(user)
    db_session.commit()

    # Verify email was cascaded and deleted
    assert db_session.get(User, user_id) is None
    assert db_session.get(EmailMessage, email_id) is None


def test_user_repository_functions(db_session: Session) -> None:
    """Verify get_user_by_id and get_user_by_email repository functions."""
    user_repo = UserRepository(db_session)
    user = user_repo.create_user(
        display_name="Professor Layla",
        email="dr.layla@university.edu.sa",
    )
    db_session.commit()

    # Test class methods
    assert user_repo.get_by_id(user.id) is not None
    assert user_repo.get_by_email("dr.layla@university.edu.sa") is not None
    assert user_repo.get_by_email("nonexistent@university.edu.sa") is None

    # Test standalone functional query helpers
    assert get_user_by_id(db_session, user.id) is not None
    assert get_user_by_email(db_session, "dr.layla@university.edu.sa") is not None
    assert get_user_by_email(db_session, "missing@university.edu.sa") is None


def test_email_repository_functions_and_ownership_isolation(
    db_session: Session,
) -> None:
    """Verify owner-scoped email queries, counts, pagination, and tenant isolation."""
    user_a = User(
        display_name="User Alice",
        email="alice@university.edu.sa",
        created_at=datetime.now(UTC),
    )
    user_b = User(
        display_name="User Bob",
        email="bob@university.edu.sa",
        created_at=datetime.now(UTC),
    )
    db_session.add_all([user_a, user_b])
    db_session.flush()

    email_repo = EmailRepository(db_session)

    # Add 3 emails for Alice (2 unread, 1 read)
    email_a1 = email_repo.create_email(
        owner_id=user_a.id,
        sender="advisor@university.edu.sa",
        recipient=user_a.email,
        subject="Alice Project Update",
        body="Progress looking good.",
        received_at=datetime(2026, 10, 5, 10, 0, 0, tzinfo=UTC),
        is_read=False,
    )
    email_repo.create_email(
        owner_id=user_a.id,
        sender="club@university.edu.sa",
        recipient=user_a.email,
        subject="AI Club Meetup",
        body="Join us tomorrow.",
        received_at=datetime(2026, 10, 6, 10, 0, 0, tzinfo=UTC),
        is_read=False,
    )
    email_repo.create_email(
        owner_id=user_a.id,
        sender="registrar@university.edu.sa",
        recipient=user_a.email,
        subject="Alice Course Enrollment",
        body="Enrollment complete.",
        received_at=datetime(2026, 10, 7, 10, 0, 0, tzinfo=UTC),
        is_read=True,
    )

    # Add 1 email for Bob
    email_b1 = email_repo.create_email(
        owner_id=user_b.id,
        sender="finance@university.edu.sa",
        recipient=user_b.email,
        subject="Bob Tuition Invoice",
        body="Confidential financial statement.",
        received_at=datetime(2026, 10, 8, 10, 0, 0, tzinfo=UTC),
        is_read=False,
    )
    db_session.commit()

    # 1. Count checks
    assert count_emails_by_owner(db_session, user_a.id) == 3
    assert count_emails_by_owner(db_session, user_a.id, unread_only=True) == 2
    assert count_emails_by_owner(db_session, user_b.id) == 1

    # 2. List emails for owner
    alice_emails = list_emails_by_owner(db_session, user_a.id)
    assert len(alice_emails) == 3
    # Check ordering (descending by received_at)
    assert alice_emails[0].subject == "Alice Course Enrollment"
    assert alice_emails[1].subject == "AI Club Meetup"
    assert alice_emails[2].subject == "Alice Project Update"

    # 3. Pagination
    paginated = list_emails_by_owner(db_session, user_a.id, skip=1, limit=1)
    assert len(paginated) == 1
    assert paginated[0].subject == "AI Club Meetup"

    # 4. Strict Ownership Isolation (Security Contract)
    # Alice CANNOT retrieve Bob's email even if she knows Bob's email_id!
    unauthorized_lookup = get_email_by_id_and_owner(
        db_session, email_id=email_b1.id, owner_id=user_a.id
    )
    assert unauthorized_lookup is None, "Cross-user data leakage detected!"

    # Bob CANNOT retrieve Alice's email
    cross_lookup = get_email_by_id_and_owner(
        db_session, email_id=email_a1.id, owner_id=user_b.id
    )
    assert cross_lookup is None, "Cross-user data leakage detected!"

    # Authorized lookups succeed
    assert (
        get_email_by_id_and_owner(db_session, email_id=email_a1.id, owner_id=user_a.id)
        is not None
    )
    assert (
        get_email_by_id_and_owner(db_session, email_id=email_b1.id, owner_id=user_b.id)
        is not None
    )


def test_deterministic_idempotent_seeding(db_session: Session) -> None:
    """Verify that seed_mock_data is deterministic, idempotent, and preserves counts."""
    # First seeding run on clean database
    first_run_stats = seed_mock_data(db_session)
    assert first_run_stats["users_created"] == 3
    assert first_run_stats["users_skipped"] == 0
    assert first_run_stats["emails_created"] == 30
    assert first_run_stats["emails_skipped"] == 0

    # Verify exact counts in database
    users = db_session.query(User).all()
    emails = db_session.query(EmailMessage).all()
    assert len(users) == 3
    assert len(emails) == 30

    # Verify each user has exactly 10 emails
    for user in users:
        owner_emails = list_emails_by_owner(db_session, user.id)
        assert len(owner_emails) == 10

    # Second seeding run (idempotency verification)
    second_run_stats = seed_mock_data(db_session)
    assert second_run_stats["users_created"] == 0
    assert second_run_stats["users_skipped"] == 3
    assert second_run_stats["emails_created"] == 0
    assert second_run_stats["emails_skipped"] == 30

    # Total counts remain strictly 3 and 30
    assert db_session.query(User).count() == 3
    assert db_session.query(EmailMessage).count() == 30

    # Verify at least 5 emails contain harmless, labeled adversarial benchmark text
    adversarial_emails = [
        email
        for email in emails
        if "[SECURITY RESEARCH" in email.subject or "[SECURITY RESEARCH" in email.body
    ]
    assert len(adversarial_emails) >= 5, (
        f"Expected at least 5 adversarial emails, found {len(adversarial_emails)}"
    )

    # Verify valid UTF-8 Arabic text is present and decoded properly
    arabic_emails = [
        email
        for email in emails
        if any("\u0600" <= c <= "\u06ff" for c in email.subject)
    ]
    assert len(arabic_emails) >= 10, (
        f"Expected at least 10 Arabic emails, found {len(arabic_emails)}"
    )
