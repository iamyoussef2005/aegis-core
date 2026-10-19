"""Test suite for database connection, session lifecycle, and repository operations."""

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import Column, Integer, String, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.db.base import Base
from app.db.session import check_db_health, create_db_engine, get_db
from app.models.email_message import EmailMessage
from app.models.user import User
from app.repositories.base import BaseRepository
from app.services.user import UserService


class DummyAuditEntry(Base):
    """Temporary model for testing repository patterns."""

    __tablename__ = "dummy_audit_entries"

    id = Column(Integer, primary_key=True, autoincrement=True)
    action_name = Column(String(50), nullable=False)


def test_database_connectivity(db_session: Session) -> None:
    """Verify that the database session can execute standard SQL queries."""
    result = db_session.execute(text("SELECT 1")).scalar()
    assert result == 1


def test_check_db_health_success(db_session: Session) -> None:
    """Verify check_db_health utility returns True on operational session."""
    assert check_db_health(db_session) is True


def test_check_db_health_global_engine_success() -> None:
    """Verify check_db_health without passing a session tests the engine directly."""
    assert check_db_health() is True


def test_check_db_health_engine_failure() -> None:
    """Verify check_db_health returns False when engine connection fails."""
    with patch(
        "app.db.session.engine.connect",
        side_effect=OperationalError("SELECT 1", {}, Exception("Connect failed")),
    ):
        assert check_db_health(session=None) is False


def test_check_db_health_failure() -> None:
    """Verify check_db_health fails gracefully on disconnected mock."""

    class BrokenSession:
        def execute(self, statement):
            raise OperationalError("SELECT 1", {}, Exception("Database disconnected"))

    assert check_db_health(BrokenSession()) is False  # type: ignore[arg-type]


def test_model_relationships_bidirectional(db_session: Session) -> None:
    """Verify bidirectional relationship between User and EmailMessage."""
    user = User(
        display_name="Relationship Test User",
        email="relationship@university.edu.sa",
        created_at=datetime.now(UTC),
    )
    db_session.add(user)
    db_session.flush()

    email1 = EmailMessage(
        owner_id=user.id,
        sender="sender1@university.edu.sa",
        recipient=user.email,
        subject="Subject 1",
        body="Body 1",
        received_at=datetime(2026, 10, 1, 10, 0, tzinfo=UTC),
    )
    email2 = EmailMessage(
        owner_id=user.id,
        sender="sender2@university.edu.sa",
        recipient=user.email,
        subject="Subject 2",
        body="Body 2",
        received_at=datetime(2026, 10, 2, 10, 0, tzinfo=UTC),
    )
    db_session.add_all([email1, email2])
    db_session.commit()

    # Refresh and verify relationship properties
    db_session.refresh(user)
    assert len(user.emails) == 2
    assert email1.owner == user
    assert email2.owner == user
    assert email1 in user.emails
    assert email2 in user.emails


def test_get_db_session_lifecycle_success() -> None:
    """Verify get_db generator yields a session and commits on completion."""
    mock_session = MagicMock(spec=Session)
    with patch("app.db.session.SessionLocal", return_value=mock_session):
        gen = get_db()
        yielded_session = next(gen)
        assert yielded_session == mock_session

        # Finish iteration
        with pytest.raises(StopIteration):
            next(gen)

        mock_session.commit.assert_called_once()
        mock_session.close.assert_called_once()


def test_get_db_session_lifecycle_error_rollback() -> None:
    """Verify get_db generator rolls back and closes on exception."""
    mock_session = MagicMock(spec=Session)
    with patch("app.db.session.SessionLocal", return_value=mock_session):
        gen = get_db()
        next(gen)

        with pytest.raises(RuntimeError, match="Simulated error"):
            gen.throw(RuntimeError("Simulated error"))

        mock_session.rollback.assert_called_once()
        mock_session.close.assert_called_once()


def test_user_service_lookup(db_session: Session) -> None:
    """Verify UserService get_user_by_id returns model or None."""
    service = UserService(db_session)
    user = User(
        display_name="Service User",
        email="service_user@university.edu.sa",
        created_at=datetime.now(UTC),
    )
    db_session.add(user)
    db_session.commit()

    fetched = service.get_user_by_id(user.id)
    assert fetched is not None
    assert fetched.id == user.id
    assert fetched.email == "service_user@university.edu.sa"

    assert service.get_user_by_id(99999) is None


def test_base_repository_crud(test_engine, db_session: Session) -> None:
    """Verify BaseRepository CRUD abstraction works with SQLAlchemy 2.x."""
    repo = BaseRepository(DummyAuditEntry, db_session)

    # Create
    item = DummyAuditEntry(action_name="tool_call_intercepted")
    created = repo.create(item)
    db_session.commit()
    assert created.id is not None
    assert created.action_name == "tool_call_intercepted"

    # Read
    fetched = repo.get_by_id(created.id)
    assert fetched is not None
    assert fetched.action_name == "tool_call_intercepted"

    # List
    all_items = repo.list_all()
    assert len(all_items) == 1

    # Delete
    repo.delete(fetched)
    db_session.commit()
    assert repo.get_by_id(created.id) is None


def test_create_db_engine_sqlite_in_memory() -> None:
    """Verify create_db_engine creates an operable engine for in-memory SQLite."""
    engine = create_db_engine(database_url="sqlite:///:memory:")
    with engine.connect() as conn:
        val = conn.execute(text("SELECT 42")).scalar()
        assert val == 42
    engine.dispose()
