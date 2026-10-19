"""Test suite for database connection, session lifecycle, and repository operations."""

from sqlalchemy import Column, Integer, String, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.db.base import Base
from app.db.session import check_db_health, create_db_engine
from app.repositories.base import BaseRepository


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


def test_check_db_health_failure() -> None:
    """Verify check_db_health fails gracefully on disconnected mock."""

    class BrokenSession:
        def execute(self, statement):
            raise OperationalError("SELECT 1", {}, Exception("Database disconnected"))

    assert check_db_health(BrokenSession()) is False  # type: ignore[arg-type]


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
