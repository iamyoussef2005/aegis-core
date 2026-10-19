"""Pytest configuration and reusable test fixtures for AEGIS-CORE."""

from collections.abc import AsyncGenerator, Generator

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx import ASGITransport
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import Settings, get_settings
from app.db.base import Base
from app.db.session import get_db
from app.main import create_app


@pytest.fixture(scope="session")
def test_settings() -> Settings:
    """Fixture providing isolated test settings with in-memory database."""
    return Settings(
        PROJECT_NAME="AEGIS-CORE-TEST",
        VERSION="0.1.0-test",
        ENVIRONMENT="testing",
        DEBUG=True,
        DATABASE_URL="sqlite:///:memory:",
        DATABASE_ECHO=False,
        LOG_LEVEL="DEBUG",
        LOG_FORMAT="console",
    )


@pytest.fixture
def test_engine():
    """In-memory SQLite engine isolated per test function."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture
def db_session(test_engine) -> Generator[Session, None, None]:
    """Provide an isolated database session fixture for testing."""
    testing_session_local = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=test_engine,
        expire_on_commit=False,
    )
    session = testing_session_local()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def test_app(test_settings: Settings, db_session: Session) -> FastAPI:
    """FastAPI application fixture with dependency overrides for testing."""
    app = create_app(settings=test_settings)

    def override_get_db() -> Generator[Session, None, None]:
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_settings] = lambda: test_settings
    return app


@pytest.fixture
def seeded_session(db_session: Session) -> Session:
    """Fixture providing a database session pre-populated with deterministic demo data."""
    from scripts.seed_mock_data import seed_mock_data

    seed_mock_data(db_session)
    return db_session


@pytest.fixture
def empty_user(db_session: Session):
    """Fixture providing a user with an empty inbox (zero emails)."""
    from datetime import UTC, datetime

    from app.models.user import User

    user = User(
        display_name="Empty Inbox Student",
        email="empty.inbox@student.university.edu.sa",
        created_at=datetime.now(UTC),
    )
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture
def sync_client(test_app: FastAPI) -> Generator[TestClient, None, None]:
    """Synchronous HTTP TestClient fixture."""
    with TestClient(test_app) as client:
        yield client


@pytest.fixture
async def async_client(test_app: FastAPI) -> AsyncGenerator[httpx.AsyncClient, None]:
    """Asynchronous HTTP client fixture using httpx ASGITransport."""
    transport = ASGITransport(app=test_app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as client:
        yield client
