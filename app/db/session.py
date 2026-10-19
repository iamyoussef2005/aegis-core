"""SQLAlchemy 2.x database engine, session factory, and dependency injection."""

import logging
from collections.abc import Generator

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import get_settings
from app.db.base import Base

logger = logging.getLogger(__name__)


def create_db_engine(
    database_url: str | None = None, echo: bool | None = None
) -> Engine:
    """Create a configured SQLAlchemy Engine instance."""
    settings = get_settings()
    url = database_url or settings.DATABASE_URL
    is_echo = echo if echo is not None else settings.DATABASE_ECHO

    connect_args = {}
    pool_class = None

    if url.startswith("sqlite"):
        # SQLite-specific flags for thread concurrency & in-memory support
        connect_args["check_same_thread"] = False
        if ":memory:" in url:
            pool_class = StaticPool

    engine_kwargs: dict = {
        "echo": is_echo,
        "connect_args": connect_args,
    }
    if pool_class is not None:
        engine_kwargs["poolclass"] = pool_class

    return create_engine(url, **engine_kwargs)


# Global engine and sessionmaker bound to application settings
engine = create_db_engine()
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=False,
)


def init_db() -> None:
    """Initialize database schemas and tables."""
    logger.info("Initializing database metadata and tables...")
    Base.metadata.create_all(bind=engine)
    logger.info("Database initialized successfully.")


def close_db() -> None:
    """Dispose of engine connection pool during graceful shutdown."""
    logger.info("Disposing database engine connection pool...")
    engine.dispose()
    logger.info("Database engine disposed.")


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency for managing transactional database session lifecycle."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def check_db_health(session: Session | None = None) -> bool:
    """Verify database responsiveness by executing a lightweight ping query."""
    if session is not None:
        try:
            session.execute(text("SELECT 1"))
            return True
        except Exception as exc:
            logger.warning("Database session health check failed: %s", exc)
            return False

    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
            return True
    except Exception as exc:
        logger.warning("Database engine health check failed: %s", exc)
        return False
