"""User repository and data access functions for AEGIS-CORE."""

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.user import User
from app.repositories.base import BaseRepository


class UserRepository(BaseRepository[User]):
    """Repository handling persistence operations for User entities."""

    def __init__(self, session: Session) -> None:
        super().__init__(User, session)

    def get_by_id(self, user_id: int) -> User | None:
        """Fetch a single user by primary key ID."""
        return self.session.get(User, user_id)

    def get_by_email(self, email: str) -> User | None:
        """Fetch a user by exact email address using bound parameters."""
        statement = select(User).where(User.email == email)
        return self.session.scalars(statement).first()

    def create_user(
        self,
        display_name: str,
        email: str,
        created_at: datetime | None = None,
    ) -> User:
        """Create and persist a new user instance."""
        user = User(
            display_name=display_name,
            email=email,
            created_at=created_at or datetime.now(UTC),
        )
        return self.create(user)


def get_user_by_id(session: Session, user_id: int) -> User | None:
    """Standalone functional query to retrieve a user by primary key."""
    return UserRepository(session).get_by_id(user_id)


def get_user_by_email(session: Session, email: str) -> User | None:
    """Standalone functional query to retrieve a user by email address."""
    return UserRepository(session).get_by_email(email)
