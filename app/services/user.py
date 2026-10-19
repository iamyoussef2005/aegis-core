"""User domain service layer for AEGIS-CORE."""

from sqlalchemy.orm import Session

from app.repositories.user import UserRepository
from app.schemas.user import UserResponse


class UserService:
    """Business logic service for managing and retrieving simulated user accounts."""

    def __init__(self, session: Session) -> None:
        self.repo = UserRepository(session)

    def list_users(self, skip: int = 0, limit: int = 100) -> list[UserResponse]:
        """Fetch all simulated users formatted as response models."""
        users = self.repo.list_users(skip=skip, limit=limit)
        return [UserResponse.model_validate(u) for u in users]

    def get_user_by_id(self, user_id: int) -> UserResponse | None:
        """Fetch a specific simulated user by ID."""
        user = self.repo.get_by_id(user_id)
        if user is None:
            return None
        return UserResponse.model_validate(user)
