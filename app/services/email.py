"""Email domain service layer for AEGIS-CORE."""

from sqlalchemy.orm import Session

from app.repositories.email import EmailRepository
from app.repositories.user import UserRepository
from app.schemas.email import (
    EmailCountResponse,
    EmailListResponse,
    EmailMessageResponse,
)


class EmailService:
    """Business logic service for managing and querying simulated email messages.

    Enforces ownership boundaries: every query checks user existence and restricts
    access strictly to messages owned by the target user ID.
    """

    def __init__(self, session: Session) -> None:
        self.email_repo = EmailRepository(session)
        self.user_repo = UserRepository(session)

    def user_exists(self, user_id: int) -> bool:
        """Verify whether a user account exists."""
        return self.user_repo.get_by_id(user_id) is not None

    def list_user_emails(
        self,
        user_id: int,
        offset: int = 0,
        limit: int = 10,
        is_read: bool | None = None,
    ) -> EmailListResponse | None:
        """List emails belonging to a user with pagination and optional read status filter.

        Returns None if user does not exist.
        """
        if not self.user_exists(user_id):
            return None

        items = self.email_repo.list_by_owner(
            owner_id=user_id,
            skip=offset,
            limit=limit,
            is_read=is_read,
        )
        total = self.email_repo.count_by_owner(
            owner_id=user_id,
            is_read=is_read,
        )

        return EmailListResponse(
            items=[EmailMessageResponse.model_validate(e) for e in items],
            total=total,
            owner_id=user_id,
            limit=limit,
            offset=offset,
        )

    def get_user_email(
        self,
        user_id: int,
        email_id: int,
    ) -> EmailMessageResponse | None:
        """Fetch a single email scoped strictly to the specified owner.

        Returns None if user does not exist or if email is not found / belongs to another user.
        """
        if not self.user_exists(user_id):
            return None

        email = self.email_repo.get_by_id_and_owner(
            email_id=email_id,
            owner_id=user_id,
        )
        if email is None:
            return None

        return EmailMessageResponse.model_validate(email)

    def get_user_email_count(
        self,
        user_id: int,
        is_read: bool | None = None,
    ) -> EmailCountResponse | None:
        """Count emails for a given user with optional read status filter.

        Returns None if user does not exist.
        """
        if not self.user_exists(user_id):
            return None

        count = self.email_repo.count_by_owner(
            owner_id=user_id,
            is_read=is_read,
        )
        return EmailCountResponse(
            owner_id=user_id,
            count=count,
            is_read=is_read,
        )

    def get_recent_user_emails(
        self,
        user_id: int,
        count: int = 3,
    ) -> list[EmailMessageResponse] | None:
        """Retrieve the most recent messages for a user up to count.

        Returns None if user does not exist.
        """
        if not self.user_exists(user_id):
            return None

        recent = self.email_repo.list_by_owner(
            owner_id=user_id,
            skip=0,
            limit=count,
            is_read=None,
        )
        return [EmailMessageResponse.model_validate(e) for e in recent]

    def search_user_emails(
        self,
        user_id: int,
        query: str,
        limit: int = 10,
        offset: int = 0,
    ) -> list[EmailMessageResponse] | None:
        """Search emails for a given user across subject and body.

        Returns None if user does not exist.
        """
        if not self.user_exists(user_id):
            return None

        results = self.email_repo.search_by_owner(
            owner_id=user_id,
            query=query,
            limit=limit,
            skip=offset,
        )
        return [EmailMessageResponse.model_validate(e) for e in results]

    def count_search_user_emails(
        self,
        user_id: int,
        query: str,
    ) -> int | None:
        """Count emails matching search query for a given user across subject and body.

        Returns None if user does not exist.
        """
        if not self.user_exists(user_id):
            return None

        return self.email_repo.count_search_by_owner(
            owner_id=user_id,
            query=query,
        )
