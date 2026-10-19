"""Email repository and owner-scoped data access functions for AEGIS-CORE."""

from collections.abc import Sequence
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.email_message import EmailMessage
from app.repositories.base import BaseRepository


class EmailRepository(BaseRepository[EmailMessage]):
    """Repository handling owner-scoped operations for EmailMessage entities.

    Guarantees strict tenant/owner isolation: every read and query is scoped
    to the owning user's ID to prevent cross-account information leakage.
    """

    def __init__(self, session: Session) -> None:
        super().__init__(EmailMessage, session)

    def list_by_owner(
        self,
        owner_id: int,
        skip: int = 0,
        limit: int = 100,
        unread_only: bool = False,
    ) -> Sequence[EmailMessage]:
        """Fetch emails belonging strictly to the specified owner, ordered by received_at descending."""
        query = select(EmailMessage).where(EmailMessage.owner_id == owner_id)
        if unread_only:
            query = query.where(EmailMessage.is_read.is_(False))
        query = (
            query.order_by(EmailMessage.received_at.desc()).offset(skip).limit(limit)
        )
        return self.session.scalars(query).all()

    def get_by_id_and_owner(
        self,
        email_id: int,
        owner_id: int,
    ) -> EmailMessage | None:
        """Fetch a single email by its ID, strictly verifying ownership."""
        query = select(EmailMessage).where(
            EmailMessage.id == email_id,
            EmailMessage.owner_id == owner_id,
        )
        return self.session.scalars(query).first()

    def count_by_owner(
        self,
        owner_id: int,
        unread_only: bool = False,
    ) -> int:
        """Count total emails belonging to the specified owner."""
        query = select(func.count(EmailMessage.id)).where(
            EmailMessage.owner_id == owner_id
        )
        if unread_only:
            query = query.where(EmailMessage.is_read.is_(False))
        result = self.session.scalar(query)
        return int(result or 0)

    def create_email(
        self,
        owner_id: int,
        sender: str,
        recipient: str,
        subject: str,
        body: str,
        received_at: datetime,
        is_read: bool = False,
        created_at: datetime | None = None,
    ) -> EmailMessage:
        """Create and persist an email message assigned to a specific owner."""
        email = EmailMessage(
            owner_id=owner_id,
            sender=sender,
            recipient=recipient,
            subject=subject,
            body=body,
            received_at=received_at,
            is_read=is_read,
            created_at=created_at or datetime.now(UTC),
        )
        return self.create(email)


def list_emails_by_owner(
    session: Session,
    owner_id: int,
    skip: int = 0,
    limit: int = 100,
    unread_only: bool = False,
) -> Sequence[EmailMessage]:
    """Retrieve emails scoped to an owner with optional pagination and unread filtering."""
    return EmailRepository(session).list_by_owner(
        owner_id=owner_id,
        skip=skip,
        limit=limit,
        unread_only=unread_only,
    )


def get_email_by_id_and_owner(
    session: Session,
    email_id: int,
    owner_id: int,
) -> EmailMessage | None:
    """Retrieve an email by primary key scoped strictly to its owner."""
    return EmailRepository(session).get_by_id_and_owner(
        email_id=email_id,
        owner_id=owner_id,
    )


def count_emails_by_owner(
    session: Session,
    owner_id: int,
    unread_only: bool = False,
) -> int:
    """Count emails owned by the specified user."""
    return EmailRepository(session).count_by_owner(
        owner_id=owner_id,
        unread_only=unread_only,
    )
