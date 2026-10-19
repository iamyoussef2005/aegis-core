"""SQLAlchemy 2.x mapped model for EmailMessage entities."""

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.user import User


class EmailMessage(Base):
    """Synthetic email message owned by a specific simulated User.

    Represents simulated incoming and outgoing communications in the mock environment.
    """

    __tablename__ = "email_messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    owner_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    sender: Mapped[str] = mapped_column(String(255), nullable=False)
    recipient: Mapped[str] = mapped_column(String(255), nullable=False)
    subject: Mapped[str] = mapped_column(String(500), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    is_read: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    # Relationship back to User
    owner: Mapped["User"] = relationship(back_populates="emails")

    __table_args__ = (
        # Composite index for efficient owner-scoped ordering and retrieval
        Index("ix_email_messages_owner_received", "owner_id", "received_at"),
        # Composite index for filtering unread emails by owner
        Index("ix_email_messages_owner_is_read", "owner_id", "is_read"),
    )

    def __repr__(self) -> str:
        return (
            f"<EmailMessage(id={self.id}, owner_id={self.owner_id}, "
            f"sender='{self.sender}', subject='{self.subject[:30]}...')>"
        )
