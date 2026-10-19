"""SQLAlchemy 2.x mapped model for User entities."""

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.email_message import EmailMessage


class User(Base):
    """User account entity representing simulated owners in the mock environment."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    display_name: Mapped[str] = mapped_column(String(150), nullable=False)
    email: Mapped[str] = mapped_column(
        String(255), unique=True, index=True, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    # 1-to-many relationship with EmailMessage
    emails: Mapped[list["EmailMessage"]] = relationship(
        back_populates="owner",
        cascade="all, delete-orphan",
        order_by="EmailMessage.received_at.desc()",
    )

    def __repr__(self) -> str:
        return f"<User(id={self.id}, email='{self.email}', display_name='{self.display_name}')>"
