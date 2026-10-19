"""Data repositories package for AEGIS-CORE.

Provides abstraction over storage operations, isolating domain logic from
database access patterns.
"""

from app.repositories.base import BaseRepository
from app.repositories.email import (
    EmailRepository,
    count_emails_by_owner,
    get_email_by_id_and_owner,
    list_emails_by_owner,
)
from app.repositories.user import (
    UserRepository,
    get_user_by_email,
    get_user_by_id,
    list_users,
)

__all__ = [
    "BaseRepository",
    "EmailRepository",
    "UserRepository",
    "count_emails_by_owner",
    "get_email_by_id_and_owner",
    "get_user_by_email",
    "get_user_by_id",
    "list_emails_by_owner",
    "list_users",
]
