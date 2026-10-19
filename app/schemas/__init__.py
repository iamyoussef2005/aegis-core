"""Pydantic request and response schemas for AEGIS-CORE."""

from app.schemas.email import (
    EmailListResponse,
    EmailMessageBase,
    EmailMessageCreate,
    EmailMessageResponse,
)
from app.schemas.health import DatabaseHealth, HealthResponse
from app.schemas.user import UserBase, UserCreate, UserResponse

__all__ = [
    "DatabaseHealth",
    "EmailListResponse",
    "EmailMessageBase",
    "EmailMessageCreate",
    "EmailMessageResponse",
    "HealthResponse",
    "UserBase",
    "UserCreate",
    "UserResponse",
]
