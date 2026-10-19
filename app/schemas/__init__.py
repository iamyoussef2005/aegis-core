"""Pydantic request and response schemas for AEGIS-CORE."""

from app.schemas.email import (
    EmailCountResponse,
    EmailListResponse,
    EmailMessageBase,
    EmailMessageCreate,
    EmailMessageResponse,
)
from app.schemas.health import DatabaseHealth, HealthResponse
from app.schemas.user import UserBase, UserCreate, UserResponse

__all__ = [
    "DatabaseHealth",
    "EmailCountResponse",
    "EmailListResponse",
    "EmailMessageBase",
    "EmailMessageCreate",
    "EmailMessageResponse",
    "HealthResponse",
    "UserBase",
    "UserCreate",
    "UserResponse",
]
