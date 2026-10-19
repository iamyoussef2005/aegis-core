"""Pydantic v2 schemas for User entities."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class UserBase(BaseModel):
    """Shared properties for User models."""

    display_name: str = Field(
        ...,
        min_length=1,
        max_length=150,
        description="Full name or display handle",
    )
    email: str = Field(
        ...,
        min_length=3,
        max_length=255,
        description="Unique user email address",
    )


class UserCreate(UserBase):
    """Schema for creating a new User."""

    created_at: datetime | None = Field(
        default=None,
        description="Optional fixed timestamp for deterministic creation",
    )


class UserResponse(UserBase):
    """Schema for reading User data."""

    model_config = ConfigDict(from_attributes=True)

    id: int = Field(..., description="Unique database identifier")
    created_at: datetime = Field(
        ..., description="Timestamp of user account creation in UTC"
    )
