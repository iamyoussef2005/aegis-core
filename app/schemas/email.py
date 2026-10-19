"""Pydantic v2 schemas for EmailMessage entities."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class EmailMessageBase(BaseModel):
    """Shared properties for EmailMessage models."""

    sender: str = Field(
        ..., min_length=1, max_length=255, description="Sender email address or name"
    )
    recipient: str = Field(
        ..., min_length=1, max_length=255, description="Recipient email address"
    )
    subject: str = Field(
        ..., min_length=1, max_length=500, description="Email subject line"
    )
    body: str = Field(..., description="Email body content in plain text or markdown")
    is_read: bool = Field(
        default=False, description="Whether the message has been read"
    )
    received_at: datetime = Field(
        ..., description="Timestamp when message was received in UTC"
    )


class EmailMessageCreate(EmailMessageBase):
    """Schema for creating a new EmailMessage."""

    owner_id: int = Field(..., description="ID of the user who owns this email inbox")
    created_at: datetime | None = Field(
        default=None, description="Optional creation timestamp in UTC"
    )


class EmailMessageResponse(EmailMessageBase):
    """Schema for reading EmailMessage data."""

    model_config = ConfigDict(from_attributes=True)

    id: int = Field(..., description="Unique email identifier")
    owner_id: int = Field(..., description="ID of the owning user")
    created_at: datetime = Field(..., description="Record creation timestamp in UTC")


class EmailListResponse(BaseModel):
    """Paginated collection of emails for a given owner."""

    items: list[EmailMessageResponse] = Field(
        default_factory=list, description="List of email records"
    )
    total: int = Field(ge=0, description="Total matching emails for this owner")
    owner_id: int = Field(description="ID of the owning user")
    skip: int = Field(default=0, ge=0, description="Pagination offset")
    limit: int = Field(default=100, ge=1, description="Pagination limit")
