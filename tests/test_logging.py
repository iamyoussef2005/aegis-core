"""Test suite for structured logging and sensitive data scrubbing."""

import json
import logging

from app.core.logging import (
    JSONFormatter,
    SensitiveDataFilter,
    mask_sensitive_value,
)


def test_mask_sensitive_value_dict() -> None:
    """Verify dictionary scrubber redacts sensitive credentials."""
    payload = {
        "user_id": 123,
        "password": "SuperSecretPassword123!",
        "api_key": "ak_live_xyz987654321",
        "nested": {
            "auth_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "safe_field": "visible_value",
        },
    }
    scrubbed = mask_sensitive_value(payload)
    assert scrubbed["user_id"] == 123
    assert scrubbed["password"] == "[REDACTED]"
    assert scrubbed["api_key"] == "[REDACTED]"
    assert scrubbed["nested"]["auth_token"] == "[REDACTED]"
    assert scrubbed["nested"]["safe_field"] == "visible_value"


def test_mask_sensitive_value_bearer_token() -> None:
    """Verify raw strings with Bearer tokens get redacted."""
    raw = "Request failed with header Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.test"
    masked = mask_sensitive_value(raw)
    assert "Bearer [REDACTED]" in masked
    assert "eyJhbGci" not in masked


def test_sensitive_data_filter() -> None:
    """Verify logging filter scrubs records before formatting."""
    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="Connecting using password=my_super_secret_password",
        args=(),
        exc_info=None,
    )
    data_filter = SensitiveDataFilter()
    data_filter.filter(record)
    assert "my_super_secret_password" not in record.msg
    assert "[REDACTED]" in record.msg


def test_json_formatter() -> None:
    """Verify JSONFormatter outputs valid JSON with expected telemetry fields."""
    formatter = JSONFormatter()
    record = logging.LogRecord(
        name="aegis.audit",
        level=logging.WARNING,
        pathname="audit.py",
        lineno=25,
        msg="Tool call blocked: unauthorized operation",
        args=(),
        exc_info=None,
    )
    formatted = formatter.format(record)
    data = json.loads(formatted)

    assert data["level"] == "WARNING"
    assert data["logger"] == "aegis.audit"
    assert data["message"] == "Tool call blocked: unauthorized operation"
    assert "timestamp" in data
    assert data["line"] == 25
