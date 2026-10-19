"""Structured logging system with sensitive data redaction for AEGIS-CORE.

Ensures security firewall logs comply with data provenance standards and never
leak credentials, API keys, or authorization tokens in development or production.
"""

import json
import logging
import re
import sys
from datetime import UTC, datetime
from typing import Any

from app.core.config import Settings

# Sensitive key patterns that must be redacted in logs
SENSITIVE_KEY_PATTERNS = re.compile(
    r"(password|secret|token|api_?key|access_?token|refresh_?token|auth|credential|private_?key)",
    re.IGNORECASE,
)

# Regex pattern to redact Bearer tokens or authorization headers in raw strings
BEARER_PATTERN = re.compile(r"(Bearer\s+)[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE)
GENERIC_SECRET_PATTERN = re.compile(
    r"(secret_key|api_key|password)\s*[:=]\s*['\"]?([A-Za-z0-9\-._~+/]+)['\"]?",
    re.IGNORECASE,
)


def mask_sensitive_value(value: Any) -> Any:
    """Recursively scrub sensitive keys and token values from data structures."""
    if isinstance(value, dict):
        scrubbed: dict[str, Any] = {}
        for k, v in value.items():
            if SENSITIVE_KEY_PATTERNS.search(str(k)):
                scrubbed[k] = "[REDACTED]"
            else:
                scrubbed[k] = mask_sensitive_value(v)
        return scrubbed
    if isinstance(value, list):
        return [mask_sensitive_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(mask_sensitive_value(item) for item in value)
    if isinstance(value, str):
        masked = BEARER_PATTERN.sub(r"\1[REDACTED]", value)
        masked = GENERIC_SECRET_PATTERN.sub(r"\1=[REDACTED]", masked)
        return masked
    return value


class SensitiveDataFilter(logging.Filter):
    """Logging filter that scrubs sensitive information from log record messages and arguments."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = mask_sensitive_value(record.msg)
        elif isinstance(record.msg, dict):
            record.msg = json.dumps(mask_sensitive_value(record.msg))

        if record.args:
            if isinstance(record.args, dict):
                record.args = mask_sensitive_value(record.args)
            elif isinstance(record.args, tuple):
                record.args = tuple(mask_sensitive_value(arg) for arg in record.args)
        return True


class JSONFormatter(logging.Formatter):
    """Structured JSON formatter for machine ingestion and security audit pipelines."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Include exception tracebacks if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        # Include custom extra attributes
        standard_attrs = {
            "name",
            "msg",
            "args",
            "levelname",
            "levelno",
            "pathname",
            "filename",
            "module",
            "exc_info",
            "exc_text",
            "stack_info",
            "lineno",
            "funcName",
            "created",
            "msecs",
            "relativeCreated",
            "thread",
            "threadName",
            "processName",
            "process",
            "message",
        }
        extras = {
            k: mask_sensitive_value(v)
            for k, v in record.__dict__.items()
            if k not in standard_attrs and not k.startswith("_")
        }
        if extras:
            log_entry["extra"] = extras

        return json.dumps(log_entry, default=str)


class ConsoleFormatter(logging.Formatter):
    """Clean, human-readable formatter for local development console."""

    COLORS = {
        "DEBUG": "\033[36m",  # Cyan
        "INFO": "\033[32m",  # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",  # Red
        "CRITICAL": "\033[35m",  # Magenta
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, self.RESET)
        timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
        prefix = (
            f"[{timestamp}] [{color}{record.levelname:<8}{self.RESET}] [{record.name}]"
        )
        message = record.getMessage()

        base_output = f"{prefix} {message}"
        if record.exc_info:
            base_output += "\n" + self.formatException(record.exc_info)
        return base_output


def setup_logging(settings: Settings) -> None:
    """Initialize structured logging according to application settings."""
    root_logger = logging.getLogger()
    root_logger.setLevel(settings.LOG_LEVEL)

    # Clear any pre-existing handlers
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(settings.LOG_LEVEL)

    # Attach sensitive data scrubber
    console_handler.addFilter(SensitiveDataFilter())

    # Set appropriate formatter
    if settings.LOG_FORMAT == "json":
        console_handler.setFormatter(JSONFormatter())
    else:
        console_handler.setFormatter(ConsoleFormatter())

    root_logger.addHandler(console_handler)

    # Adjust third-party loggers to avoid noise
    logging.getLogger("uvicorn.access").setLevel(logging.INFO)
    logging.getLogger("uvicorn.error").setLevel(logging.INFO)
    logging.getLogger("sqlalchemy.engine").setLevel(
        logging.INFO if settings.DATABASE_ECHO else logging.WARNING
    )


def get_logger(name: str) -> logging.Logger:
    """Return a typed logger instance scoped to the specified module."""
    return logging.getLogger(name)
