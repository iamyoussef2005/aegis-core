"""Environment configuration and application settings for AEGIS-CORE.

Uses Pydantic v2 BaseSettings for type-safe environment variable parsing.
"""

import json
from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application Metadata
    PROJECT_NAME: str = Field(
        default="AEGIS-CORE",
        description="Public display name of the firewall service",
    )
    VERSION: str = Field(
        default="0.1.0",
        description="Application semantic version",
    )
    DESCRIPTION: str = Field(
        default="Research-oriented security firewall for autonomous AI agents",
        description="High-level service description",
    )
    ENVIRONMENT: Literal["development", "staging", "production", "testing"] = Field(
        default="development",
        description="Runtime environment tier",
    )
    DEBUG: bool = Field(
        default=True,
        description="Enable debug mode and verbose tracebacks",
    )

    # Server Settings
    HOST: str = Field(
        default="127.0.0.1",
        description="Host interface to bind HTTP listener",
    )
    PORT: int = Field(
        default=8000,
        description="Port to bind HTTP listener",
    )
    API_V1_PREFIX: str = Field(
        default="/api/v1",
        description="Prefix for v1 REST API routes",
    )

    # Security Configuration
    SECRET_KEY: str = Field(
        default="insecure-dev-secret-key-change-in-production-aegis-core-2026",
        description="Cryptographic secret key for signing tokens and sessions",
    )
    CORS_ORIGINS: list[str] = Field(
        default_factory=lambda: [
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
        ],
        description="Permitted Cross-Origin Resource Sharing origins",
    )

    # Database Configuration
    DATABASE_URL: str = Field(
        default="sqlite:///./aegis.db",
        description="SQLAlchemy database connection URI",
    )
    DATABASE_ECHO: bool = Field(
        default=False,
        description="Echo raw SQL statements to logger (for development debugging)",
    )

    # Logging Configuration
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO",
        description="Standard root log severity threshold",
    )
    LOG_FORMAT: Literal["json", "console"] = Field(
        default="console",
        description="Log output formatting: machine-readable JSON or human-readable console",
    )

    # LLM Provider & Agent Configuration
    LLM_PROVIDER: Literal["fake", "openai"] = Field(
        default="fake",
        description="Active LLM provider: 'fake' for offline/testing or 'openai' for live API",
    )
    OPENAI_API_KEY: str | None = Field(
        default=None,
        description="OpenAI API key (required when LLM_PROVIDER=openai)",
    )
    OPENAI_BASE_URL: str | None = Field(
        default=None,
        description="Optional custom base URL for OpenAI-compatible gateways",
    )
    OPENAI_MODEL: str = Field(
        default="gpt-4o-mini",
        description="Model identifier for OpenAI provider (e.g. gpt-4o-mini, gpt-4o)",
    )
    AGENT_MAX_TOOL_CALLS: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Maximum allowed tool calls per agent invocation",
    )
    AGENT_MODEL_TIMEOUT_SECONDS: float = Field(
        default=30.0,
        ge=1.0,
        le=300.0,
        description="Timeout for LLM API requests in seconds",
    )
    AGENT_MAX_OUTPUT_TOKENS: int = Field(
        default=1024,
        ge=64,
        le=8192,
        description="Upper bound for model response token generation",
    )

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, value: str | list[str]) -> list[str]:
        """Parse CORS_ORIGINS from either a JSON string, comma-separated string, or list."""
        if isinstance(value, str):
            value = value.strip()
            if value.startswith("[") and value.endswith("]"):
                try:
                    parsed = json.loads(value)
                    if isinstance(parsed, list):
                        return [
                            str(item).strip() for item in parsed if str(item).strip()
                        ]
                except json.JSONDecodeError:
                    pass
            return [part.strip() for part in value.split(",") if part.strip()]
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        return []

    @property
    def is_production(self) -> bool:
        """Helper to check if running in production mode."""
        return self.ENVIRONMENT == "production"

    @property
    def is_testing(self) -> bool:
        """Helper to check if running in test suite."""
        return self.ENVIRONMENT == "testing"


@lru_cache
def get_settings() -> Settings:
    """Singleton getter for application settings with LRU cache."""
    return Settings()
