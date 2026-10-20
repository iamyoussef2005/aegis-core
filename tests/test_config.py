"""Test suite for application configuration and environment parsing."""

from app.core.config import Settings


def test_default_settings() -> None:
    """Verify sensible development defaults."""
    settings = Settings()
    assert settings.PROJECT_NAME == "AEGIS-CORE"
    assert settings.VERSION == "0.1.0"
    assert settings.ENVIRONMENT in {"development", "testing"}
    assert settings.API_V1_PREFIX == "/api/v1"
    assert settings.PORT == 8000
    assert "sqlite" in settings.DATABASE_URL


def test_cors_origins_parsing_from_string() -> None:
    """Verify CORS origins parsing from comma-separated string."""
    settings = Settings(CORS_ORIGINS="http://example.com, http://app.local")
    assert settings.CORS_ORIGINS == ["http://example.com", "http://app.local"]


def test_cors_origins_parsing_from_json_string() -> None:
    """Verify CORS origins parsing from JSON array string."""
    settings = Settings(CORS_ORIGINS='["http://alpha.com", "http://beta.com"]')
    assert settings.CORS_ORIGINS == ["http://alpha.com", "http://beta.com"]


def test_environment_helpers() -> None:
    """Verify helper properties for environment detection."""
    prod_settings = Settings(ENVIRONMENT="production")
    assert prod_settings.is_production is True
    assert prod_settings.is_testing is False

    test_settings = Settings(ENVIRONMENT="testing")
    assert test_settings.is_production is False
    assert test_settings.is_testing is True


def test_llm_agent_settings() -> None:
    """Verify LLM and agent configuration defaults and overrides."""
    settings = Settings()
    assert settings.LLM_PROVIDER == "fake"
    assert settings.OPENAI_API_KEY is None
    assert settings.OPENAI_MODEL == "gpt-4o-mini"
    assert settings.AGENT_MAX_TOOL_CALLS == 5
    assert settings.AGENT_MODEL_TIMEOUT_SECONDS == 30.0
    assert settings.AGENT_MAX_OUTPUT_TOKENS == 1024

    custom = Settings(
        LLM_PROVIDER="openai",
        OPENAI_API_KEY="sk-test-key",
        OPENAI_MODEL="gpt-4o",
        AGENT_MAX_TOOL_CALLS=10,
        AGENT_MODEL_TIMEOUT_SECONDS=45.0,
        AGENT_MAX_OUTPUT_TOKENS=2048,
    )
    assert custom.LLM_PROVIDER == "openai"
    assert custom.OPENAI_API_KEY == "sk-test-key"
    assert custom.OPENAI_MODEL == "gpt-4o"
    assert custom.AGENT_MAX_TOOL_CALLS == 10
    assert custom.AGENT_MODEL_TIMEOUT_SECONDS == 45.0
    assert custom.AGENT_MAX_OUTPUT_TOKENS == 2048
