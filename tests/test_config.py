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
