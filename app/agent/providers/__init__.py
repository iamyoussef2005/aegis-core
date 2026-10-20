"""LLM Providers package for AEGIS-CORE.

Provides abstraction, data models, fake deterministic provider, and real OpenAI provider.
"""

from app.agent.providers.base import (
    BaseLLMProvider,
    ChatMessage,
    LLMResponse,
    ProviderAPIError,
    ProviderConfigError,
    ProviderError,
    ProviderTimeoutError,
    ToolCall,
)
from app.agent.providers.fake_provider import FakeLLMProvider
from app.agent.providers.openai_provider import OpenAIProvider
from app.core.config import get_settings


def get_provider(
    provider_type: str | None = None,
    **kwargs,
) -> BaseLLMProvider:
    """Factory creating an LLM provider based on settings or explicit override.

    Args:
        provider_type: "fake" or "openai". If None, reads from Settings.LLM_PROVIDER.
        **kwargs: Optional arguments passed to provider constructor.

    Returns:
        Instance of BaseLLMProvider.
    """
    settings = get_settings()
    active_type = (provider_type or settings.LLM_PROVIDER).lower().strip()

    if active_type == "openai":
        return OpenAIProvider(**kwargs)
    elif active_type == "fake":
        return FakeLLMProvider(**kwargs)
    else:
        raise ProviderConfigError(
            f"Unsupported LLM_PROVIDER: '{active_type}'. Allowed values: 'fake', 'openai'."
        )


__all__ = [
    "BaseLLMProvider",
    "ChatMessage",
    "FakeLLMProvider",
    "LLMResponse",
    "OpenAIProvider",
    "ProviderAPIError",
    "ProviderConfigError",
    "ProviderError",
    "ProviderTimeoutError",
    "ToolCall",
    "get_provider",
]
