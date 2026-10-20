"""OpenAI Provider implementation for AEGIS-CORE using the official OpenAI Python SDK.

Supports tool-calling chat completions with configurable models, timeouts,
and structured exception mapping.
"""

from typing import Any

from openai import (
    APITimeoutError,
    AuthenticationError,
    OpenAI,
    OpenAIError,
)

from app.agent.providers.base import (
    BaseLLMProvider,
    ChatMessage,
    LLMResponse,
    ProviderAPIError,
    ProviderConfigError,
    ProviderTimeoutError,
    ToolCall,
)
from app.core.config import get_settings


class OpenAIProvider(BaseLLMProvider):
    """Production LLM provider integrating with OpenAI's Chat Completions API."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        timeout: float | None = None,
        max_output_tokens: int | None = None,
        client: OpenAI | None = None,
    ) -> None:
        settings = get_settings()

        self._api_key = api_key or settings.OPENAI_API_KEY
        self._base_url = base_url or settings.OPENAI_BASE_URL
        self._model = model or settings.OPENAI_MODEL
        self._timeout = (
            timeout if timeout is not None else settings.AGENT_MODEL_TIMEOUT_SECONDS
        )
        self._max_output_tokens = (
            max_output_tokens
            if max_output_tokens is not None
            else settings.AGENT_MAX_OUTPUT_TOKENS
        )

        # Allow injected client for testing and dependency injection
        self._client = client

    @property
    def provider_name(self) -> str:
        return "openai"

    @property
    def model_name(self) -> str:
        return self._model

    def _get_client(self) -> OpenAI:
        """Lazily initialize or return the OpenAI SDK client."""
        if self._client is not None:
            return self._client

        if not self._api_key or not self._api_key.strip():
            raise ProviderConfigError(
                "OpenAI API key is not configured. Please set the OPENAI_API_KEY "
                "environment variable or pass api_key to OpenAIProvider. "
                "For local testing and offline development, use LLM_PROVIDER=fake. "
                "See docs/agent-provider.md for setup instructions."
            )

        kwargs: dict[str, Any] = {
            "api_key": self._api_key,
            "timeout": self._timeout,
        }
        if self._base_url:
            kwargs["base_url"] = self._base_url

        self._client = OpenAI(**kwargs)
        return self._client

    def _format_messages_for_api(
        self, messages: list[ChatMessage]
    ) -> list[dict[str, Any]]:
        """Format normalized ChatMessages into OpenAI Chat Completion payload."""
        payload: list[dict[str, Any]] = []

        for msg in messages:
            if msg.role == "system":
                payload.append({"role": "system", "content": msg.content or ""})
            elif msg.role == "user":
                payload.append({"role": "user", "content": msg.content or ""})
            elif msg.role == "assistant":
                entry: dict[str, Any] = {
                    "role": "assistant",
                    "content": msg.content,
                }
                if msg.tool_calls:
                    entry["tool_calls"] = [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.name,
                                "arguments": tc.arguments,
                            },
                        }
                        for tc in msg.tool_calls
                    ]
                payload.append(entry)
            elif msg.role == "tool":
                payload.append(
                    {
                        "role": "tool",
                        "tool_call_id": msg.tool_call_id or "",
                        "content": msg.content or "",
                    }
                )

        return payload

    def generate(
        self,
        messages: list[ChatMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> LLMResponse:
        """Execute a tool-calling chat completion via OpenAI SDK."""
        client = self._get_client()
        formatted_messages = self._format_messages_for_api(messages)

        request_kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": formatted_messages,
            "timeout": self._timeout,
        }
        if tools:
            request_kwargs["tools"] = tools
        if self._max_output_tokens:
            request_kwargs["max_tokens"] = self._max_output_tokens

        try:
            response = client.chat.completions.create(**request_kwargs)
        except APITimeoutError as err:
            raise ProviderTimeoutError(
                f"OpenAI request timed out after {self._timeout}s: {err}"
            ) from err
        except AuthenticationError as err:
            raise ProviderConfigError(
                f"OpenAI authentication failed. Verify your OPENAI_API_KEY: {err}"
            ) from err
        except OpenAIError as err:
            raise ProviderAPIError(f"OpenAI API error: {err}") from err
        except Exception as err:
            raise ProviderAPIError(
                f"Unexpected error calling OpenAI API: {err}"
            ) from err

        choice = response.choices[0]
        choice_msg = choice.message

        tool_calls: list[ToolCall] = []
        if choice_msg.tool_calls:
            for tc in choice_msg.tool_calls:
                tool_calls.append(
                    ToolCall(
                        id=tc.id,
                        name=tc.function.name,
                        arguments=tc.function.arguments,
                    )
                )

        usage_dict: dict[str, int] = {}
        if response.usage:
            usage_dict = {
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
                "total_tokens": response.usage.total_tokens,
            }

        return LLMResponse(
            content=choice_msg.content,
            tool_calls=tool_calls,
            finish_reason=choice.finish_reason,
            model=response.model or self._model,
            usage=usage_dict,
        )
