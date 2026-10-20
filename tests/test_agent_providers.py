"""Unit and integration tests for AEGIS-CORE LLM Providers, Tool Registry, and Agent Runner.

Verifies:
- Tool definition generation conforming to OpenAI schema.
- Server-side user_id identity invariance (model cannot change user_id).
- Unknown tool rejection and argument validation.
- FakeLLMProvider deterministic completions and canned responses.
- OpenAIProvider configuration, message translation, error mapping, and timeout handling.
- AgentRunner multi-turn tool calling, bounds enforcement, and error resilience.
- All tests execute strictly offline without external network dependencies or real API keys.
"""

import json
from typing import Any
from unittest.mock import MagicMock

import pytest
from openai import APITimeoutError, AuthenticationError, OpenAIError
from sqlalchemy.orm import Session

from app.agent.prompts import DEFAULT_SYSTEM_PROMPT, build_system_prompt
from app.agent.providers import (
    ChatMessage,
    FakeLLMProvider,
    LLMResponse,
    OpenAIProvider,
    ProviderAPIError,
    ProviderConfigError,
    ProviderTimeoutError,
    ToolCall,
    get_provider,
)
from app.agent.runner import AgentExecutionResult, AgentRunner
from app.agent.tool_registry import (
    ALLOWED_TOOL_NAMES,
    ToolRegistry,
    default_tool_registry,
)
from app.core.config import Settings

# ==============================================================================
# Category 1: Tool Registry & Schema Conversion Tests
# ==============================================================================


def test_tool_registry_openai_definitions() -> None:
    """Verify tool definitions are generated in standard OpenAI function format."""
    registry = ToolRegistry()
    defs = registry.get_openai_tool_definitions()

    assert len(defs) == 3
    names = {d["function"]["name"] for d in defs}
    assert names == ALLOWED_TOOL_NAMES

    for d in defs:
        assert d["type"] == "function"
        fn = d["function"]
        assert "description" in fn
        assert "parameters" in fn
        params = fn["parameters"]
        assert params["type"] == "object"
        assert "properties" in params

        # CRITICAL SECURITY INVARIANT:
        # user_id must NOT be exposed in LLM parameter schemas!
        assert "user_id" not in params["properties"], (
            f"user_id leaked in parameters schema of {fn['name']}"
        )


def test_tool_registry_unknown_tool_rejection() -> None:
    """Verify registry rejects unknown tools not in the strict allowlist."""
    registry = ToolRegistry()

    assert registry.validate_tool_name("read_inbox") is True
    assert registry.validate_tool_name("send_email") is False
    assert registry.validate_tool_name("delete_email") is False
    assert registry.validate_tool_name("execute_script") is False

    # Attempt execution of forbidden tool
    result = registry.execute_tool(
        tool_name="delete_email",
        raw_arguments={"email_id": 1},
        user_id=1,
    )
    assert result.success is False
    assert result.error is not None
    assert result.error.code == "UNKNOWN_TOOL"


def test_tool_registry_malformed_json_arguments() -> None:
    """Verify registry produces structured error on malformed JSON arguments."""
    registry = ToolRegistry()
    result = registry.execute_tool(
        tool_name="read_inbox",
        raw_arguments="{not a valid json",
        user_id=1,
    )

    assert result.success is False
    assert result.error is not None
    assert result.error.code == "INVALID_ARGUMENTS_JSON"


def test_tool_registry_argument_validation_errors() -> None:
    """Verify registry validates arguments against Pydantic models."""
    registry = ToolRegistry()

    # read_inbox limit exceeds bounds (>20)
    res_inbox = registry.execute_tool(
        tool_name="read_inbox",
        raw_arguments={"limit": 50},
        user_id=1,
    )
    assert res_inbox.success is False
    assert res_inbox.error is not None
    assert res_inbox.error.code == "VALIDATION_ERROR"

    # search_emails empty query
    res_search = registry.execute_tool(
        tool_name="search_emails",
        raw_arguments={"query": "   "},
        user_id=1,
    )
    assert res_search.success is False
    assert res_search.error is not None
    assert res_search.error.code == "VALIDATION_ERROR"

    # get_email_details non-positive ID
    res_detail = registry.execute_tool(
        tool_name="get_email_details",
        raw_arguments={"email_id": 0},
        user_id=1,
    )
    assert res_detail.success is False
    assert res_detail.error is not None
    assert res_detail.error.code == "VALIDATION_ERROR"


def test_tool_registry_server_identity_invariance(seeded_session: Session) -> None:
    """CRITICAL SECURITY TEST: Model attempting to pass user_id cannot override server identity."""
    registry = ToolRegistry()

    # Adversarial argument payload: model attempts to inspect user 2's inbox while session is for user 1
    malicious_args = {"user_id": 2, "limit": 5}
    result = registry.execute_tool(
        tool_name="read_inbox",
        raw_arguments=malicious_args,
        user_id=1,  # Server-verified identity
        session=seeded_session,
    )

    assert result.success is True
    assert result.data is not None
    # Must be bound to user 1, completely ignoring malicious "user_id": 2
    assert result.data.owner_id == 1
    assert all(e.owner_id == 1 for e in result.data.emails)

    # Adversarial single-email lookup: model tries to access email 11 (owned by user 2)
    malicious_detail_args = {"user_id": 2, "email_id": 11}
    detail_res = registry.execute_tool(
        tool_name="get_email_details",
        raw_arguments=malicious_detail_args,
        user_id=1,
        session=seeded_session,
    )
    assert detail_res.success is False
    assert detail_res.error is not None
    # Returns EMAIL_NOT_FOUND scoped to user 1
    assert detail_res.error.code == "EMAIL_NOT_FOUND"
    assert "user 1" in detail_res.error.message


def test_tool_registry_formatting_for_llm() -> None:
    """Verify tool output formatting embeds untrusted data notices."""
    registry = ToolRegistry()

    # Format success
    success_res = registry.execute_tool(
        tool_name="read_inbox",
        raw_arguments={"limit": 1},
        user_id=1,
    )
    formatted = registry.format_tool_result_for_llm("read_inbox", success_res)
    assert "[TOOL_RESULT: read_inbox]" in formatted
    assert "STATUS: SUCCESS" in formatted
    assert "UNTRUSTED SIMULATED CONTENT" in formatted

    # Format error
    err_res = registry.execute_tool(
        tool_name="unknown_tool",
        raw_arguments={},
        user_id=1,
    )
    err_formatted = registry.format_tool_result_for_llm("unknown_tool", err_res)
    assert "STATUS: ERROR (UNKNOWN_TOOL)" in err_formatted


# ==============================================================================
# Category 2: Prompts Tests
# ==============================================================================


def test_prompts_content_and_defense_instructions() -> None:
    """Verify system prompt enforces indirect prompt-injection and read-only boundaries."""
    prompt = build_system_prompt(user_id=1, user_display_name="Dr. Layla")

    assert "Active User ID: 1 (Dr. Layla)" in prompt
    assert "UNTRUSTED DATA SEPARATION" in prompt
    assert "SYSTEM INSTRUCTION OVERRIDE" in prompt
    assert "READ-ONLY CONSTRAINT" in prompt
    assert "Arabic" in prompt
    assert DEFAULT_SYSTEM_PROMPT.strip() in prompt


# ==============================================================================
# Category 3: FakeLLMProvider Tests
# ==============================================================================


def test_fake_provider_deterministic_behavior() -> None:
    """Verify FakeLLMProvider returns rule-based completions matching user intent."""
    provider = FakeLLMProvider()

    # 1. Greeting / generic message
    res_greet = provider.generate([ChatMessage(role="user", content="Hello")])
    assert res_greet.has_tool_calls is False
    assert "ready to assist" in res_greet.content

    # 2. Inbox request triggers read_inbox tool call
    res_inbox = provider.generate(
        [ChatMessage(role="user", content="Show my recent emails")]
    )
    assert res_inbox.has_tool_calls is True
    assert res_inbox.tool_calls[0].name == "read_inbox"

    # 3. Search request triggers search_emails tool call
    res_search = provider.generate(
        [ChatMessage(role="user", content="Search for algorithms")]
    )
    assert res_search.has_tool_calls is True
    assert res_search.tool_calls[0].name == "search_emails"
    args = json.loads(res_search.tool_calls[0].arguments)
    assert "algorithms" in args["query"].lower()

    # 4. Detail request triggers get_email_details tool call
    res_detail = provider.generate([ChatMessage(role="user", content="Read email 7")])
    assert res_detail.has_tool_calls is True
    assert res_detail.tool_calls[0].name == "get_email_details"
    args = json.loads(res_detail.tool_calls[0].arguments)
    assert args["email_id"] == 7

    # 5. Tool response generates summary
    tool_msg = ChatMessage(
        role="tool",
        tool_call_id="call_1",
        name="read_inbox",
        content="[TOOL_RESULT: read_inbox]\nSTATUS: SUCCESS\nDATA: {...}\n[END_TOOL_RESULT]",
    )
    res_summary = provider.generate([tool_msg])
    assert res_summary.has_tool_calls is False
    assert (
        "retrieved and summarized" in res_summary.content
        or "retrieved and reviewed" in res_summary.content
    )


def test_fake_provider_canned_responses() -> None:
    """Verify canned responses are served in FIFO sequence."""
    provider = FakeLLMProvider()
    canned1 = LLMResponse(content="First answer", finish_reason="stop")
    canned2 = LLMResponse(content="Second answer", finish_reason="stop")

    provider.add_canned_response(canned1)
    provider.add_canned_response(canned2)

    res1 = provider.generate([ChatMessage(role="user", content="Q1")])
    res2 = provider.generate([ChatMessage(role="user", content="Q2")])

    assert res1.content == "First answer"
    assert res2.content == "Second answer"


def test_fake_provider_error_simulation() -> None:
    """Verify FakeLLMProvider can simulate timeouts and API errors."""
    timeout_provider = FakeLLMProvider(force_timeout=True)
    with pytest.raises(ProviderTimeoutError, match="timed out"):
        timeout_provider.generate([ChatMessage(role="user", content="Test")])

    error_provider = FakeLLMProvider(force_api_error=True)
    with pytest.raises(ProviderAPIError, match="simulated upstream"):
        error_provider.generate([ChatMessage(role="user", content="Test")])


# ==============================================================================
# Category 4: OpenAIProvider Unit Tests (Mocked Client)
# ==============================================================================


def test_openai_provider_missing_key_fails_gracefully(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify OpenAIProvider raises ProviderConfigError when no key is set."""
    monkeypatch.setattr(
        "app.core.config.get_settings", lambda: Settings(OPENAI_API_KEY=None)
    )
    provider = OpenAIProvider(api_key=None)

    with pytest.raises(ProviderConfigError, match="OpenAI API key is not configured"):
        provider.generate([ChatMessage(role="user", content="Hi")])


def test_openai_provider_with_mocked_client() -> None:
    """Verify OpenAIProvider correctly formats requests and parses completions."""
    mock_client = MagicMock()
    mock_choice = MagicMock()
    mock_choice.finish_reason = "stop"
    mock_choice.message.content = "Mocked assistant answer"
    mock_choice.message.tool_calls = None

    mock_response = MagicMock()
    mock_response.choices = [mock_choice]
    mock_response.model = "gpt-4o-mini"
    mock_response.usage.prompt_tokens = 10
    mock_response.usage.completion_tokens = 5
    mock_response.usage.total_tokens = 15

    mock_client.chat.completions.create.return_value = mock_response

    provider = OpenAIProvider(
        api_key="sk-mocked-key",
        model="gpt-4o-mini",
        client=mock_client,
    )

    messages = [
        ChatMessage(role="system", content="System instruction"),
        ChatMessage(role="user", content="User question"),
    ]
    res = provider.generate(
        messages, tools=[{"type": "function", "function": {"name": "test"}}]
    )

    assert res.content == "Mocked assistant answer"
    assert res.has_tool_calls is False
    assert res.model == "gpt-4o-mini"
    assert res.usage["total_tokens"] == 15

    # Check call arguments passed to mock
    mock_client.chat.completions.create.assert_called_once()
    kwargs = mock_client.chat.completions.create.call_args.kwargs
    assert kwargs["model"] == "gpt-4o-mini"
    assert len(kwargs["messages"]) == 2
    assert kwargs["messages"][0] == {"role": "system", "content": "System instruction"}
    assert kwargs["messages"][1] == {"role": "user", "content": "User question"}


def test_openai_provider_tool_calls_parsing() -> None:
    """Verify OpenAIProvider parses returned tool calls accurately."""
    mock_client = MagicMock()
    mock_tool_call = MagicMock()
    mock_tool_call.id = "call_abc123"
    mock_tool_call.function.name = "read_inbox"
    mock_tool_call.function.arguments = '{"limit": 3}'

    mock_choice = MagicMock()
    mock_choice.finish_reason = "tool_calls"
    mock_choice.message.content = None
    mock_choice.message.tool_calls = [mock_tool_call]

    mock_response = MagicMock()
    mock_response.choices = [mock_choice]
    mock_response.model = "gpt-4o-mini"
    mock_response.usage = None

    mock_client.chat.completions.create.return_value = mock_response

    provider = OpenAIProvider(
        api_key="sk-mocked-key",
        client=mock_client,
    )

    res = provider.generate([ChatMessage(role="user", content="Read inbox")])

    assert res.has_tool_calls is True
    assert len(res.tool_calls) == 1
    assert res.tool_calls[0].id == "call_abc123"
    assert res.tool_calls[0].name == "read_inbox"
    assert res.tool_calls[0].arguments == '{"limit": 3}'


def test_openai_provider_error_mapping() -> None:
    """Verify OpenAI SDK exceptions map to AEGIS-CORE ProviderError hierarchy."""
    mock_client = MagicMock()

    # 1. APITimeoutError -> ProviderTimeoutError
    mock_client.chat.completions.create.side_effect = APITimeoutError(
        request=MagicMock()
    )
    provider = OpenAIProvider(api_key="sk-test", client=mock_client)
    with pytest.raises(ProviderTimeoutError, match="timed out"):
        provider.generate([ChatMessage(role="user", content="Test")])

    # 2. AuthenticationError -> ProviderConfigError
    mock_client.chat.completions.create.side_effect = AuthenticationError(
        message="Invalid API Key", response=MagicMock(), body=None
    )
    with pytest.raises(ProviderConfigError, match="authentication failed"):
        provider.generate([ChatMessage(role="user", content="Test")])

    # 3. OpenAIError -> ProviderAPIError
    mock_client.chat.completions.create.side_effect = OpenAIError("Generic API error")
    with pytest.raises(ProviderAPIError, match="OpenAI API error"):
        provider.generate([ChatMessage(role="user", content="Test")])


# ==============================================================================
# Category 5: AgentRunner Multi-Turn Execution Tests
# ==============================================================================


def test_agent_runner_inbox_task_with_fake_provider(seeded_session: Session) -> None:
    """Test full multi-turn execution reading inbox with FakeLLMProvider."""
    runner = AgentRunner(
        provider=FakeLLMProvider(),
        tool_registry=default_tool_registry,
    )

    result = runner.run(
        user_id=1,
        prompt="Please check my recent emails",
        session=seeded_session,
    )

    assert isinstance(result, AgentExecutionResult)
    assert result.success is True
    assert result.user_id == 1
    assert result.tool_calls_count == 1
    assert len(result.tool_executions) == 1
    assert result.tool_executions[0]["tool_name"] == "read_inbox"
    assert result.tool_executions[0]["success"] is True
    assert len(result.final_answer) > 0


def test_agent_runner_search_task_with_fake_provider(seeded_session: Session) -> None:
    """Test multi-turn execution searching emails with FakeLLMProvider."""
    runner = AgentRunner(
        provider=FakeLLMProvider(),
        tool_registry=default_tool_registry,
    )

    result = runner.run(
        user_id=1,
        prompt="Search for Teaching Evaluation in my inbox",
        session=seeded_session,
    )

    assert result.success is True
    assert result.tool_calls_count == 1
    assert result.tool_executions[0]["tool_name"] == "search_emails"
    assert result.tool_executions[0]["success"] is True


def test_agent_runner_arabic_content_with_fake_provider(
    seeded_session: Session,
) -> None:
    """Test multi-turn execution handling Arabic query and Arabic response."""
    runner = AgentRunner(
        provider=FakeLLMProvider(),
        tool_registry=default_tool_registry,
    )

    result = runner.run(
        user_id=1,
        prompt="ابحث عن رسائل المختبر في بريدي الأكاديمي",
        session=seeded_session,
    )

    assert result.success is True
    assert result.tool_calls_count == 1
    assert result.tool_executions[0]["tool_name"] == "search_emails"
    # Verify Arabic text returned in final answer
    assert "بريدك الأكاديمي" in result.final_answer


def test_agent_runner_direct_response_without_tools() -> None:
    """Test agent responds directly without tools for general queries."""
    runner = AgentRunner(provider=FakeLLMProvider())
    result = runner.run(user_id=1, prompt="Hello there!")

    assert result.success is True
    assert result.tool_calls_count == 0
    assert len(result.tool_executions) == 0
    assert "ready to assist" in result.final_answer


def test_agent_runner_max_tool_calls_bounded() -> None:
    """Test agent runner enforces maximum tool call limit."""
    # Program a provider that continuously requests tool calls
    infinite_tool_provider = FakeLLMProvider(
        canned_responses=[
            LLMResponse(
                tool_calls=[
                    ToolCall(id=f"c_{i}", name="read_inbox", arguments='{"limit": 1}')
                ],
                finish_reason="tool_calls",
            )
            for i in range(10)
        ]
        + [LLMResponse(content="Final synthesis after limit", finish_reason="stop")]
    )

    runner = AgentRunner(
        provider=infinite_tool_provider,
        max_tool_calls=2,  # Strict bound
    )

    result = runner.run(user_id=1, prompt="Loop test")

    assert result.success is True
    assert result.tool_calls_count == 2
    assert result.finish_reason == "max_tool_calls_exceeded"


def test_agent_runner_invalid_inputs() -> None:
    """Test agent runner input validation on user_id and prompt."""
    runner = AgentRunner(provider=FakeLLMProvider())

    # Invalid user_id
    res_id = runner.run(user_id=0, prompt="Hello")
    assert res_id.success is False
    assert "Invalid user_id" in res_id.error

    # Empty prompt
    res_prompt = runner.run(user_id=1, prompt="   ")
    assert res_prompt.success is False
    assert "Prompt cannot be empty" in res_prompt.error


def test_agent_runner_provider_error_handling() -> None:
    """Test agent runner cleanly captures provider timeouts and errors."""
    failing_provider = FakeLLMProvider(force_timeout=True)
    runner = AgentRunner(provider=failing_provider)

    result = runner.run(user_id=1, prompt="Check mail")

    assert result.success is False
    assert "timed out" in result.error
    assert result.finish_reason == "provider_error"


def test_get_provider_factory() -> None:
    """Verify get_provider factory instantiates correct provider types."""
    fake = get_provider("fake")
    assert isinstance(fake, FakeLLMProvider)

    openai_p = get_provider("openai", api_key="sk-test-fake")
    assert isinstance(openai_p, OpenAIProvider)

    with pytest.raises(ProviderConfigError, match="Unsupported LLM_PROVIDER"):
        get_provider("unsupported_provider")


def test_openai_provider_message_formatting_and_client_init() -> None:
    """Verify OpenAIProvider formats complex multi-turn histories and initializes client."""
    provider = OpenAIProvider(
        api_key="sk-test-live",
        base_url="https://api.openai.com/v1",
        model="gpt-4o",
    )
    assert provider.provider_name == "openai"
    assert provider.model_name == "gpt-4o"

    # Verify client initialization
    client = provider._get_client()
    assert client.api_key == "sk-test-live"
    assert "https://api.openai.com/v1" in str(client.base_url)

    # Test formatting with system, user, assistant with tool_calls, and tool messages
    messages = [
        ChatMessage(role="system", content="System instruction"),
        ChatMessage(role="user", content="Read email 5"),
        ChatMessage(
            role="assistant",
            content=None,
            tool_calls=[
                ToolCall(
                    id="c_1", name="get_email_details", arguments='{"email_id": 5}'
                )
            ],
        ),
        ChatMessage(
            role="tool",
            tool_call_id="c_1",
            name="get_email_details",
            content="[TOOL_RESULT: get_email_details]\nSTATUS: SUCCESS\nDATA: {}\n[END_TOOL_RESULT]",
        ),
    ]

    formatted = provider._format_messages_for_api(messages)
    assert len(formatted) == 4
    assert formatted[0] == {"role": "system", "content": "System instruction"}
    assert formatted[1] == {"role": "user", "content": "Read email 5"}
    assert formatted[2]["role"] == "assistant"
    assert formatted[2]["tool_calls"][0]["function"]["name"] == "get_email_details"
    assert formatted[3]["role"] == "tool"
    assert formatted[3]["tool_call_id"] == "c_1"


def test_openai_provider_unexpected_exception() -> None:
    """Verify OpenAIProvider handles unexpected generic exceptions."""
    mock_client = MagicMock()
    mock_client.chat.completions.create.side_effect = RuntimeError("Socket dropped")
    provider = OpenAIProvider(api_key="sk-test", client=mock_client)

    with pytest.raises(ProviderAPIError, match="Unexpected error calling OpenAI API"):
        provider.generate([ChatMessage(role="user", content="Hi")])


def test_fake_provider_edge_cases() -> None:
    """Verify FakeLLMProvider empty messages and property getters."""
    provider = FakeLLMProvider()
    assert provider.provider_name == "fake"
    assert provider.model_name == "fake-deterministic-model"

    # Empty message list
    res_empty = provider.generate([])
    assert "Hello" in res_empty.content

    # Tool message with error status
    res_err = provider.generate(
        [
            ChatMessage(
                role="tool",
                tool_call_id="c1",
                content="[TOOL_RESULT: get_email_details]\nSTATUS: ERROR (NOT_FOUND)",
            )
        ]
    )
    assert "Could not complete" in res_err.content

    # Tool message with Arabic error status
    res_ar_err = provider.generate(
        [
            ChatMessage(role="user", content="ابحث عن رسالة"),
            ChatMessage(
                role="tool",
                tool_call_id="c1",
                content="[TOOL_RESULT: search_emails]\nSTATUS: ERROR (NOT_FOUND)",
            ),
        ]
    )
    assert "تعذر" in res_ar_err.content


def test_agent_runner_fallback_on_final_synthesis_error() -> None:
    """Verify AgentRunner falls back gracefully if final synthesis call fails."""

    class FailOnSecondCallProvider(FakeLLMProvider):
        def generate(
            self,
            messages: list[ChatMessage],
            tools: list[dict[str, Any]] | None = None,
        ) -> LLMResponse:
            if self._call_count >= 1:
                raise ProviderAPIError("Simulated synthesis failure")
            return super().generate(messages, tools)

    provider = FailOnSecondCallProvider(
        canned_responses=[
            LLMResponse(
                tool_calls=[
                    ToolCall(id="c_1", name="read_inbox", arguments='{"limit": 1}')
                ],
                finish_reason="tool_calls",
            )
        ]
    )

    runner = AgentRunner(provider=provider, max_tool_calls=1)
    result = runner.run(user_id=1, prompt="Test limit")

    assert result.success is True
    assert result.tool_calls_count == 1
    assert "Maximum tool calls limit reached" in result.final_answer
    assert result.finish_reason == "max_tool_calls_exceeded"
