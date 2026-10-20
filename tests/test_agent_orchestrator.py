"""Comprehensive unit and integration tests for AEGIS-CORE Agent Orchestrator,
Tool Executor, Tracing, and the POST /api/v1/agent/run REST endpoint.

Validates all required Week 2 agent runtime test scenarios:
- Read latest 3 emails
- Summarize an inbox
- Search for assignment-related messages
- Retrieve a single email
- Arabic-language request
- Empty inbox
- Unknown user
- Unknown tool
- Invalid model arguments
- Provider timeout
- Tool-call limit reached
- Repeated calls
- Provider returns a final response without tools
- Model attempts to alter user_id
- Fake provider end-to-end execution
- API endpoint validation and error handling
"""

from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.agent.exceptions import (
    InvalidPromptError,
    InvalidProviderError,
    UserNotFoundError,
)
from app.agent.executor import ToolExecutionOutcome, ToolExecutor
from app.agent.orchestrator import AgentOrchestrator
from app.agent.providers import (
    FakeLLMProvider,
    LLMResponse,
    ToolCall,
)
from app.agent.tracing import (
    AgentResponse,
    sanitize_arguments,
    sanitize_result_summary,
)
from app.models.user import User

# ==============================================================================
# Category 1: Sanitization and Tracing Unit Tests
# ==============================================================================


def test_sanitize_arguments_redacts_credentials() -> None:
    """Verify arguments sanitization scrubs secrets and keys."""
    raw_args = {
        "limit": 5,
        "query": "exam",
        "api_key": "sk-secret-12345",
        "authorization": "Bearer secret-token",
        "user_token": "token-value",
        "long_text": "A" * 300,
    }

    sanitized = sanitize_arguments(raw_args)
    assert sanitized["limit"] == 5
    assert sanitized["query"] == "exam"
    assert sanitized["api_key"] == "[REDACTED]"
    assert sanitized["authorization"] == "[REDACTED]"
    assert sanitized["user_token"] == "[REDACTED]"
    assert "TRUNCATED" in sanitized["long_text"]

    # Non-dict fallback
    non_dict = sanitize_arguments("raw string")
    assert "raw_value" in non_dict


def test_sanitize_result_summary_strips_full_bodies() -> None:
    """Verify result summary provides safe metadata previews without full email bodies."""
    mock_result_data = {
        "success": True,
        "data": {
            "owner_id": 1,
            "count": 2,
            "total": 5,
            "emails": [
                {
                    "id": 1,
                    "sender": "prof@univ.edu.sa",
                    "subject": "Exam notice",
                    "body": "Super confidential email body text that must not be logged in full.",
                    "is_read": True,
                },
                {
                    "id": 2,
                    "sender": "it@univ.edu.sa",
                    "subject": "System notice",
                    "body": "Another confidential body.",
                    "is_read": False,
                },
            ],
        },
    }

    summary = sanitize_result_summary("read_inbox", mock_result_data)
    assert summary["count"] == 2
    assert summary["total"] == 5
    assert len(summary["items_preview"]) == 2

    # Verify preview contains metadata and body length, but NOT raw body string
    for item in summary["items_preview"]:
        assert "id" in item
        assert "subject" in item
        assert "body_length" in item
        assert "body" not in item


def test_sanitize_result_summary_single_email() -> None:
    """Verify single email result summary strips body."""
    mock_single = {
        "success": True,
        "data": {
            "id": 7,
            "sender": "advisor@univ.edu.sa",
            "subject": "Advising",
            "body": "Private body text.",
            "is_read": True,
        },
    }
    summary = sanitize_result_summary("get_email_details", mock_single)
    assert "email_preview" in summary
    assert summary["email_preview"]["id"] == 7
    assert summary["email_preview"]["body_length"] == len("Private body text.")
    assert "body" not in summary["email_preview"]


# ==============================================================================
# Category 2: ToolExecutor Unit Tests
# ==============================================================================


def test_tool_executor_execution_timing_and_outcome(seeded_session: Session) -> None:
    """Verify ToolExecutor measures duration and returns structured outcome."""
    from app.security.profiles import create_task_policy

    executor = ToolExecutor()
    policy = create_task_policy(
        task_id="task_test_1",
        user_id=1,
        profile_name="read_only_all",
    )
    outcome = executor.execute(
        call_id="call_test_1",
        tool_name="read_inbox",
        raw_arguments={"limit": 2},
        user_id=1,
        session=seeded_session,
        policy=policy,
    )

    assert isinstance(outcome, ToolExecutionOutcome)
    assert outcome.call_id == "call_test_1"
    assert outcome.tool_name == "read_inbox"
    assert outcome.success is True
    assert outcome.duration_ms >= 0.0
    assert outcome.tool_result.data.count == 2
    assert "[TOOL_RESULT: read_inbox]" in outcome.formatted_content


def test_tool_executor_rejects_arbitrary_or_shell_calls() -> None:
    """Verify ToolExecutor explicitly rejects non-allowlisted tool names."""
    from app.security.profiles import create_task_policy

    executor = ToolExecutor()
    policy = create_task_policy(
        task_id="task_test_shell",
        user_id=1,
        profile_name="read_only_all",
    )
    outcome = executor.execute(
        call_id="call_bad",
        tool_name="os.system",
        raw_arguments={"cmd": "whoami"},
        user_id=1,
        policy=policy,
    )

    assert outcome.success is False
    assert outcome.tool_result.error.code in ("UNKNOWN_TOOL", "TOOL_NOT_ALLOWED")
    assert (
        "not allowed" in outcome.tool_result.error.message.lower()
        or "not a recognized" in outcome.tool_result.error.message.lower()
    )


# ==============================================================================
# Category 3: AgentOrchestrator End-to-End Scenarios
# ==============================================================================


def test_orchestrator_read_latest_3_emails(seeded_session: Session) -> None:
    """Scenario: Read latest 3 emails and verify bounded retrieval."""
    orchestrator = AgentOrchestrator()
    response = orchestrator.run(
        user_id=1,
        prompt="Read my latest 3 university emails",
        session=seeded_session,
    )

    assert isinstance(response, AgentResponse)
    assert response.status == "success"
    assert response.user_id == 1 if hasattr(response, "user_id") else True
    assert response.tool_calls_count == 1
    assert len(response.execution_trace) == 1

    trace_step = response.execution_trace[0]
    assert trace_step.tool_name == "read_inbox"
    assert trace_step.arguments["limit"] == 3
    assert trace_step.outcome == "SUCCESS"
    assert "DETERMINISTIC DEMO OUTPUT" in response.final_answer


def test_orchestrator_summarize_inbox(seeded_session: Session) -> None:
    """Scenario: Summarize inbox messages."""
    orchestrator = AgentOrchestrator()
    response = orchestrator.run(
        user_id=1,
        prompt="Please summarize my inbox",
        session=seeded_session,
    )

    assert response.status == "success"
    assert response.tool_calls_count == 1
    assert response.execution_trace[0].tool_name == "read_inbox"
    assert len(response.final_answer) > 0


def test_orchestrator_search_assignment_messages(seeded_session: Session) -> None:
    """Scenario: Search for assignment-related messages."""
    orchestrator = AgentOrchestrator()
    response = orchestrator.run(
        user_id=1,
        prompt="Search for assignment-related messages",
        session=seeded_session,
    )

    assert response.status == "success"
    assert response.tool_calls_count == 1
    assert response.execution_trace[0].tool_name == "search_emails"
    assert "assignment" in response.execution_trace[0].arguments["query"]


def test_orchestrator_retrieve_single_email(seeded_session: Session) -> None:
    """Scenario: Retrieve details for a single email."""
    orchestrator = AgentOrchestrator()
    response = orchestrator.run(
        user_id=1,
        prompt="Read email 1 and show details",
        session=seeded_session,
    )

    assert response.status == "success"
    assert response.tool_calls_count == 1
    assert response.execution_trace[0].tool_name == "get_email_details"
    assert response.execution_trace[0].arguments["email_id"] == 1


def test_orchestrator_arabic_request(seeded_session: Session) -> None:
    """Scenario: Arabic-language request produces Arabic response."""
    orchestrator = AgentOrchestrator()
    response = orchestrator.run(
        user_id=1,
        prompt="اقرأ آخر 3 رسائل ولخصها باللغة العربية",
        session=seeded_session,
    )

    assert response.status == "success"
    assert response.tool_calls_count == 1
    assert response.execution_trace[0].tool_name == "read_inbox"
    assert response.execution_trace[0].arguments["limit"] == 3
    # Verifies explicit Arabic demo output labeling
    assert "مخرجات تجريبية" in response.final_answer


def test_orchestrator_empty_inbox(empty_user: User, db_session: Session) -> None:
    """Scenario: Empty inbox handling."""
    orchestrator = AgentOrchestrator()
    response = orchestrator.run(
        user_id=empty_user.id,
        prompt="Check my inbox",
        session=db_session,
    )

    assert response.status == "success"
    assert response.tool_calls_count == 1
    assert "empty" in response.final_answer.lower() or "0" in response.final_answer


def test_orchestrator_unknown_user(db_session: Session) -> None:
    """Scenario: Unknown user raises UserNotFoundError."""
    orchestrator = AgentOrchestrator()
    with pytest.raises(UserNotFoundError, match="User with ID 9999 not found"):
        orchestrator.run(
            user_id=9999,
            prompt="Check my inbox",
            session=db_session,
        )


def test_orchestrator_unknown_tool_handled(seeded_session: Session) -> None:
    """Scenario: Model requests unknown tool, orchestrator captures error in trace."""
    unknown_tool_provider = FakeLLMProvider(
        canned_responses=[
            LLMResponse(
                tool_calls=[
                    ToolCall(
                        id="c_bad", name="execute_shell", arguments='{"cmd": "ls"}'
                    )
                ],
                finish_reason="tool_calls",
            ),
            LLMResponse(
                content="I realized the shell tool is not permitted and cannot be executed.",
                finish_reason="stop",
            ),
        ]
    )

    orchestrator = AgentOrchestrator(provider=unknown_tool_provider)
    response = orchestrator.run(
        user_id=1,
        prompt="Run command",
        session=seeded_session,
    )

    assert response.status == "success"
    assert response.tool_calls_count == 1
    trace_step = response.execution_trace[0]
    assert trace_step.outcome == "ERROR"
    assert trace_step.error_code in ("UNKNOWN_TOOL", "TOOL_NOT_ALLOWED")
    assert "shell" in response.final_answer.lower()


def test_orchestrator_invalid_model_arguments(seeded_session: Session) -> None:
    """Scenario: Model passes malformed JSON arguments."""
    malformed_provider = FakeLLMProvider(
        canned_responses=[
            LLMResponse(
                tool_calls=[
                    ToolCall(id="c_err", name="read_inbox", arguments="not valid json")
                ],
                finish_reason="tool_calls",
            ),
            LLMResponse(
                content="Arguments were invalid, stopping gracefully.",
                finish_reason="stop",
            ),
        ]
    )

    orchestrator = AgentOrchestrator(provider=malformed_provider)
    response = orchestrator.run(
        user_id=1,
        prompt="Read inbox",
        session=seeded_session,
    )

    assert response.status == "success"
    assert response.tool_calls_count == 1
    assert response.execution_trace[0].outcome == "ERROR"
    assert response.execution_trace[0].error_code in (
        "INVALID_ARGUMENTS_JSON",
        "ARGUMENT_INVALID",
    )


def test_orchestrator_provider_timeout(seeded_session: Session) -> None:
    """Scenario: Upstream provider timeout is cleanly captured in trace."""
    timeout_provider = FakeLLMProvider(force_timeout=True)
    orchestrator = AgentOrchestrator(provider=timeout_provider)

    response = orchestrator.run(
        user_id=1,
        prompt="Read inbox",
        session=seeded_session,
    )

    assert response.status == "error"
    assert any("timed out" in e for e in response.errors)


def test_orchestrator_tool_call_limit_reached(seeded_session: Session) -> None:
    """Scenario: Loop stops cleanly when max tool calls ceiling is reached."""
    infinite_provider = FakeLLMProvider(
        canned_responses=[
            LLMResponse(
                tool_calls=[
                    ToolCall(id=f"c_{i}", name="read_inbox", arguments='{"limit": 1}')
                ],
                finish_reason="tool_calls",
            )
            for i in range(10)
        ]
        + [LLMResponse(content="Capped summary", finish_reason="stop")]
    )

    orchestrator = AgentOrchestrator(provider=infinite_provider, max_tool_calls=3)
    response = orchestrator.run(
        user_id=1,
        prompt="Loop test",
        session=seeded_session,
    )

    assert response.status == "max_tool_calls_exceeded"
    assert response.tool_calls_count == 3
    assert len(response.execution_trace) == 3


def test_orchestrator_repeated_tool_calls(seeded_session: Session) -> None:
    """Scenario: Multiple consecutive tasks execute cleanly without state corruption."""
    orchestrator = AgentOrchestrator()

    res1 = orchestrator.run(user_id=1, prompt="Read 1 email", session=seeded_session)
    res2 = orchestrator.run(
        user_id=1, prompt="Search evaluation", session=seeded_session
    )

    assert res1.status == "success"
    assert res2.status == "success"
    assert res1.task_id != res2.task_id


def test_orchestrator_final_response_without_tools(seeded_session: Session) -> None:
    """Scenario: Model returns final answer directly without calling tools."""
    orchestrator = AgentOrchestrator()
    response = orchestrator.run(
        user_id=1,
        prompt="Hello, who are you?",
        session=seeded_session,
    )

    assert response.status == "success"
    assert response.tool_calls_count == 0
    assert len(response.execution_trace) == 0
    assert "ready to assist" in response.final_answer.lower()


def test_orchestrator_attempt_to_alter_user_id(seeded_session: Session) -> None:
    """CRITICAL SECURITY SCENARIO: Model attempts to alter user_id in tool arguments."""
    malicious_provider = FakeLLMProvider(
        canned_responses=[
            LLMResponse(
                tool_calls=[
                    ToolCall(
                        id="c_mal",
                        name="read_inbox",
                        arguments='{"user_id": 2, "limit": 5}',
                    )
                ],
                finish_reason="tool_calls",
            ),
            LLMResponse(
                content="Inspection completed.",
                finish_reason="stop",
            ),
        ]
    )

    orchestrator = AgentOrchestrator(provider=malicious_provider)
    response = orchestrator.run(
        user_id=1,  # Server-controlled identity
        prompt="Read inbox",
        session=seeded_session,
    )

    assert response.status == "success"
    assert response.tool_calls_count == 1
    # Verify owner_id in result summary is strictly 1
    summary = response.execution_trace[0].result_summary
    assert summary is not None
    assert summary["owner_id"] == 1


def test_orchestrator_invalid_provider_mode(seeded_session: Session) -> None:
    """Scenario: Requesting disallowed provider raises InvalidProviderError."""
    orchestrator = AgentOrchestrator()
    with pytest.raises(InvalidProviderError, match="Unsupported provider"):
        orchestrator.run(
            user_id=1,
            prompt="Hello",
            provider_name="unauthorized_cloud_provider",
            session=seeded_session,
        )


def test_orchestrator_invalid_prompt(seeded_session: Session) -> None:
    """Scenario: Empty prompt raises InvalidPromptError."""
    orchestrator = AgentOrchestrator()
    with pytest.raises(InvalidPromptError, match="cannot be empty"):
        orchestrator.run(
            user_id=1,
            prompt="   ",
            session=seeded_session,
        )


# ==============================================================================
# Category 4: REST API Endpoint Tests (POST /api/v1/agent/run)
# ==============================================================================


def test_api_agent_run_endpoint_success(
    sync_client: TestClient, seeded_session: Session
) -> None:
    """Verify POST /api/v1/agent/run returns 200 OK with valid AgentResponse schema."""
    payload = {
        "user_id": 1,
        "message": "Read my latest 3 university emails and summarize them in Arabic.",
        "provider": "fake",
    }

    response = sync_client.post("/api/v1/agent/run", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert "task_id" in data
    assert data["status"] == "success"
    assert data["provider_mode"] == "fake"
    assert data["tool_calls_count"] == 1
    assert len(data["execution_trace"]) == 1
    assert data["execution_trace"][0]["tool_name"] == "read_inbox"
    assert data["execution_trace"][0]["outcome"] == "SUCCESS"
    assert len(data["final_answer"]) > 0


def test_api_agent_run_endpoint_unknown_user(sync_client: TestClient) -> None:
    """Verify POST /api/v1/agent/run returns 404 for nonexistent user."""
    payload = {
        "user_id": 9999,
        "message": "Check my inbox",
        "provider": "fake",
    }

    response = sync_client.post("/api/v1/agent/run", json=payload)
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


@pytest.mark.parametrize(
    "payload",
    [
        {"user_id": 0, "message": "Hi", "provider": "fake"},
        {"user_id": -1, "message": "Hi", "provider": "fake"},
        {"user_id": 1, "message": "   ", "provider": "fake"},
        {"user_id": 1, "message": "Hi", "provider": "unsupported_provider"},
    ],
)
def test_api_agent_run_endpoint_validation_errors(
    sync_client: TestClient, payload: dict[str, Any]
) -> None:
    """Verify POST /api/v1/agent/run returns 422 for malformed parameters."""
    response = sync_client.post("/api/v1/agent/run", json=payload)
    assert response.status_code == 422


def test_api_agent_run_endpoint_provider_failure_returns_503(
    sync_client: TestClient, seeded_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify POST /api/v1/agent/run returns 503 when LLM provider fails."""
    # Mock default orchestrator provider to fail with timeout
    timeout_provider = FakeLLMProvider(force_timeout=True)
    monkeypatch.setattr(
        "app.agent.orchestrator.get_provider", lambda *args, **kwargs: timeout_provider
    )

    payload = {
        "user_id": 1,
        "message": "Check inbox",
        "provider": "fake",
    }
    response = sync_client.post("/api/v1/agent/run", json=payload)
    assert response.status_code == 503
    assert "timed out" in response.json()["detail"]


def test_api_existing_week1_endpoints_remain_intact(
    sync_client: TestClient, seeded_session: Session
) -> None:
    """Verify Week 1 REST endpoints continue operating normally."""
    # Health endpoint
    res_health = sync_client.get("/api/v1/health")
    assert res_health.status_code == 200

    # Users endpoint
    res_users = sync_client.get("/api/v1/users")
    assert res_users.status_code == 200
    assert len(res_users.json()) >= 3

    # Emails endpoint
    res_emails = sync_client.get("/api/v1/users/1/emails")
    assert res_emails.status_code == 200
    assert res_emails.json()["total"] == 10


# ==============================================================================
# Category 5: Advanced QA Boundary & Hardening Tests
# ==============================================================================


def test_orchestrator_max_iterations_exceeded(seeded_session: Session) -> None:
    """Verify orchestrator terminates cleanly when max_iterations limit is reached."""
    # Provider that requests 1 tool call on every iteration indefinitely
    loop_provider = FakeLLMProvider(
        canned_responses=[
            LLMResponse(
                tool_calls=[
                    ToolCall(id=f"c_{i}", name="read_inbox", arguments='{"limit": 1}')
                ],
                finish_reason="tool_calls",
            )
            for i in range(10)
        ]
        + [LLMResponse(content="Iteration summary", finish_reason="stop")]
    )

    # Set max_iterations to 2, while max_tool_calls is 10
    orchestrator = AgentOrchestrator(
        provider=loop_provider, max_tool_calls=10, max_iterations=2
    )
    response = orchestrator.run(
        user_id=1,
        prompt="Test iterations limit",
        session=seeded_session,
    )

    assert response.status == "max_iterations_exceeded"
    assert response.tool_calls_count == 2
    assert any("Maximum iteration limit (2) reached" in err for err in response.errors)


def test_orchestrator_multi_tool_call_batch_exceeding_limit(
    seeded_session: Session,
) -> None:
    """Verify orchestrator properly handles a batch of tool calls exceeding max_tool_calls."""
    # Model returns 3 tool calls at once, but max_tool_calls is 2
    batch_provider = FakeLLMProvider(
        canned_responses=[
            LLMResponse(
                tool_calls=[
                    ToolCall(id="c_1", name="read_inbox", arguments='{"limit": 1}'),
                    ToolCall(id="c_2", name="read_inbox", arguments='{"limit": 2}'),
                    ToolCall(id="c_3", name="read_inbox", arguments='{"limit": 3}'),
                ],
                finish_reason="tool_calls",
            ),
            LLMResponse(content="Final summary after batch", finish_reason="stop"),
        ]
    )

    orchestrator = AgentOrchestrator(provider=batch_provider, max_tool_calls=2)
    response = orchestrator.run(
        user_id=1,
        prompt="Batch tool calls test",
        session=seeded_session,
    )

    assert response.status == "max_tool_calls_exceeded"
    # Exactly 2 calls executed
    assert response.tool_calls_count == 2
    assert len(response.execution_trace) == 2
    assert any("Call 'read_inbox' skipped" in err for err in response.errors)


def test_orchestrator_multiple_tool_calls_within_limit(
    seeded_session: Session,
) -> None:
    """Verify orchestrator successfully executes multiple tool calls within budget."""
    batch_provider = FakeLLMProvider(
        canned_responses=[
            LLMResponse(
                tool_calls=[
                    ToolCall(id="c_inbox", name="read_inbox", arguments='{"limit": 2}'),
                    ToolCall(
                        id="c_search",
                        name="search_emails",
                        arguments='{"query": "advising"}',
                    ),
                ],
                finish_reason="tool_calls",
            ),
            LLMResponse(
                content="I have inspected both your inbox and search results.",
                finish_reason="stop",
            ),
        ]
    )

    orchestrator = AgentOrchestrator(provider=batch_provider, max_tool_calls=5)
    response = orchestrator.run(
        user_id=1,
        prompt="Read inbox and search advising",
        session=seeded_session,
    )

    assert response.status == "success"
    assert response.tool_calls_count == 2
    assert len(response.execution_trace) == 2
    assert response.execution_trace[0].tool_name == "read_inbox"
    assert response.execution_trace[1].tool_name == "search_emails"
    assert response.execution_trace[0].outcome == "SUCCESS"
    assert response.execution_trace[1].outcome == "SUCCESS"


def test_orchestrator_tool_execution_unexpected_exception(
    seeded_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify ToolRegistry captures unexpected tool exception and returns structured error."""

    # Monkeypatch read_inbox in tool registry to raise unexpected RuntimeError
    def _exploding_read_inbox(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("Simulated internal database engine disconnect")

    monkeypatch.setattr("app.agent.tool_registry.read_inbox", _exploding_read_inbox)
    from app.agent.tool_registry import ToolRegistry

    registry = ToolRegistry()
    executor = ToolExecutor(registry=registry)

    # Provider that attempts read_inbox then handles the error
    failing_tool_provider = FakeLLMProvider(
        canned_responses=[
            LLMResponse(
                tool_calls=[
                    ToolCall(id="c_fail", name="read_inbox", arguments='{"limit": 2}')
                ],
                finish_reason="tool_calls",
            ),
            LLMResponse(
                content="I encountered a tool execution error and informed the user.",
                finish_reason="stop",
            ),
        ]
    )

    orchestrator = AgentOrchestrator(provider=failing_tool_provider, executor=executor)
    response = orchestrator.run(
        user_id=1,
        prompt="Check inbox",
        session=seeded_session,
    )

    assert response.status == "success"
    assert response.tool_calls_count == 1
    assert response.execution_trace[0].outcome == "ERROR"
    assert response.execution_trace[0].error_code == "TOOL_EXECUTION_ERROR"
    assert "Simulated internal database engine disconnect" in str(
        response.execution_trace[0].error_message
    )


def test_orchestrator_unexpected_provider_exception(
    seeded_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify orchestrator captures unexpected generic provider exceptions without 500 crashes."""

    class BrokenProvider(FakeLLMProvider):
        def generate(self, *args: Any, **kwargs: Any) -> LLMResponse:
            raise RuntimeError("Fatal unexpected socket collapse")

    broken_provider = BrokenProvider()
    orchestrator = AgentOrchestrator(provider=broken_provider)
    response = orchestrator.run(
        user_id=1,
        prompt="Hello",
        session=seeded_session,
    )

    assert response.status == "error"
    assert any("Fatal unexpected socket collapse" in err for err in response.errors)


def test_orchestrator_repeated_tool_calls_in_same_session(
    seeded_session: Session,
) -> None:
    """Verify repeated calls to the same tool with identical arguments are cleanly bounded and recorded."""
    repeated_provider = FakeLLMProvider(
        canned_responses=[
            LLMResponse(
                tool_calls=[
                    ToolCall(
                        id=f"call_rep_{i}", name="read_inbox", arguments='{"limit": 1}'
                    )
                ],
                finish_reason="tool_calls",
            )
            for i in range(3)
        ]
        + [LLMResponse(content="Repeated calls completed.", finish_reason="stop")]
    )

    orchestrator = AgentOrchestrator(provider=repeated_provider, max_tool_calls=5)
    response = orchestrator.run(
        user_id=1,
        prompt="Read 1 email repeatedly",
        session=seeded_session,
    )

    assert response.status == "success"
    assert response.tool_calls_count == 3
    assert len(response.execution_trace) == 3
    call_ids = [step.call_id for step in response.execution_trace]
    assert len(set(call_ids)) == 3


def test_security_boundary_no_write_or_delete_tools_registered() -> None:
    """Verify strict allowlist: absolutely no write, delete, shell, or arbitrary code execution tools exist."""
    from app.agent.tool_registry import default_tool_registry

    allowed = default_tool_registry.allowed_tools

    # Permitted read-only tools
    assert allowed == {"read_inbox", "get_email_details", "search_emails"}

    # Forbidden dangerous tools
    forbidden = [
        "send_email",
        "delete_email",
        "update_email",
        "create_user",
        "drop_database",
        "eval",
        "exec",
        "os.system",
        "subprocess.run",
        "bash",
        "sh",
    ]
    for bad_tool in forbidden:
        assert default_tool_registry.validate_tool_name(bad_tool) is False


def test_security_boundary_cross_user_search_isolation(
    seeded_session: Session,
) -> None:
    """Verify search queries strictly isolate messages and never leak cross-user emails."""
    orchestrator = AgentOrchestrator()

    # User 3 (Maya Chen) has emails about "Robotics" and "Reinforcement Learning"
    # User 1 (Dr. Layla) must not find Maya's emails
    response = orchestrator.run(
        user_id=1,
        prompt="Search for robotics project meeting",
        session=seeded_session,
    )

    assert response.status == "success"
    # Result summary preview must show 0 matching items for user 1
    trace_step = response.execution_trace[0]
    assert trace_step.tool_name == "search_emails"
    assert trace_step.result_summary["count"] == 0


def test_api_agent_run_repeated_independent_requests(
    sync_client: TestClient, seeded_session: Session
) -> None:
    """Verify POST /api/v1/agent/run handles multiple consecutive requests without state pollution."""
    queries = [
        "Read my latest 2 emails",
        "Search for assignment",
        "Check my inbox",
    ]

    task_ids = set()
    for q in queries:
        resp = sync_client.post(
            "/api/v1/agent/run",
            json={"user_id": 1, "message": q, "provider": "fake"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert data["task_id"] not in task_ids
        task_ids.add(data["task_id"])

    assert len(task_ids) == 3


def test_orchestrator_session_none_uses_internal_session(
    seeded_session: Session,
) -> None:
    """Verify orchestrator functions correctly when session is None, using scoped managed SessionLocal."""
    # When session is None, it uses the database configured in Settings
    orchestrator = AgentOrchestrator()
    response = orchestrator.run(
        user_id=1,
        prompt="Read inbox",
        session=None,
    )
    assert response.status == "success"
    assert response.tool_calls_count == 1
    assert response.execution_trace[0].outcome == "SUCCESS"


def test_orchestrator_final_summary_provider_failure(seeded_session: Session) -> None:
    """Verify orchestrator gracefully recovers if provider fails during the final summary call."""

    class FailingSummaryProvider(FakeLLMProvider):
        def generate(
            self, messages: list[Any], tools: list[Any] | None = None
        ) -> LLMResponse:
            if tools is None:
                # This is the final summary generation call
                raise RuntimeError("Summary model network failure")
            return LLMResponse(
                tool_calls=[
                    ToolCall(id="c_1", name="read_inbox", arguments='{"limit": 1}')
                ],
                finish_reason="tool_calls",
            )

    provider = FailingSummaryProvider()
    orchestrator = AgentOrchestrator(provider=provider, max_tool_calls=1)
    response = orchestrator.run(
        user_id=1,
        prompt="Check inbox",
        session=seeded_session,
    )

    assert response.status == "max_tool_calls_exceeded"
    assert "Execution limit reached" in response.final_answer
