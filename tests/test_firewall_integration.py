"""Comprehensive Integration Test Suite for AEGIS-CORE Policy Firewall.

==============================================================================
SECURITY REQUIREMENTS VERIFIED:
------------------------------------------------------------------------------
1. Explicitly authorized read_inbox call executes.
2. Unauthorized read_inbox call is denied (TOOL_NOT_ALLOWED).
3. Authorized get_email_details executes.
4. Unauthorized get_email_details is denied (CONSTRAINT_VIOLATION).
5. Authorized search_emails executes.
6. Unauthorized search_emails is denied (TOOL_NOT_ALLOWED).
7. Missing policy denies tool execution (POLICY_MISSING).
8. Policy expiration blocks execution at runtime (POLICY_EXPIRED).
9. Model cannot forge a different task_id through tool arguments.
10. Model cannot forge a different user_id through tool arguments.
11. Agent loop continues gracefully after tool denial and reports failure reason to model.
12. Denied calls count against max tool call limits.
13. Denied operations NEVER invoke the underlying tool adapter or database (zero invocations).
14. Policy evaluation errors fail closed (DENY / EVALUATION_ERROR).
15. Audit trace captures policy decisions and reason codes.
16. Local demo harness executes successfully with explicit demo policy.
==============================================================================
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.agent.executor import ToolExecutor
from app.agent.orchestrator import AgentOrchestrator
from app.agent.providers import FakeLLMProvider, LLMResponse, ToolCall
from app.security import (
    GetEmailDetailsConstraint,
    PolicyAction,
    PolicyReasonCode,
    ReadInboxConstraint,
    SearchEmailsConstraint,
    TaskPolicy,
    create_task_policy,
)
from scripts.demo_agent import run_demo

# ==============================================================================
# 1 & 2: read_inbox Authorization and Denial
# ==============================================================================


def test_integration_authorized_read_inbox_executes(seeded_session: Session) -> None:
    """Requirement 1: Explicitly authorized read_inbox call executes successfully."""
    executor = ToolExecutor()
    policy = TaskPolicy(
        task_id="task_inbox_auth",
        bound_user_id=1,
        allowed_tools=frozenset({"read_inbox"}),
        constraints={"read_inbox": ReadInboxConstraint(max_limit=10)},
    )

    outcome = executor.execute(
        call_id="call_inbox_1",
        tool_name="read_inbox",
        raw_arguments={"limit": 3},
        user_id=1,
        session=seeded_session,
        policy=policy,
    )

    assert outcome.success is True
    assert outcome.policy_decision is not None
    assert outcome.policy_decision.decision == PolicyAction.ALLOW
    assert outcome.policy_decision.reason_code == PolicyReasonCode.ALLOW
    assert outcome.tool_result.data.count == 3


def test_integration_unauthorized_read_inbox_denied(seeded_session: Session) -> None:
    """Requirement 2: read_inbox is denied when not listed in allowed_tools."""
    executor = ToolExecutor()
    policy = TaskPolicy(
        task_id="task_inbox_unauth",
        bound_user_id=1,
        allowed_tools=frozenset({"get_email_details"}),
    )

    outcome = executor.execute(
        call_id="call_inbox_denied",
        tool_name="read_inbox",
        raw_arguments={"limit": 5},
        user_id=1,
        session=seeded_session,
        policy=policy,
    )

    assert outcome.success is False
    assert outcome.policy_decision is not None
    assert outcome.policy_decision.decision == PolicyAction.DENY
    assert outcome.policy_decision.reason_code == PolicyReasonCode.TOOL_NOT_ALLOWED
    assert outcome.tool_result.error.code == "TOOL_NOT_ALLOWED"


# ==============================================================================
# 3 & 4: get_email_details Authorization and Constraint Violation
# ==============================================================================


def test_integration_authorized_get_email_details_executes(
    seeded_session: Session,
) -> None:
    """Requirement 3: Explicitly authorized get_email_details executes."""
    executor = ToolExecutor()
    policy = TaskPolicy(
        task_id="task_details_auth",
        bound_user_id=1,
        allowed_tools=frozenset({"get_email_details"}),
        constraints={
            "get_email_details": GetEmailDetailsConstraint(
                allowed_email_ids=frozenset({1, 2})
            )
        },
    )

    outcome = executor.execute(
        call_id="call_det_1",
        tool_name="get_email_details",
        raw_arguments={"email_id": 1},
        user_id=1,
        session=seeded_session,
        policy=policy,
    )

    assert outcome.success is True
    assert outcome.policy_decision is not None
    assert outcome.policy_decision.decision == PolicyAction.ALLOW
    assert outcome.tool_result.data.id == 1


def test_integration_unauthorized_get_email_details_denied(
    seeded_session: Session,
) -> None:
    """Requirement 4: get_email_details for scoped-out ID is denied."""
    executor = ToolExecutor()
    policy = TaskPolicy(
        task_id="task_details_denied",
        bound_user_id=1,
        allowed_tools=frozenset({"get_email_details"}),
        constraints={
            "get_email_details": GetEmailDetailsConstraint(
                allowed_email_ids=frozenset({1, 2})
            )
        },
    )

    outcome = executor.execute(
        call_id="call_det_denied",
        tool_name="get_email_details",
        raw_arguments={"email_id": 5},
        user_id=1,
        session=seeded_session,
        policy=policy,
    )

    assert outcome.success is False
    assert outcome.policy_decision is not None
    assert outcome.policy_decision.decision == PolicyAction.DENY
    assert outcome.policy_decision.reason_code == PolicyReasonCode.CONSTRAINT_VIOLATION
    assert "email_id 5 is not in" in outcome.policy_decision.explanation


# ==============================================================================
# 5 & 6: search_emails Authorization and Denial
# ==============================================================================


def test_integration_authorized_search_emails_executes(
    seeded_session: Session,
) -> None:
    """Requirement 5: Explicitly authorized search_emails executes."""
    executor = ToolExecutor()
    policy = TaskPolicy(
        task_id="task_search_auth",
        bound_user_id=1,
        allowed_tools=frozenset({"search_emails"}),
        constraints={
            "search_emails": SearchEmailsConstraint(max_limit=10, max_query_length=50)
        },
    )

    outcome = executor.execute(
        call_id="call_srch_1",
        tool_name="search_emails",
        raw_arguments={"query": "AI", "limit": 3},
        user_id=1,
        session=seeded_session,
        policy=policy,
    )

    assert outcome.success is True
    assert outcome.policy_decision is not None
    assert outcome.policy_decision.decision == PolicyAction.ALLOW


def test_integration_unauthorized_search_emails_denied(
    seeded_session: Session,
) -> None:
    """Requirement 6: search_emails denied when tool is omitted from policy."""
    executor = ToolExecutor()
    policy = TaskPolicy(
        task_id="task_srch_denied",
        bound_user_id=1,
        allowed_tools=frozenset({"read_inbox"}),
    )

    outcome = executor.execute(
        call_id="call_srch_denied",
        tool_name="search_emails",
        raw_arguments={"query": "exam"},
        user_id=1,
        session=seeded_session,
        policy=policy,
    )

    assert outcome.success is False
    assert outcome.policy_decision is not None
    assert outcome.policy_decision.decision == PolicyAction.DENY
    assert outcome.policy_decision.reason_code == PolicyReasonCode.TOOL_NOT_ALLOWED


# ==============================================================================
# 7: Missing Policy Denies Tool Execution (Default Deny)
# ==============================================================================


def test_integration_missing_policy_denies_execution(
    seeded_session: Session,
) -> None:
    """Requirement 7: Tool execution without a policy fails closed with POLICY_MISSING."""
    executor = ToolExecutor()

    # Pass policy=None explicitly
    outcome = executor.execute(
        call_id="call_no_policy",
        tool_name="read_inbox",
        raw_arguments={"limit": 5},
        user_id=1,
        session=seeded_session,
        policy=None,
    )

    assert outcome.success is False
    assert outcome.policy_decision is not None
    assert outcome.policy_decision.decision == PolicyAction.DENY
    assert outcome.policy_decision.reason_code == PolicyReasonCode.POLICY_MISSING
    assert outcome.tool_result.error.code == "POLICY_MISSING"

    # Orchestrator with explicit policy=None fails closed
    orch = AgentOrchestrator(
        provider=FakeLLMProvider(
            canned_responses=[
                LLMResponse(
                    tool_calls=[
                        ToolCall(id="c1", name="read_inbox", arguments='{"limit": 2}')
                    ],
                    finish_reason="tool_calls",
                ),
                LLMResponse(content="Stopped due to denial.", finish_reason="stop"),
            ]
        ),
        default_policy_profile=None,
    )

    response = orch.run(
        user_id=1,
        prompt="Check inbox",
        session=seeded_session,
        policy=None,
    )

    assert response.status == "success"
    assert response.tool_calls_count == 1
    assert response.execution_trace[0].outcome == "ERROR"
    assert response.execution_trace[0].error_code == "POLICY_MISSING"
    assert response.execution_trace[0].policy_action == "DENY"
    assert response.execution_trace[0].policy_reason_code == "POLICY_MISSING"


# ==============================================================================
# 8: Policy Expiration Blocks Execution
# ==============================================================================


def test_integration_policy_expiration_blocks_execution(
    seeded_session: Session,
) -> None:
    """Requirement 8: Expired policy fails closed with POLICY_EXPIRED."""
    executor = ToolExecutor()
    past_time = datetime.now(UTC) - timedelta(hours=1)
    issued_time = past_time - timedelta(minutes=10)

    policy = TaskPolicy(
        task_id="task_expired",
        bound_user_id=1,
        allowed_tools=frozenset({"read_inbox"}),
        issued_at=issued_time,
        expires_at=past_time,
    )

    outcome = executor.execute(
        call_id="call_exp",
        tool_name="read_inbox",
        raw_arguments={"limit": 1},
        user_id=1,
        session=seeded_session,
        policy=policy,
    )

    assert outcome.success is False
    assert outcome.policy_decision is not None
    assert outcome.policy_decision.decision == PolicyAction.DENY
    assert outcome.policy_decision.reason_code == PolicyReasonCode.POLICY_EXPIRED


# ==============================================================================
# 9 & 10: Model Cannot Forge task_id or user_id
# ==============================================================================


def test_integration_model_cannot_forge_task_id(seeded_session: Session) -> None:
    """Requirement 9: Model injecting forged task_id in arguments cannot alter bound task."""
    executor = ToolExecutor()
    policy = TaskPolicy(
        task_id="legitimate_task_123",
        bound_user_id=1,
        allowed_tools=frozenset({"read_inbox"}),
    )

    # Model maliciously injects forged task_id in arguments
    outcome = executor.execute(
        call_id="call_forge_task",
        tool_name="read_inbox",
        raw_arguments={"task_id": "forged_malicious_task", "limit": 2},
        user_id=1,
        session=seeded_session,
        task_id="legitimate_task_123",
        policy=policy,
    )

    assert outcome.success is True
    # Evaluated under legitimate task_id
    assert outcome.policy_decision.task_id == "legitimate_task_123"


def test_integration_model_cannot_forge_user_id(seeded_session: Session) -> None:
    """Requirement 10: Model injecting forged user_id in arguments cannot alter bound user."""
    executor = ToolExecutor()
    policy = TaskPolicy(
        task_id="legitimate_task_456",
        bound_user_id=1,
        allowed_tools=frozenset({"read_inbox"}),
    )

    # Model maliciously injects user_id 2 in arguments
    outcome = executor.execute(
        call_id="call_forge_user",
        tool_name="read_inbox",
        raw_arguments={"user_id": 2, "limit": 3},
        user_id=1,  # Server-controlled identity
        session=seeded_session,
        policy=policy,
    )

    assert outcome.success is True
    # Server-verified user identity strictly preserved
    assert outcome.tool_result.data.owner_id == 1


# ==============================================================================
# 11: Agent Loop Continues Gracefully After Denial
# ==============================================================================


def test_integration_agent_loop_continues_gracefully_after_denial(
    seeded_session: Session,
) -> None:
    """Requirement 11: Orchestration loop does not crash on denial and feeds back reason."""
    provider = FakeLLMProvider(
        canned_responses=[
            LLMResponse(
                tool_calls=[
                    ToolCall(
                        id="call_denied_step",
                        name="search_emails",
                        arguments='{"query": "secret"}',
                    )
                ],
                finish_reason="tool_calls",
            ),
            LLMResponse(
                content="I understand that search_emails is not permitted under the active policy.",
                finish_reason="stop",
            ),
        ]
    )

    # Restrict policy to read_inbox only
    triage_policy = create_task_policy(
        task_id="task_graceful_denial",
        user_id=1,
        profile_name="minimal_read",
    )

    orch = AgentOrchestrator(provider=provider)
    response = orch.run(
        user_id=1,
        prompt="Search for secret emails",
        session=seeded_session,
        policy=triage_policy,
    )

    assert response.status == "success"
    assert response.tool_calls_count == 1
    assert response.execution_trace[0].outcome == "ERROR"
    assert response.execution_trace[0].policy_action == "DENY"
    assert response.execution_trace[0].policy_reason_code == "TOOL_NOT_ALLOWED"
    assert "not permitted" in response.final_answer


# ==============================================================================
# 12: Denied Calls Count Against Max Tool Limits
# ==============================================================================


def test_integration_denied_calls_count_against_limits(
    seeded_session: Session,
) -> None:
    """Requirement 12: Repeated denied tool attempts count toward max_tool_calls limit."""
    looping_provider = FakeLLMProvider(
        canned_responses=[
            LLMResponse(
                tool_calls=[
                    ToolCall(
                        id=f"call_{i}",
                        name="read_inbox",
                        arguments='{"limit": 4}',  # Violates policy max_limit=2 (within schema limit 20)
                    )
                ],
                finish_reason="tool_calls",
            )
            for i in range(5)
        ]
        + [LLMResponse(content="Capped summary.", finish_reason="stop")]
    )

    strict_policy = TaskPolicy(
        task_id="task_capped",
        bound_user_id=1,
        allowed_tools=frozenset({"read_inbox"}),
        constraints={"read_inbox": ReadInboxConstraint(max_limit=2)},
    )

    orch = AgentOrchestrator(provider=looping_provider, max_tool_calls=2)
    response = orch.run(
        user_id=1,
        prompt="Loop violating calls",
        session=seeded_session,
        policy=strict_policy,
    )

    assert response.status == "max_tool_calls_exceeded"
    assert response.tool_calls_count == 2
    assert all(step.outcome == "ERROR" for step in response.execution_trace)
    assert all(
        step.policy_reason_code == "CONSTRAINT_VIOLATION"
        for step in response.execution_trace
    )


# ==============================================================================
# 13: Denied Operations NEVER Invoke Underlying Tool Adapter
# ==============================================================================


def test_integration_denied_operations_never_invoke_service(
    seeded_session: Session,
) -> None:
    """Requirement 13: Denied operations NEVER invoke EmailService or ToolRegistry dispatch."""
    executor = ToolExecutor()
    policy = TaskPolicy(
        task_id="task_spy_test",
        bound_user_id=1,
        allowed_tools=frozenset({"read_inbox"}),
        constraints={"read_inbox": ReadInboxConstraint(max_limit=5)},
    )

    # Spy on registry.execute_tool
    with patch.object(
        executor.registry, "execute_tool", wraps=executor.registry.execute_tool
    ) as spy_registry:
        # Violation: limit=20 exceeds policy max_limit=5
        outcome = executor.execute(
            call_id="call_spy_viol",
            tool_name="read_inbox",
            raw_arguments={"limit": 20},
            user_id=1,
            session=seeded_session,
            policy=policy,
        )

        assert outcome.success is False
        assert outcome.policy_decision.decision == PolicyAction.DENY
        # Absolute guarantee: Underlying execute_tool was NEVER called
        assert spy_registry.call_count == 0


# ==============================================================================
# 14: Policy Evaluation Errors Fail Closed (DENY)
# ==============================================================================


def test_integration_evaluation_exception_fails_closed(
    seeded_session: Session,
) -> None:
    """Requirement 14: Unexpected exception during policy evaluation fails closed (DENY)."""
    mock_engine = MagicMock()
    mock_engine.evaluate.side_effect = RuntimeError("Fatal evaluator memory error")

    executor = ToolExecutor(policy_engine=mock_engine)
    policy = create_task_policy("task_err", user_id=1, profile_name="read_only_all")

    outcome = executor.execute(
        call_id="call_err",
        tool_name="read_inbox",
        raw_arguments={"limit": 2},
        user_id=1,
        session=seeded_session,
        policy=policy,
    )

    assert outcome.success is False
    assert outcome.policy_decision is not None
    assert outcome.policy_decision.decision == PolicyAction.DENY
    assert outcome.policy_decision.reason_code == PolicyReasonCode.EVALUATION_ERROR
    assert "Fatal evaluator memory error" in outcome.policy_decision.explanation


# ==============================================================================
# 15: Audit Trace Captures Policy Decisions and Reason Codes
# ==============================================================================


def test_integration_audit_trace_captures_policy_metadata(
    seeded_session: Session,
) -> None:
    """Requirement 15: Execution trace correctly captures policy_action and policy_reason_code."""
    provider = FakeLLMProvider(
        canned_responses=[
            LLMResponse(
                tool_calls=[
                    ToolCall(
                        id="c_allow",
                        name="read_inbox",
                        arguments='{"limit": 2}',
                    ),
                    ToolCall(
                        id="c_deny",
                        name="search_emails",
                        arguments='{"query": "Kaust"}',
                    ),
                ],
                finish_reason="tool_calls",
            ),
            LLMResponse(content="Final summary.", finish_reason="stop"),
        ]
    )

    # Allow read_inbox, deny search_emails
    policy = TaskPolicy(
        task_id="task_trace_meta",
        bound_user_id=1,
        allowed_tools=frozenset({"read_inbox"}),
    )

    orch = AgentOrchestrator(provider=provider, max_tool_calls=5)
    response = orch.run(
        user_id=1,
        prompt="Read and search",
        session=seeded_session,
        policy=policy,
    )

    assert response.status == "success"
    assert len(response.execution_trace) == 2

    step1 = response.execution_trace[0]
    assert step1.tool_name == "read_inbox"
    assert step1.outcome == "SUCCESS"
    assert step1.policy_action == "ALLOW"
    assert step1.policy_reason_code == "ALLOW"

    step2 = response.execution_trace[1]
    assert step2.tool_name == "search_emails"
    assert step2.outcome == "ERROR"
    assert step2.policy_action == "DENY"
    assert step2.policy_reason_code == "TOOL_NOT_ALLOWED"


# ==============================================================================
# 16: API Endpoint Profile Selection
# ==============================================================================


def test_integration_api_endpoint_profiles(
    sync_client: TestClient, seeded_session: Session
) -> None:
    """Verify POST /api/v1/agent/run respects server-owned profile selection."""
    # 1. Profile 'read_only_all' succeeds for legitimate query
    res = sync_client.post(
        "/api/v1/agent/run",
        json={
            "user_id": 1,
            "message": "Read my latest 2 emails.",
            "provider": "fake",
            "policy_profile": "read_only_all",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["execution_trace"][0]["policy_action"] == "ALLOW"

    # 2. Profile 'none' fails closed (denies tool execution)
    res_none = sync_client.post(
        "/api/v1/agent/run",
        json={
            "user_id": 1,
            "message": "Read my latest 2 emails.",
            "provider": "fake",
            "policy_profile": "none",
        },
    )
    assert res_none.status_code == 200
    data_none = res_none.json()
    assert data_none["execution_trace"][0]["policy_action"] == "DENY"
    assert data_none["execution_trace"][0]["policy_reason_code"] == "POLICY_MISSING"

    # 3. Invalid profile is rejected with 422
    res_bad = sync_client.post(
        "/api/v1/agent/run",
        json={
            "user_id": 1,
            "message": "Read inbox",
            "policy_profile": "unrestricted_admin",
        },
    )
    assert res_bad.status_code == 422


# ==============================================================================
# 17: Local Demo Harness Verification
# ==============================================================================


def test_integration_demo_script_runs_successfully() -> None:
    """Requirement 16: Week 2 offline demo harness runs to completion with 0 exit code."""
    result_code = run_demo()
    assert result_code == 0
