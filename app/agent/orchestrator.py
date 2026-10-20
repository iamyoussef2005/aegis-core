"""Mini AI Agent Orchestrator for AEGIS-CORE.

Coordinates user intent, identity validation, provider interaction,
task-scoped policy authorization, bounded tool execution, and structured tracing.
"""

import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.agent.exceptions import (
    InvalidPromptError,
    InvalidProviderError,
    UserNotFoundError,
)
from app.agent.executor import ToolExecutor, default_tool_executor
from app.agent.prompts import build_system_prompt
from app.agent.providers import (
    BaseLLMProvider,
    ChatMessage,
    ProviderConfigError,
    ProviderError,
    ProviderTimeoutError,
    get_provider,
)
from app.agent.tracing import AgentResponse, ExecutionTracer
from app.core.config import get_settings
from app.db.session import SessionLocal
from app.security.context import TaskContext
from app.security.profiles import create_task_policy
from app.security.schemas import TaskPolicy
from app.services.user import UserService

ALLOWED_PROVIDER_MODES: frozenset[str] = frozenset({"fake", "openai"})
_POLICY_UNSET = object()


class AgentOrchestrator:
    """Orchestrates end-to-end task execution for the Mini AI Agent."""

    def __init__(
        self,
        provider: BaseLLMProvider | None = None,
        executor: ToolExecutor | None = None,
        max_tool_calls: int | None = None,
        max_iterations: int | None = None,
        default_policy_profile: str | None = "read_only_all",
    ) -> None:
        settings = get_settings()
        self._provider = provider
        self.executor = executor or default_tool_executor
        self.max_tool_calls = (
            max_tool_calls
            if max_tool_calls is not None
            else settings.AGENT_MAX_TOOL_CALLS
        )
        self.max_iterations = (
            max_iterations if max_iterations is not None else self.max_tool_calls + 2
        )
        self.default_policy_profile = default_policy_profile

    def _get_provider(self, provider_mode: str | None = None) -> BaseLLMProvider:
        """Resolve and validate the LLM provider instance."""
        if provider_mode:
            clean_mode = provider_mode.lower().strip()
            if clean_mode not in ALLOWED_PROVIDER_MODES:
                raise InvalidProviderError(
                    f"Unsupported provider: '{provider_mode}'. Allowed modes: {sorted(ALLOWED_PROVIDER_MODES)}"
                )
            return get_provider(clean_mode)

        if self._provider is not None:
            return self._provider

        return get_provider()

    def run(
        self,
        user_id: int,
        prompt: str,
        provider_name: str | None = None,
        session: Session | None = None,
        policy: Any = _POLICY_UNSET,
        policy_profile: str | None = None,
    ) -> AgentResponse:
        """Execute a user query against the simulated academic environment.

        Args:
            user_id: Target simulated user ID (verified server-side).
            prompt: User task description or message.
            provider_name: Optional provider identifier ('fake', 'openai').
            session: Optional database session.
            policy: Explicit TaskPolicy or None. If omitted, uses policy_profile or default.
            policy_profile: Predefined profile name ('read_only_all', 'inbox_triage', etc.).

        Returns:
            AgentResponse containing final answer and audit trace.

        Raises:
            UserNotFoundError: If user_id is non-positive or user account does not exist.
            InvalidPromptError: If prompt is empty or pure whitespace.
            InvalidProviderError: If requested provider mode is unsupported.
        """
        # 1. Input Validation
        if user_id < 1:
            raise UserNotFoundError(
                f"Invalid user_id: {user_id}. User ID must be a positive integer."
            )

        clean_prompt = prompt.strip() if prompt else ""
        if not clean_prompt:
            raise InvalidPromptError("User prompt cannot be empty or whitespace only.")

        # Resolve provider
        provider = self._get_provider(provider_name)
        provider_mode = provider.provider_name

        # 2. Verify user account exists in database
        def _check_user(db: Session) -> str | None:
            user_service = UserService(db)
            user_record = user_service.get_user_by_id(user_id)
            if user_record is None:
                raise UserNotFoundError(f"User with ID {user_id} not found.")
            return user_record.display_name

        if session is not None:
            display_name = _check_user(session)
        else:
            with SessionLocal() as db_session:
                display_name = _check_user(db_session)

        # 3. Initialize unique Task, Context, and Execution Tracer
        task_id = f"task_{uuid.uuid4().hex[:12]}"

        # Resolve effective security policy before any tool execution
        effective_policy: TaskPolicy | None
        if policy is not _POLICY_UNSET:
            effective_policy = policy
            if isinstance(effective_policy, TaskPolicy):
                task_id = effective_policy.task_id
        elif policy_profile is not None:
            effective_policy = create_task_policy(
                task_id=task_id, user_id=user_id, profile_name=policy_profile
            )
        elif self.default_policy_profile is not None:
            effective_policy = create_task_policy(
                task_id=task_id,
                user_id=user_id,
                profile_name=self.default_policy_profile,
            )
        else:
            effective_policy = None

        context = TaskContext(
            task_id=task_id,
            user_id=user_id,
            policy=effective_policy,
        )

        tracer = ExecutionTracer(
            task_id=task_id,
            user_id=user_id,
            provider_mode=provider_mode,
        )

        # 4. Context Initialization
        system_content = build_system_prompt(
            user_id=user_id, user_display_name=display_name
        )
        messages: list[ChatMessage] = [
            ChatMessage(role="system", content=system_content),
            ChatMessage(role="user", content=clean_prompt),
        ]

        tools = self.executor.registry.get_openai_tool_definitions()
        tool_calls_count = 0
        iteration_count = 0
        limit_reason: str | None = None

        # 5. Bounded ReAct Execution Loop
        while tool_calls_count < self.max_tool_calls:
            if iteration_count >= self.max_iterations:
                limit_reason = "max_iterations_exceeded"
                tracer.record_error(
                    f"Maximum iteration limit ({self.max_iterations}) reached."
                )
                break

            iteration_count += 1

            try:
                response = provider.generate(messages=messages, tools=tools)
            except ProviderTimeoutError as err:
                tracer.record_error(f"Provider request timed out: {err}")
                return tracer.build_response(final_answer="", status="error")
            except ProviderConfigError as err:
                tracer.record_error(f"Provider configuration error: {err}")
                return tracer.build_response(final_answer="", status="error")
            except ProviderError as err:
                tracer.record_error(f"Provider execution failure: {err}")
                return tracer.build_response(final_answer="", status="error")
            except Exception as err:
                tracer.record_error(f"Unexpected provider error: {err}")
                return tracer.build_response(final_answer="", status="error")

            # Check if model requested tool call(s)
            if response.has_tool_calls:
                messages.append(
                    ChatMessage(
                        role="assistant",
                        content=response.content,
                        tool_calls=response.tool_calls,
                    )
                )

                for tc in response.tool_calls:
                    if tool_calls_count >= self.max_tool_calls:
                        limit_reason = "max_tool_calls_exceeded"
                        # Ceiling reached within multi-tool call response
                        tracer.record_error(
                            f"Tool call limit ({self.max_tool_calls}) reached. Call '{tc.name}' skipped."
                        )
                        # Append protocol-compliant tool error message so upstream APIs do not reject history
                        messages.append(
                            ChatMessage(
                                role="tool",
                                tool_call_id=tc.id,
                                name=tc.name,
                                content=(
                                    f"[TOOL_RESULT: {tc.name}]\n"
                                    f"STATUS: ERROR\n"
                                    f"ERROR_CODE: TOOL_CALL_LIMIT_EXCEEDED\n"
                                    f"MESSAGE: Tool call limit ({self.max_tool_calls}) reached. Call skipped.\n"
                                    f"[END_TOOL_RESULT]"
                                ),
                            )
                        )
                        continue

                    tool_calls_count += 1

                    # Execute through single controlled executor entry point
                    outcome = self.executor.execute(
                        call_id=tc.id,
                        tool_name=tc.name,
                        raw_arguments=tc.arguments,
                        user_id=user_id,
                        session=session,
                        task_id=task_id,
                        policy=effective_policy,
                        context=context,
                    )

                    # Extract error info if tool failed
                    err_code = (
                        outcome.tool_result.error.code
                        if outcome.tool_result.error
                        else None
                    )
                    err_msg = (
                        outcome.tool_result.error.message
                        if outcome.tool_result.error
                        else None
                    )

                    policy_act = (
                        outcome.policy_decision.decision.value
                        if outcome.policy_decision
                        else None
                    )
                    policy_rc = (
                        outcome.policy_decision.reason_code.value
                        if outcome.policy_decision
                        else None
                    )

                    tracer.record_tool_step(
                        call_id=tc.id,
                        tool_name=tc.name,
                        arguments=tc.arguments,
                        success=outcome.success,
                        duration_ms=outcome.duration_ms,
                        result_dict=outcome.tool_result.to_dict(),
                        error_code=err_code,
                        error_message=err_msg,
                        policy_action=policy_act,
                        policy_reason_code=policy_rc,
                    )

                    # Append tool result formatted as untrusted data
                    messages.append(
                        ChatMessage(
                            role="tool",
                            tool_call_id=tc.id,
                            name=tc.name,
                            content=outcome.formatted_content,
                        )
                    )

            else:
                # Model provided final synthesis without requesting tools
                messages.append(ChatMessage(role="assistant", content=response.content))
                return tracer.build_response(
                    final_answer=response.content or "",
                    status="success",
                )

        # 6. Maximum Tool Call or Iteration Limit Reached: Request bounded final summary
        final_status = limit_reason or "max_tool_calls_exceeded"
        messages.append(
            ChatMessage(
                role="system",
                content=(
                    "Execution limit reached. Provide your final summary "
                    "to the user based strictly on the retrieved data. Do not call any tools."
                ),
            )
        )

        try:
            final_res = provider.generate(messages=messages, tools=None)
            final_answer = final_res.content or "Execution limit reached."
        except Exception:
            final_answer = "Execution limit reached while processing the request."

        return tracer.build_response(
            final_answer=final_answer,
            status=final_status,
        )
