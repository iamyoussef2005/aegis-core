"""Autonomous execution runner for the AEGIS-CORE Mini AI Agent.

Orchestrates the conversation loop between LLM providers and the secure tool registry.
"""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.agent.prompts import build_system_prompt
from app.agent.providers import get_provider
from app.agent.providers.base import (
    BaseLLMProvider,
    ChatMessage,
    ProviderError,
)
from app.agent.tool_registry import ToolRegistry, default_tool_registry
from app.core.config import get_settings


class AgentExecutionResult(BaseModel):
    """Structured result returned after executing a user task with the Mini AI Agent."""

    model_config = ConfigDict(extra="ignore")

    success: bool = Field(
        ..., description="Whether the agent task completed successfully"
    )
    final_answer: str = Field(
        ..., description="The final text response provided by the agent"
    )
    user_id: int = Field(
        ..., description="The simulated user ID bound to this execution"
    )
    tool_calls_count: int = Field(
        default=0, description="Total number of tool calls executed"
    )
    tool_executions: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Audit trace of all tool calls and their results",
    )
    messages: list[ChatMessage] = Field(
        default_factory=list,
        description="Full conversation history exchanged with the LLM",
    )
    error: str | None = Field(
        default=None, description="Error message if execution failed"
    )
    finish_reason: str | None = Field(
        default=None,
        description="Termination reason (e.g. 'stop', 'max_tool_calls_exceeded')",
    )


class AgentRunner:
    """Coordinates multi-turn tool calling between an LLM provider and AEGIS-CORE tools."""

    def __init__(
        self,
        provider: BaseLLMProvider | None = None,
        tool_registry: ToolRegistry | None = None,
        max_tool_calls: int | None = None,
    ) -> None:
        settings = get_settings()
        self.provider = provider or get_provider()
        self.tool_registry = tool_registry or default_tool_registry
        self.max_tool_calls = (
            max_tool_calls
            if max_tool_calls is not None
            else settings.AGENT_MAX_TOOL_CALLS
        )

    def run(
        self,
        user_id: int,
        prompt: str,
        session: Session | None = None,
        user_display_name: str | None = None,
    ) -> AgentExecutionResult:
        """Execute a user query against the simulated inbox using the configured LLM provider.

        Args:
            user_id: The verified user ID. Preserved server-side; cannot be altered by model.
            prompt: User request or instruction.
            session: Optional database session.
            user_display_name: Optional user display name for context.

        Returns:
            AgentExecutionResult containing final answer and audit trail.
        """
        # Validate inputs
        if user_id < 1:
            return AgentExecutionResult(
                success=False,
                final_answer="",
                user_id=user_id,
                error=f"Invalid user_id: {user_id}. Must be a positive integer.",
                finish_reason="validation_error",
            )

        clean_prompt = prompt.strip()
        if not clean_prompt:
            return AgentExecutionResult(
                success=False,
                final_answer="",
                user_id=user_id,
                error="Prompt cannot be empty.",
                finish_reason="validation_error",
            )

        # 1. Initialize conversation context
        system_content = build_system_prompt(
            user_id=user_id, user_display_name=user_display_name
        )
        messages: list[ChatMessage] = [
            ChatMessage(role="system", content=system_content),
            ChatMessage(role="user", content=clean_prompt),
        ]

        tools = self.tool_registry.get_openai_tool_definitions()
        tool_calls_count = 0
        tool_executions: list[dict[str, Any]] = []

        # 2. ReAct Agent Execution Loop
        while tool_calls_count < self.max_tool_calls:
            try:
                response = self.provider.generate(messages=messages, tools=tools)
            except ProviderError as err:
                return AgentExecutionResult(
                    success=False,
                    final_answer="",
                    user_id=user_id,
                    tool_calls_count=tool_calls_count,
                    tool_executions=tool_executions,
                    messages=messages,
                    error=str(err),
                    finish_reason="provider_error",
                )

            # If model returned tool calls, process them
            if response.has_tool_calls:
                # Append assistant tool call message to history
                messages.append(
                    ChatMessage(
                        role="assistant",
                        content=response.content,
                        tool_calls=response.tool_calls,
                    )
                )

                for tc in response.tool_calls:
                    if tool_calls_count >= self.max_tool_calls:
                        break

                    tool_calls_count += 1

                    # Execute tool through secure registry (server-controlled identity)
                    result = self.tool_registry.execute_tool(
                        tool_name=tc.name,
                        raw_arguments=tc.arguments,
                        user_id=user_id,
                        session=session,
                    )

                    tool_executions.append(
                        {
                            "call_id": tc.id,
                            "tool_name": tc.name,
                            "arguments": tc.arguments,
                            "success": result.success,
                            "result": result.to_dict(),
                        }
                    )

                    # Format tool result as untrusted data for LLM context
                    formatted_content = ToolRegistry.format_tool_result_for_llm(
                        tc.name, result
                    )
                    messages.append(
                        ChatMessage(
                            role="tool",
                            tool_call_id=tc.id,
                            name=tc.name,
                            content=formatted_content,
                        )
                    )

            else:
                # Model provided final text response without requesting tools
                messages.append(ChatMessage(role="assistant", content=response.content))
                return AgentExecutionResult(
                    success=True,
                    final_answer=response.content or "",
                    user_id=user_id,
                    tool_calls_count=tool_calls_count,
                    tool_executions=tool_executions,
                    messages=messages,
                    finish_reason="stop",
                )

        # 3. Handle max tool calls boundary reached
        # Request final synthesis without additional tool calls allowed
        messages.append(
            ChatMessage(
                role="system",
                content=(
                    "You have reached the maximum allowed tool call limit. "
                    "Provide your final answer to the user based strictly on the "
                    "data retrieved above. Do not attempt further tool calls."
                ),
            )
        )

        try:
            final_res = self.provider.generate(messages=messages, tools=None)
            final_answer = final_res.content or "Maximum tool calls limit reached."
        except ProviderError:
            final_answer = (
                "Maximum tool calls limit reached while processing the request."
            )

        return AgentExecutionResult(
            success=True,
            final_answer=final_answer,
            user_id=user_id,
            tool_calls_count=tool_calls_count,
            tool_executions=tool_executions,
            messages=messages,
            finish_reason="max_tool_calls_exceeded",
        )
