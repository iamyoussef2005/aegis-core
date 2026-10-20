"""Deterministic Fake LLM Provider for offline testing, local development, and demos.

Does not make any external network requests or require an API key.
"""

import json
import re
from typing import Any

from app.agent.providers.base import (
    BaseLLMProvider,
    ChatMessage,
    LLMResponse,
    ProviderAPIError,
    ProviderTimeoutError,
    ToolCall,
)


class FakeLLMProvider(BaseLLMProvider):
    """Deterministic, mock LLM provider designed for offline QA and automated testing."""

    def __init__(
        self,
        model_name: str = "fake-deterministic-model",
        canned_responses: list[LLMResponse] | None = None,
        force_timeout: bool = False,
        force_api_error: bool = False,
    ) -> None:
        self._model_name = model_name
        self._canned_responses: list[LLMResponse] = list(canned_responses or [])
        self._call_count = 0
        self.call_history: list[dict[str, Any]] = []
        self.force_timeout = force_timeout
        self.force_api_error = force_api_error

    @property
    def provider_name(self) -> str:
        return "fake"

    @property
    def model_name(self) -> str:
        return self._model_name

    def add_canned_response(self, response: LLMResponse) -> None:
        """Add a canned response to the queue."""
        self._canned_responses.append(response)

    def set_canned_responses(self, responses: list[LLMResponse]) -> None:
        """Replace the canned response queue with a new sequence."""
        self._canned_responses = list(responses)

    def generate(
        self,
        messages: list[ChatMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> LLMResponse:
        """Produce the next deterministic response."""
        self.call_history.append({"messages": messages, "tools": tools})
        self._call_count += 1

        if self.force_timeout:
            raise ProviderTimeoutError(
                f"FakeLLMProvider request timed out (model: {self._model_name})"
            )

        if self.force_api_error:
            raise ProviderAPIError(
                f"FakeLLMProvider simulated upstream API failure (model: {self._model_name})"
            )

        # 1. Use canned response if available
        if self._canned_responses:
            return self._canned_responses.pop(0)

        # 2. Dynamic rule-based completion for automated testing & offline demos
        return self._generate_rule_based_response(messages)

    def _generate_rule_based_response(self, messages: list[ChatMessage]) -> LLMResponse:
        """Generate intelligent deterministic responses based on conversation state."""
        if not messages:
            return LLMResponse(
                content="Hello! How can I assist you with your emails?",
                finish_reason="stop",
                model=self._model_name,
            )

        last_message = messages[-1]

        # Case A: Answering after a tool execution
        if last_message.role == "tool":
            content_str = last_message.content or ""
            # Detect requested Arabic from user prompts (untrusted email contents must not dictate output language)
            user_prompts = " ".join(
                m.content or "" for m in messages if m.role == "user"
            )
            has_arabic = bool(
                re.search(r"[\u0600-\u06FF]", user_prompts)
                or "arabic" in user_prompts.lower()
                or "بالعربية" in user_prompts
                or "عربي" in user_prompts
            )

            if "STATUS: SUCCESS" in content_str:
                is_empty = bool(
                    re.search(r'"count":\s*0\b', content_str)
                    or re.search(r'"emails":\s*\[\]', content_str)
                )
                if is_empty:
                    if has_arabic:
                        summary = (
                            "[مخرجات تجريبية محددة مسبقاً - ليست استدلالاً حقيقياً لنموذج لغوي] "
                            "صندوق البريد فارغ أو لم يتم العثور على نتائج في بريدك الأكاديمي (0 رسائل)."
                        )
                    else:
                        summary = (
                            "[DETERMINISTIC DEMO OUTPUT - NOT REAL LLM REASONING] "
                            "Your simulated inbox is currently empty or no matching messages were found (0 messages)."
                        )
                elif has_arabic:
                    summary = (
                        "[مخرجات تجريبية محددة مسبقاً - ليست استدلالاً حقيقياً لنموذج لغوي] "
                        "بناءً على الرسائل المسترجعة من بريدك الأكاديمي، قمت بمراجعة وتلخيص البريد المطلوب. "
                        "تؤكد الرسائل التفاصيل الأكاديمية المطلوبة دون تنفيذ أي تعليمات برمجية داخلية."
                    )
                else:
                    summary = (
                        "[DETERMINISTIC DEMO OUTPUT - NOT REAL LLM REASONING] "
                        "I have retrieved and summarized your simulated academic emails. "
                        "All messages have been inspected as untrusted data without executing embedded instructions."
                    )
            elif "STATUS: ERROR" in content_str:
                if has_arabic:
                    summary = (
                        "[مخرجات تجريبية محددة مسبقاً - ليست استدلالاً حقيقياً لنموذج لغوي] "
                        "تعذر استرجاع الرسالة المطلوبة، إما لأنها غير موجودة أو تابعة لمستخدم آخر."
                    )
                else:
                    summary = (
                        "[DETERMINISTIC DEMO OUTPUT - NOT REAL LLM REASONING] "
                        "Could not complete the requested email operation. "
                        "The message was either not found or access is restricted."
                    )
            else:
                summary = (
                    "[DETERMINISTIC DEMO OUTPUT - NOT REAL LLM REASONING] "
                    "Operation completed successfully."
                )

            return LLMResponse(
                content=summary,
                finish_reason="stop",
                model=self._model_name,
                usage={
                    "prompt_tokens": 150,
                    "completion_tokens": 50,
                    "total_tokens": 200,
                },
            )

        # Case B: User request requiring tool invocation
        user_text = last_message.content or ""
        lower_user = user_text.lower()

        # Attempt deterministic intent resolution for seamless Week 4 integration
        try:
            from app.intent.parser import parse_intent
            from app.intent.schemas import IntentType

            intent = parse_intent(user_text)
            if intent.intent_type in (
                IntentType.READ_LATEST_EMAILS,
                IntentType.SUMMARIZE_RECENT_EMAILS,
            ):
                limit = intent.requested_count or 5
                return LLMResponse(
                    tool_calls=[
                        ToolCall(
                            id=f"call_inbox_{self._call_count}",
                            name="read_inbox",
                            arguments=json.dumps({"limit": limit}),
                        )
                    ],
                    finish_reason="tool_calls",
                    model=self._model_name,
                )
            elif intent.intent_type == IntentType.SEARCH_EMAILS and intent.search_query:
                return LLMResponse(
                    tool_calls=[
                        ToolCall(
                            id=f"call_search_{self._call_count}",
                            name="search_emails",
                            arguments=json.dumps(
                                {"query": intent.search_query, "limit": 5}
                            ),
                        )
                    ],
                    finish_reason="tool_calls",
                    model=self._model_name,
                )
            elif (
                intent.intent_type == IntentType.READ_EMAIL_DETAILS
                and intent.requested_email_id
            ):
                return LLMResponse(
                    tool_calls=[
                        ToolCall(
                            id=f"call_detail_{self._call_count}",
                            name="get_email_details",
                            arguments=json.dumps(
                                {"email_id": intent.requested_email_id}
                            ),
                        )
                    ],
                    finish_reason="tool_calls",
                    model=self._model_name,
                )
        except Exception:
            # Fallback to existing heuristic regexes
            pass

        # Check for assignment search specifically
        if "assignment" in lower_user or "تكليف" in user_text:
            query = "assignment" if "assignment" in lower_user else "تكليف"
            return LLMResponse(
                tool_calls=[
                    ToolCall(
                        id=f"call_search_{self._call_count}",
                        name="search_emails",
                        arguments=json.dumps({"query": query, "limit": 5}),
                    )
                ],
                finish_reason="tool_calls",
                model=self._model_name,
            )

        # Check for search intention
        if "search" in lower_user or "find" in lower_user or "ابحث" in user_text:
            # Extract query candidate
            match = re.search(
                r'(?:search|find|for|ابحث عن)\s+["\']?([^"\'\n\.\?]+)["\']?',
                user_text,
                re.IGNORECASE,
            )
            query = match.group(1).strip() if match else "academic"
            return LLMResponse(
                tool_calls=[
                    ToolCall(
                        id=f"call_search_{self._call_count}",
                        name="search_emails",
                        arguments=json.dumps({"query": query, "limit": 5}),
                    )
                ],
                finish_reason="tool_calls",
                model=self._model_name,
            )

        # Check for specific email detail intention
        if (
            "detail" in lower_user
            or "email id" in lower_user
            or "read email" in lower_user
            or re.search(r"email\s+#?(\d+)", lower_user)
        ):
            id_match = re.search(r"(\d+)", user_text)
            email_id = int(id_match.group(1)) if id_match else 1
            return LLMResponse(
                tool_calls=[
                    ToolCall(
                        id=f"call_detail_{self._call_count}",
                        name="get_email_details",
                        arguments=json.dumps({"email_id": email_id}),
                    )
                ],
                finish_reason="tool_calls",
                model=self._model_name,
            )

        # Check for inbox reading or summarization intention
        if (
            "inbox" in lower_user
            or "email" in lower_user
            or "unread" in lower_user
            or "summarize" in lower_user
            or "summary" in lower_user
            or "لخص" in user_text
            or "رسائل" in user_text
            or "بريد" in user_text
        ):
            is_unread = "unread" in lower_user or "غير مقروء" in user_text
            # Extract count/limit if specified (e.g. "latest 3", "3 emails")
            count_match = re.search(
                r"(?:latest|recent|first|اقرأ)\s*(\d+)|(\d+)\s*(?:university\s+)?(?:emails|messages|رسائل)",
                lower_user,
            )
            limit = 5
            if count_match:
                extracted = count_match.group(1) or count_match.group(2)
                if extracted and extracted.isdigit():
                    limit = max(1, min(int(extracted), 20))

            args: dict[str, Any] = {"limit": limit}
            if is_unread:
                args["is_read"] = False

            return LLMResponse(
                tool_calls=[
                    ToolCall(
                        id=f"call_inbox_{self._call_count}",
                        name="read_inbox",
                        arguments=json.dumps(args),
                    )
                ],
                finish_reason="tool_calls",
                model=self._model_name,
            )

        # Default: direct helpful response without tools
        return LLMResponse(
            content="I am ready to assist with your academic mailbox. You can ask me to read your inbox, search for keywords, or inspect specific email details.",
            finish_reason="stop",
            model=self._model_name,
        )
