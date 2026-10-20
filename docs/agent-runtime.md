# AEGIS-CORE Agent Runtime & Orchestration Specification

**Document Version:** 0.3.0  
**Milestone:** Week 2 (Read-Only Mini AI Agent Execution Orchestration)  
**Status:** Approved & Implemented  
**Date:** October 20, 2026  

---

## 1. Executive Summary

Week 2 of AEGIS-CORE delivers a production-grade, bounded Mini AI Agent execution orchestrator and runtime subsystem. The agent operates in a strictly read-only mode against our simulated academic mailbox environment, interacting through a controlled tool-calling cycle.

Key architectural properties enforced by this runtime include:
- **Server-Controlled Identity:** The tenant identity (`user_id`) is strictly bound and managed server-side. The LLM is never presented with identity parameters and cannot forge or alter the active user context.
- **Untrusted Data Boundaries:** All tool output (headers, subjects, message bodies) returned from the database layer is delimited as untrusted external data (`[TOOL_RESULT: ...] STATUS: SUCCESS DATA (UNTRUSTED SIMULATED CONTENT) ... [END_TOOL_RESULT]`), preventing indirect prompt-injection instructions from hijacking the agent.
- **Strict Deterministic Bounds:** The ReAct execution loop is governed by configurable bounds: maximum tool calls per task (default: 5), model request timeouts (default: 30.0s), and token bounds.
- **Privacy-Preserving Sanitized Traces:** Full email bodies are scrubbed from telemetry, logs, and API execution traces, exposing only safe structural summaries (`items_preview` with `id`, `sender`, `subject`, and `body_length`).
- **Week 3 Extension Point:** The runtime exposes an explicit interception hook in `ToolExecutor.execute` designed to host the upcoming Week 3 Intent-Aware Execution Firewall.

---

## 2. Architecture & Component Interaction

```
+========================================================================================+
|                       HTTP CLIENT / RESEARCH TEST HARNESS                              |
+========================================================================================+
                                            |
                                            | POST /api/v1/agent/run
                                            v
+========================================================================================+
|                         API ROUTE (app/api/v1/routes/agent.py)                         |
|  * Validates request schema (AgentRunRequest)                                          |
|  * Enforces allowed provider modes ("fake", "openai")                                  |
|  * Injects database session from connection pool                                       |
+========================================================================================+
                                            |
                                            v
+========================================================================================+
|                    AGENT ORCHESTRATOR (app/agent/orchestrator.py)                      |
|                                                                                        |
|  1. Verifies simulated user existence (UserService)                                   |
|  2. Generates unique correlation `task_id` (e.g., `task_a1b2c3d4e5f6`)                 |
|  3. Initializes ExecutionTracer and conversation state with indirect-injection defenses|
|  4. Manages multi-turn ReAct loop bounded by max_tool_calls                            |
+========================================================================================+
                     |                                              |
                     | Generates Tool Calls                         | Dispatches Tool Call
                     v                                              v
+==========================================+   +=========================================+
|   LLM PROVIDER (app/agent/providers/)    |   |     TOOL EXECUTOR (app/agent/executor.py)|
|                                          |   |                                         |
|  * BaseLLMProvider abstraction           |   |  * Single controlled execution gate     |
|  * FakeLLMProvider (Offline deterministic|   |  * [WEEK 3 FIREWALL INTERCEPTION HOOK]   |
|    labeled research output)              |   |  * Binds verified server user_id        |
|  * OpenAIProvider (Official SDK client)  |   |  * Executes via ToolRegistry            |
+==========================================+   +=========================================+
                                                                    |
                                                                    | Dispatches Tool
                                                                    v
                                               +=========================================+
                                               |   TOOL REGISTRY & PYTHON TOOL ADAPTERS  |
                                               |  (app/agent/tool_registry.py & tools/)  |
                                               |                                         |
                                               |  * read_inbox                           |
                                               |  * get_email_details                    |
                                               |  * search_emails                        |
                                               +=========================================+
                                                                    |
                                                                    | Queries Scoped Data
                                                                    v
                                               +=========================================+
                                               |   DOMAIN SERVICES & SQLALCHEMY REPOS    |
                                               |   (EmailService, UserService, SQLite)   |
                                               +=========================================+
```

---

## 3. Tool Execution Lifecycle & Identity Invariance

The execution lifecycle of a single tool invocation within the orchestrator follows a 6-stage lifecycle:

1. **Model Generation:** Upstream provider requests one or more tool calls with an `id`, `tool_name`, and `raw_arguments` JSON string.
2. **Allowlist Verification:** `ToolRegistry` validates `tool_name` against the registered allowlist (`read_inbox`, `get_email_details`, `search_emails`). Unrecognized tools yield structured error results without crashing or invoking external code.
3. **Week 3 Policy Interception Hook:** Execution passes through `ToolExecutor.execute`, where the upcoming AEGIS-CORE Firewall Interceptor inspects the tool call before execution.
4. **Server Identity Injection:** The LLM-exposed tool parameter schemas explicitly omit `user_id`. Any model-supplied `user_id` is stripped; the server-verified `user_id` is injected into the kwargs.
5. **Adapter Dispatch:** The Python tool adapter runs within the active database session context, executing domain logic through `EmailService`.
6. **Delimited Output Formatting & Sanitized Tracing:**
   - The result is serialized to JSON and wrapped in delimiters for the LLM.
   - The trace records an execution summary where message bodies are scrubbed (`sanitize_result_summary`).

---

## 4. Execution Limits & Bounds

The agent runtime strictly prevents runaway loops, resource exhaustion, and denial-of-service conditions:

| Bound | Configuration Parameter | Default Value | Enforcement Mechanism |
|---|---|---|---|
| **Max Tool Calls** | `AGENT_MAX_TOOL_CALLS` | `5` | Orchestrator counter; terminates ReAct loop when exceeded with explanatory message. |
| **Max Consecutive Iterations** | Hard bounded | `max_tool_calls + 2` | Prevents infinite conversation loops even if provider generates empty responses. |
| **Model Request Timeout** | `AGENT_MODEL_TIMEOUT_SECONDS` | `30.0s` | Passed to provider HTTP client / request configuration; aborts on hung network calls. |
| **Output Token Limit** | `AGENT_MAX_OUTPUT_TOKENS` | `1024` | Sets upstream max generation tokens where supported. |
| **Query Character Limit** | Tool schema | `200` chars | Search query capped to prevent SQL/memory buffer pressure. |
| **Inbox Retrieval Limit** | Tool schema | `20` items | Read inbox results bounded between 1 and 20 items per call. |

---

## 5. Privacy & Sanitized Tracing

To prevent sensitive or private email content from leaking into application logs, monitoring pipelines, or API responses, `ExecutionTracer` applies deterministic redaction rules:

- **Full Body Stripping:** Email bodies are never recorded in `SanitizedToolExecution.result_summary`.
- **Structural Metadata Retention:** Traces retain message counts, identifiers, senders, subjects, read states, and `body_length` integers.
- **Sensitive Argument Redaction:** Keys matching passwords, tokens, API keys, or authorization secrets are replaced with `[REDACTED]`.
- **Correlation:** Every run generates a unique `task_id` (e.g., `task_12febcad4f2e`) that links log records, traces, and HTTP responses.

---

## 6. REST API Specification

### Endpoint: Execute Agent Task

- **Route:** `POST /api/v1/agent/run`
- **Content-Type:** `application/json`

#### Request Schema (`AgentRunRequest`)

| Field | Type | Required | Description |
|---|---|---|---|
| `user_id` | `int` | Yes | Target synthetic user ID (must be $\ge 1$). |
| `message` | `str` | Yes | User instruction or prompt (1 to 2000 characters). |
| `provider` | `str` | No | Target provider mode: `"fake"` (default) or `"openai"`. |

#### Request Example

```json
{
  "user_id": 1,
  "message": "Read my latest 3 university emails and summarize them in Arabic.",
  "provider": "fake"
}
```

#### Response Schema (`AgentResponse`)

```json
{
  "task_id": "task_12febcad4f2e",
  "final_answer": "[مخرجات تجريبية محددة مسبقاً - ليست استدلالاً حقيقياً لنموذج لغوي] بناءً على الرسائل المسترجعة من بريدك الأكاديمي، قمت بمراجعة وتلخيص البريد المطلوب...",
  "provider_mode": "fake",
  "tool_calls_count": 1,
  "execution_trace": [
    {
      "call_id": "call_inbox_1",
      "tool_name": "read_inbox",
      "arguments": {
        "limit": 3
      },
      "outcome": "SUCCESS",
      "duration_ms": 4.12,
      "timestamp": "2026-10-20T07:15:30.123456+00:00",
      "error_code": null,
      "error_message": null,
      "result_summary": {
        "owner_id": 1,
        "count": 3,
        "total": 10,
        "items_preview": [
          {
            "id": 10,
            "sender": "infosec@university.edu.sa",
            "subject": "Campus Security Advisory: Multi-Factor Authentication Verification",
            "is_read": true,
            "body_length": 280
          }
        ]
      }
    }
  ],
  "status": "success",
  "errors": []
}
```

#### Error Status Codes

- `400 Bad Request`: Empty or invalid user message.
- `404 Not Found`: Target user ID does not exist in the simulation database.
- `422 Unprocessable Entity`: Request body failed schema validation.
- `503 Service Unavailable`: LLM provider communication error or upstream timeout.

---

## 7. Week 3 Firewall Interception Extension Point

In Week 3, the AEGIS-CORE project will implement the Intent-Aware Security Firewall. The integration point has already been architected into `ToolExecutor`:

```python
# app/agent/executor.py
class ToolExecutor:
    def execute(
        self,
        call_id: str,
        tool_name: str,
        raw_arguments: str | dict[str, Any],
        user_id: int,
        session: Session | None = None,
    ) -> ToolExecutionOutcome:
        # ======================================================================
        # EXTENSION POINT: Week 3 Security Policy Interception
        # ----------------------------------------------------------------------
        # In Week 3, the AEGIS-CORE Firewall Interceptor will evaluate this call:
        # decision = self.policy_engine.evaluate(user_id, tool_name, raw_arguments)
        # if decision.action == PolicyAction.DENY:
        #     return self._build_denial_outcome(call_id, tool_name, decision)
        # ======================================================================
        tool_result = self.registry.execute_tool(
            tool_name=tool_name,
            raw_arguments=raw_arguments,
            user_id=user_id,
            session=session,
        )
        ...
```

This guarantees that security enforcement in Week 3 can be dropped directly into the runtime without restructuring the orchestrator or provider abstraction.

---

## 8. Verification & Test Coverage Summary

- **Total Unit & Integration Tests:** 161 passing tests
- **Measured Test Coverage:** 95.11% (threshold $\ge 85.0\%$)
- **Linters & Formatters:** 100% compliant with Ruff rules
