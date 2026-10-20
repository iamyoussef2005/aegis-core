# AEGIS-CORE LLM Provider & Agent Tool-Calling Specification

**Document Version:** 0.2.0  
**Milestone:** Week 2 (Read-Only Mini AI Agent Provider Integration)  
**Status:** Approved & Implemented  
**Date:** October 20, 2026  

---

## 1. Executive Summary

AEGIS-CORE Week 2 introduces a vendor-agnostic LLM provider abstraction and tool-calling execution coordinator for our read-only Mini AI Agent. This layer enables autonomous agents to interact with our simulated academic email environment through structured function calling while strictly maintaining:
- Server-controlled user identity (immutable `user_id`).
- Untrusted data separation (preventing indirect prompt-injection execution).
- Multi-lingual capability (Arabic and English academic communication).
- Strict upper bounds on tool calls, token generation, and network timeouts.

The architecture decouples the LLM communication plane (`BaseLLMProvider`) from tool argument parsing, validation, and execution (`ToolRegistry` and `AgentRunner`), ensuring the system can operate with live production providers (`OpenAIProvider`) or completely offline with zero credentials (`FakeLLMProvider`).

---

## 2. Architecture Overview & Component Diagram

```
+===================================================================================+
|                             USER QUERY / CLI HARNESS                              |
+===================================================================================+
                                         |
                                         v
+===================================================================================+
|                        AGENT RUNNER (app/agent/runner.py)                         |
|                                                                                   |
|  * Orchestrates the multi-turn ReAct conversation loop                            |
|  * Bounds execution: max_tool_calls (default 5), timeout, max_tokens              |
|  * Injects system prompt with indirect prompt-injection defenses                  |
|  * Tags all tool outputs as UNTRUSTED DATA before feeding back to LLM context     |
+===================================================================================+
                     |                                           |
                     | 1. Generates Completion                   | 2. Dispatches Tool Calls
                     v                                           v
+=========================================+   +=====================================+
|  PROVIDER LAYER (app/agent/providers/)  |   | TOOL REGISTRY (tool_registry.py)    |
|                                         |   |                                     |
|  * BaseLLMProvider (ABC)                |   |  * Strict allowlist validation      |
|  * FakeLLMProvider (Offline/Testing)    |   |  * Pydantic argument parsing        |
|  * OpenAIProvider (Official SDK)        |   |  * FORCED server-side user_id       |
+=========================================+   +=====================================+
                                                                 |
                                                                 | Executes
                                                                 v
                                              +=====================================+
                                              | EMAIL TOOLS (tools/email_tools.py)  |
                                              |                                     |
                                              |  * read_inbox                       |
                                              |  * get_email_details                |
                                              |  * search_emails                    |
                                              +=====================================+
                                                                 |
                                                                 v
                                              +=====================================+
                                              | DOMAIN SERVICES (Email/UserService) |
                                              +=====================================+
```

---

## 3. Supported Tools & Parameter Schemas

All tools are converted from Pydantic models to OpenAI-compliant function definitions:

| Tool Name | Parameters Presented to LLM | Description | Server-Enforced Identity |
|---|---|---|---|
| `read_inbox` | `limit` (int, 1-20, default 5)<br>`offset` (int, default 0)<br>`is_read` (optional bool) | Reads recent messages from the simulated user's inbox with pagination and read-status filtering. | `user_id` injected server-side; model input ignored. |
| `get_email_details` | `email_id` (int, min 1, required) | Fetches the complete headers, metadata, and body text of a single email message. | Scoped to active user. Foreign email returns `EMAIL_NOT_FOUND`. |
| `search_emails` | `query` (str, 1-200 chars, required)<br>`limit` (int, 1-10, default 5)<br>`offset` (int, default 0) | Searches subject and body text with case-insensitivity and wildcard escaping. | Scoped strictly to active user's messages. |

---

## 4. Configuration & Environment Variables

All settings are managed via Pydantic Settings (`app/core/config.py`) and loaded from `.env`:

| Variable | Type | Default | Description |
|---|---|---|---|
| `LLM_PROVIDER` | `str` | `"fake"` | Active provider: `"fake"` for offline tests/demos, `"openai"` for live API. |
| `OPENAI_API_KEY` | `str` | `None` | OpenAI API key. Required when `LLM_PROVIDER="openai"`. Never log or print. |
| `OPENAI_BASE_URL` | `str` | `None` | Custom base URL for proxies or OpenAI-compatible local gateways. |
| `OPENAI_MODEL` | `str` | `"gpt-4o-mini"` | Target OpenAI model identifier (e.g. `gpt-4o-mini`, `gpt-4o`). |
| `AGENT_MAX_TOOL_CALLS`| `int` | `5` | Maximum number of sequential tool calls allowed per task execution. |
| `AGENT_MODEL_TIMEOUT_SECONDS`| `float` | `30.0` | HTTP network timeout for upstream model requests. |
| `AGENT_MAX_OUTPUT_TOKENS` | `int` | `1024` | Upper bound for model response token generation. |

---

## 5. Providers

### 5.1 Deterministic Fake Provider (`FakeLLMProvider`)
The `FakeLLMProvider` enables 100% offline development, CI/CD pipeline automation, and reproducible research:
- **Zero Credentials:** Operates without any API keys or network sockets.
- **Rule-Based Completion:** Automatically infers tool calls based on user prompts (inbox reading, keyword searching, detail inspection) and bilingual Arabic/English responses.
- **Canned Responses:** Supports queued `LLMResponse` objects for deterministic multi-step testing.
- **Fault Injection:** Supports `force_timeout=True` and `force_api_error=True` to verify agent error recovery.

### 5.2 Real OpenAI Provider (`OpenAIProvider`)
The `OpenAIProvider` connects directly to the official OpenAI API using `openai>=1.30.0`:
- **Graceful Failure:** If `LLM_PROVIDER="openai"` is configured without `OPENAI_API_KEY`, it fails gracefully with a `ProviderConfigError` detailing exact configuration steps.
- **Message Translation:** Maps internal `ChatMessage` records (system, user, assistant tool calls, tool results) to the OpenAI chat completions schema.
- **Exception Normalization:** Translates SDK `APITimeoutError` into `ProviderTimeoutError`, `AuthenticationError` into `ProviderConfigError`, and `OpenAIError` into `ProviderAPIError`.
- **Injection for Testing:** Accepts a mock client instance in tests to verify edge cases without incurring API costs.

---

## 6. Real Provider Setup & Running Demos

### Step 1: Configure Environment Variables
Copy `.env.example` to `.env` and set:
```bash
LLM_PROVIDER="openai"
OPENAI_API_KEY="sk-proj-your-actual-key-here"
OPENAI_MODEL="gpt-4o-mini"
```

### Step 2: Python Code Example
```python
from app.agent.runner import AgentRunner
from app.agent.providers import get_provider

# Automatically selects OpenAIProvider when LLM_PROVIDER="openai"
runner = AgentRunner(provider=get_provider())

# Execute a query on behalf of User 1 (Dr. Layla Al-Mansoor)
result = runner.run(
    user_id=1,
    prompt="What are the latest announcements regarding teaching evaluations in my inbox?",
)

print("Agent Response:\n", result.final_answer)
print(f"Executed {result.tool_calls_count} tool call(s).")
```

---

## 7. Cost Considerations & Token Economics

When using `OpenAIProvider`, token consumption is strictly managed through:
1. **Model Selection:** Default is `gpt-4o-mini`, providing high tool-calling fidelity at ~$0.15 per million input tokens.
2. **Strict Tool Call Ceiling:** Capped at `AGENT_MAX_TOOL_CALLS=5`. An agent cannot enter runaway execution loops.
3. **Bounded Results:** `read_inbox` is capped at 20 messages, `search_emails` at 10 messages, preventing massive context window inflation.
4. **Token Generation Cap:** `AGENT_MAX_OUTPUT_TOKENS=1024` bounds completion generation costs per turn.

---

## 8. Security Boundaries & Known Limitations

> [!WARNING]
> **CRITICAL SECURITY NOTICE (WEEK 2 RESEARCH SCOPE):**
> 1. **No Authorization Firewall Yet:** The deterministic policy firewall (Allow/Deny/Prompt-User) is scheduled for **Weeks 3 and 4**. The current implementation relies on server-controlled `user_id` binding, schema validation, and read-only tools.
> 2. **Indirect Prompt Injection:** While the system instruction and tool delimiters explicitly classify email text as untrusted data, LLMs can still theoretically be susceptible to novel adversarial injections. Real firewall interception and red-teaming benchmarks occur in Weeks 3 and 9.
> 3. **Read-Only Capability:** Sending, forwarding, or deleting emails is physically impossible in this release because no write tool adapters exist.
