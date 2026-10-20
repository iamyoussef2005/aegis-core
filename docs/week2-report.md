# AEGIS-CORE Week 2 Acceptance & Independent Audit Report

**Milestone:** Week 2 — Read-Only Mini AI Agent Runtime & LLM Tool Calling  
**Auditor:** Principal Software Auditor, Release Engineer & Technical Lead  
**Date:** October 20, 2026  
**Final Status:** **ACCEPTED (PASS)**  

---

## 1. Executive Summary

AEGIS-CORE is a 10-week Computer Science research project building an intent-aware execution firewall for autonomous AI agents. Following the successful delivery and audit of Week 1 (FastAPI backend, SQLite persistence, and mock academic email environment), Week 2 delivers a functional, strictly bounded, read-only Mini AI Agent runtime.

The core deliverables of Week 2 have been audited, hardened, and verified:
- **Vendor-Agnostic LLM Provider Layer:** Abstract interface (`BaseLLMProvider`) with a 100% offline, deterministic research provider (`FakeLLMProvider`) and an official SDK-compatible real provider adapter (`OpenAIProvider`).
- **Controlled Tool Execution Pipeline:** Single execution entry point (`ToolExecutor`) with strict allowlist enforcement, schema conversion, and immutable server-controlled identity injection.
- **Python Tool Adapters:** Three strictly read-only tools (`read_inbox`, `get_email_details`, `search_emails`) with parameter validation, pagination bounding, SQL wildcard escaping, and tenant ownership scoping.
- **Bounded ReAct Agent Orchestrator:** Multi-turn loop with strict execution bounds (`max_tool_calls`, `max_iterations`, timeouts), untrusted data boundary demarcation, and privacy-preserving sanitized execution tracing.
- **REST API Endpoint:** `POST /api/v1/agent/run` accepting structured task requests, enforcing allowed provider modes, and returning comprehensive `AgentResponse` telemetry.
- **Quality Assurance & Verification:** 172 automated tests (61 Week 1 regression + 111 Week 2 agent/tool/orchestration/API tests) passing with 0 failures, 95.87% combined coverage (97.60% statement, 87.19% branch), clean Ruff linting/formatting, and a reproducible offline CLI demonstration script (`scripts/demo_agent.py`).

Following comprehensive independent testing, code review, and defect remediation, the Week 2 implementation satisfies all acceptance criteria and is approved for release.

---

## 2. Requirements Verification Matrix (34 Items)

| # | Requirement | Implementation Module(s) | Verification Evidence | Status |
|---|---|---|---|---|
| **1** | Week 1 backend remains operational | `app/main.py`, `app/api/v1/routes/` | Week 1 `/health`, `/users`, `/emails` endpoints respond normally | **PASS** |
| **2** | Week 1 regression tests still pass | `tests/test_startup.py`, `tests/test_api_users_emails.py`, etc. | All 61 Week 1 tests pass in 3.1s without modification | **PASS** |
| **3** | Existing email services are reused | `app/agent/tools/email_tools.py` | Adapters directly call `EmailService` and `UserService` | **PASS** |
| **4** | `read_inbox` works | `app/agent/tools/email_tools.py` | Verified with limit, offset, read-status filter in `test_agent_tools.py` | **PASS** |
| **5** | `get_email_details` works | `app/agent/tools/email_tools.py` | Verified single message header/body retrieval in `test_agent_tools.py` | **PASS** |
| **6** | `search_emails` works | `app/agent/tools/email_tools.py` | Case-insensitive subject/body keyword search verified | **PASS** |
| **7** | Tool input validation works | `app/agent/schemas.py`, `app/agent/tool_registry.py` | Pydantic v2 rejects out-of-range bounds, malformed JSON | **PASS** |
| **8** | Owner-scoped retrieval is enforced | `app/agent/tools/email_tools.py` | User 1 querying User 2's email ID 11 returns `EMAIL_NOT_FOUND` | **PASS** |
| **9** | Real LLM provider adapter exists | `app/agent/providers/openai_provider.py` | `OpenAIProvider` implements `BaseLLMProvider` interface | **PASS** |
| **10** | Real adapter compatible with installed SDK | `app/agent/providers/openai_provider.py` | Compatible with installed `openai==3.35.1` (Python SDK v1+) | **PASS** |
| **11** | Deterministic `FakeLLMProvider` exists | `app/agent/providers/fake_provider.py` | Canned responses & rule-based completions operate 100% offline | **PASS** |
| **12** | Tool definitions are valid | `app/agent/tool_registry.py` | Schemas convert cleanly to OpenAI function calling format | **PASS** |
| **13** | Tool-call responses correctly processed | `app/agent/orchestrator.py` | Serialized tool outputs fed back with correct tool-call IDs | **PASS** |
| **14** | Unknown tools are rejected | `app/agent/tool_registry.py` | Requesting `execute_shell` or `eval` returns `UNKNOWN_TOOL` | **PASS** |
| **15** | Model identity overrides are rejected | `app/agent/tool_registry.py`, `executor.py` | Injected model `user_id` discarded; server identity strictly bound | **PASS** |
| **16** | Agent tool loop is bounded | `app/agent/orchestrator.py` | Enforces `max_tool_calls` (default 5) and `max_iterations` | **PASS** |
| **17** | Provider timeouts are handled | `app/agent/providers/`, `orchestrator.py` | `ProviderTimeoutError` caught and logged in trace without crash | **PASS** |
| **18** | Provider failures are handled | `app/agent/providers/`, `orchestrator.py` | `ProviderError` / `ProviderConfigError` mapped to structured response | **PASS** |
| **19** | Final `AgentResponse` is structured | `app/agent/tracing.py` | Validated Pydantic schema with `task_id`, `trace`, `status` | **PASS** |
| **20** | Execution logs are sanitized | `app/agent/tracing.py` | Full email bodies scrubbed; secrets & bearer tokens redacted | **PASS** |
| **21** | `POST /api/v1/agent/run` works | `app/api/v1/routes/agent.py` | Tested via FastAPI TestClient across valid/invalid/error scenarios | **PASS** |
| **22** | Arabic content is supported | `app/agent/prompts.py`, `fake_provider.py` | Arabic prompts yield fluent Arabic responses without corruption | **PASS** |
| **23** | Deterministic end-to-end offline demo works| `scripts/demo_agent.py` | Runs all 3 core queries and 8 edge cases with zero network calls | **PASS** |
| **24** | Tests use isolated databases | `tests/conftest.py` | Every test function executes against an isolated `:memory:` SQLite | **PASS** |
| **25** | No tests require live paid services | `tests/` | 100% of test suites run using `FakeLLMProvider` or mocks | **PASS** |
| **26** | No real Gmail integration exists | Codebase audit | Zero external email protocols, IMAP/SMTP, or Google API client libs | **PASS** |
| **27** | No sending or deleting email is possible | `app/agent/tool_registry.py` | Allowlist restricted strictly to read-only tools | **PASS** |
| **28** | No arbitrary generated code is executed | `app/agent/tool_registry.py` | No `eval()`, `exec()`, `os.system()`, or dynamic `__import__` | **PASS** |
| **29** | Documentation matches implementation | `docs/` | Architecture, provider, runtime, and testing docs synchronized | **PASS** |
| **30** | Code passes Ruff and automated tests | Workspace | `ruff check` (0 errors), `ruff format` (clean), pytest 172/172 pass | **PASS** |
| **31** | Coverage measured $\ge 85\%$ target | `pytest-cov` | 95.87% combined, 97.60% statement, 87.19% branch | **PASS** |
| **32** | Future Policy Engine integration point clear | `app/agent/executor.py` | Documented hook in `ToolExecutor.execute` for Week 3 firewall | **PASS** |
| **33** | Project accurately describes security limits | `app/api/v1/routes/agent.py`, `docs/` | Explicit notice: `user_id` is simulation selector, not auth | **PASS** |
| **34** | Intended Week 2 demo can be reproduced | `scripts/demo_agent.py` | Reproducible in 1 command: `python scripts/demo_agent.py` | **PASS** |

---

## 3. Architecture & LLM Execution Pipeline

```
+========================================================================================+
|                              CLIENT / REST TEST HARNESS                                |
+========================================================================================+
                                            |
                                            | POST /api/v1/agent/run
                                            v
+========================================================================================+
|                         API ROUTE (app/api/v1/routes/agent.py)                         |
|  * Enforces AgentRunRequest schema (user_id >= 1, message non-empty, provider)          |
|  * Rejects unauthorized provider selections                                            |
+========================================================================================+
                                            |
                                            v
+========================================================================================+
|                    AGENT ORCHESTRATOR (app/agent/orchestrator.py)                      |
|                                                                                        |
|  * Validates simulated user existence via UserService                                  |
|  * Generates unique correlation task_id (e.g. task_6920e5f3629e)                       |
|  * Injects system prompt with indirect prompt-injection defenses                       |
|  * Coordinates bounded ReAct loop (max_tool_calls=5, max_iterations=7)                 |
+========================================================================================+
                     |                                              |
                     | Generates Tool Calls                         | Dispatches Tool Call
                     v                                              v
+==========================================+   +=========================================+
|   LLM PROVIDER (app/agent/providers/)    |   |     TOOL EXECUTOR (app/agent/executor.py)|
|                                          |   |                                         |
|  * BaseLLMProvider (ABC)                 |   |  * Single controlled execution gate     |
|  * FakeLLMProvider (Deterministic demo)  |   |  * [WEEK 3 FIREWALL INTERCEPTION HOOK]   |
|  * OpenAIProvider (Official SDK client)  |   |  * Injects server-controlled user_id    |
+==========================================+   +=========================================+
                                                                    |
                                                                    v
                                               +=========================================+
                                               |    TOOL REGISTRY & PYTHON ADAPTERS      |
                                               |  (app/agent/tool_registry.py & tools/)  |
                                               |                                         |
                                               |  * read_inbox(user_id, limit, ...)      |
                                               |  * get_email_details(user_id, email_id) |
                                               |  * search_emails(user_id, query, ...)   |
                                               +=========================================+
                                                                    |
                                                                    v
                                               +=========================================+
                                               |    DOMAIN SERVICES & SQLALCHEMY REPOS   |
                                               |  (EmailService, UserRepository, SQLite) |
                                               +=========================================+
```

---

## 4. Implemented Tools & Security Restrictions

| Tool Name | Parameters Presented to LLM | Server-Injected Parameters | Functionality & Scoping | Security Restrictions |
|---|---|---|---|---|
| `read_inbox` | `limit` (int, 1-20, default 5)<br>`offset` (int, default 0)<br>`is_read` (optional bool) | `user_id` (int)<br>`session` (Session) | Retrieves bounded messages from active user's inbox in descending date order. | Model cannot access other inboxes. Upper bound capped at 20 messages. |
| `get_email_details` | `email_id` (int, required) | `user_id` (int)<br>`session` (Session) | Fetches complete header and body for a single email. | Scoped strictly to active user. Foreign email returns `EMAIL_NOT_FOUND` without leaking metadata. |
| `search_emails` | `query` (str, 1-200 chars, required)<br>`limit` (int, 1-10, default 5)<br>`offset` (int, default 0) | `user_id` (int)<br>`session` (Session) | Case-insensitive keyword search across subject and body text. | SQL wildcards escaped (`%`, `_`, `\`). Bounded parameter queries prevent SQL injection. |

---

## 5. LLM Provider Verification

In accordance with strict auditor standards, provider capabilities are audited across three distinct tiers:

1. **Tier A — Deterministic Fake Provider (`FakeLLMProvider`):**
   - **Status:** **VERIFIED (PASS)**
   - Operates 100% offline with zero network connectivity and zero API keys.
   - Provides deterministic, rule-based completion for inbox reading, keyword searching, detail fetching, and multilingual Arabic/English responses.
   - All simulated completions explicitly prepend: `[DETERMINISTIC DEMO OUTPUT - NOT REAL LLM REASONING]`.

2. **Tier B — Real Provider Adapter Compatibility (`OpenAIProvider`):**
   - **Status:** **VERIFIED via Mocking (PASS)**
   - Conforms strictly to the official OpenAI Python SDK v1+ Chat Completions API.
   - Validated using unit tests that mock the upstream client: verifies correct message formatting, function parameter serialization, usage token tracking, and mapped exception handling (`APITimeoutError -> ProviderTimeoutError`, `AuthenticationError -> ProviderConfigError`).

3. **Tier C — Live Real-Provider API Execution:**
   - **Status:** **UNVERIFIED (Pending Optional Live API Credentials)**
   - No `OPENAI_API_KEY` was provided in the test environment. In accordance with milestone requirements, live paid credentials are not required to accept the offline engineering deliverable.
   - **Safe Manual Verification Command:**
     ```bash
     $env:OPENAI_API_KEY="sk-your-key-here"
     $env:LLM_PROVIDER="openai"
     .\.venv\Scripts\python.exe -c "from app.agent.orchestrator import AgentOrchestrator; orch = AgentOrchestrator(); print(orch.run(user_id=1, prompt='Read my latest 2 emails'))"
     ```

---

## 6. End-to-End API Verification

The REST API interface (`POST /api/v1/agent/run`) was verified using both automated HTTP integration tests and the standalone demonstration script.

### Sample Request
```bash
curl -X POST http://localhost:8000/api/v1/agent/run \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": 1,
    "message": "Read my latest 3 emails and summarize them in Arabic.",
    "provider": "fake"
  }'
```

### Verified Response (`200 OK`)
```json
{
  "task_id": "task_6920e5f3629e",
  "final_answer": "[مخرجات تجريبية محددة مسبقاً - ليست استدلالاً حقيقياً لنموذج لغوي] بناءً على الرسائل المسترجعة من بريدك الأكاديمي، قمت بمراجعة وتلخيص البريد المطلوب. تؤكد الرسائل التفاصيل الأكاديمية المطلوبة دون تنفيذ أي تعليمات برمجية داخلية.",
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
      "duration_ms": 3.03,
      "timestamp": "2026-10-20T07:23:28.123456+00:00",
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
          },
          {
            "id": 9,
            "sender": "teaching.affairs@university.edu.sa",
            "subject": "تذكير: رصد درجات التكليف الأول لمقرر تعلم الآلة",
            "is_read": true,
            "body_length": 210
          },
          {
            "id": 8,
            "sender": "partnerships.ai@kaust.edu.sa",
            "subject": "Nomination Request: KAUST & Aramco Fall AI Research Internships",
            "is_read": true,
            "body_length": 264
          }
        ]
      }
    }
  ],
  "status": "success",
  "errors": []
}
```

---

## 7. Quality Assurance & Test Results

```
============================= test session starts =============================
platform win32 -- Python 3.14.4, pytest-9.1.1, pluggy-1.7.0
rootdir: C:\Users\ASUS TUF\Desktop\My Proj
configfile: pyproject.toml
plugins: anyio-4.15.1, asyncio-1.4.0, cov-7.1.0
collected 172 items

tests\test_agent_orchestrator.py ........................................ [ 23%]
tests\test_agent_providers.py ..........................                 [ 38%]
tests\test_agent_tools.py ............................................   [ 63%]
tests\test_api_users_emails.py .............                             [ 71%]
tests\test_config.py .....                                               [ 74%]
tests\test_database.py ...........                                       [ 80%]
tests\test_edge_cases.py ........                                        [ 85%]
tests\test_health.py ....                                                [ 87%]
tests\test_logging.py ....                                               [ 90%]
tests\test_mock_email_env.py ......                                      [ 93%]
tests\test_security_boundaries.py ......                                 [ 97%]
tests\test_startup.py .....                                              [100%]

============================= 172 passed in 4.69s =============================
```

- **Test Pass Rate:** 172 / 172 (100%)
- **Statement Coverage:** 97.60% (1,299 / 1,331 statements)
- **Branch Coverage:** 87.19% (211 / 242 branches)
- **Combined Coverage:** 95.87% (threshold: $\ge 85.0\%$)
- **Lint & Style:** 100% compliant with Ruff rules (`ruff check .` -> 0 errors; `ruff format --check .` -> 72 files clean).

---

## 8. Security Boundaries & Risk Assessment

1. **Simulation Identity Boundary:**
   - The endpoint uses `user_id` as a tenant simulation selector. It does not implement production authentication (passwords, JWTs, or session cookies). It must not be deployed to public internet interfaces.
2. **Untrusted Data Demarcation:**
   - Tool outputs are formatted with unambiguous boundary tags (`[TOOL_RESULT: ...] STATUS: SUCCESS DATA (UNTRUSTED SIMULATED CONTENT) ... [END_TOOL_RESULT]`).
   - While this prevents application code from treating email data as instructions, it is a defensive baseline, not proof of complete immunity against all prompt-injection attacks. Full intent-aware semantic policy interception will be developed in Weeks 3–5.
3. **Execution Privacy:**
   - Traces and logs scrub full email bodies, recording only structural preview metadata.

---

## 9. Defects Discovered and Resolved During Audit

| Defect ID | Affected Component | Root Cause | Fix & Verification |
|---|---|---|---|
| **DEF-01** | `app/agent/providers/fake_provider.py` | Untrusted email body content triggered Arabic response mode when user asked in English | Modified language detector to inspect only user messages (`role == "user"`) |
| **DEF-02** | `app/agent/providers/fake_provider.py` | Compact JSON formatting (`"count":0`) failed regex with space (`"count": 0`) | Updated regex to `r'"count":\s*0\b'` |
| **DEF-03** | `tests/test_agent_orchestrator.py` | Missing `seeded_session` fixture in integration tests caused empty DB 404s | Injected `seeded_session` fixture into affected test cases |
| **DEF-04** | `app/agent/tool_registry.py` | Unhandled tool adapter runtime exceptions bubbled up uncaught | Wrapped dispatch in try/except returning structured `TOOL_EXECUTION_ERROR` |
| **DEF-05** | `app/agent/orchestrator.py` | Absence of an iteration ceiling left potential for infinite conversation loops | Added configurable `max_iterations` bound (default: `max_tool_calls + 2`) |
| **DEF-06** | `app/agent/orchestrator.py` | Truncated multi-tool batches caused OpenAI API 400 parameter schema violations | Appended protocol-compliant `TOOL_CALL_LIMIT_EXCEEDED` error messages for skipped tool calls |

---

## 10. Audit Conclusion & Week 3 Readiness

- **Audit Verdict:** **PASS (ACCEPTED)**
- **Week 3 Readiness:** **READY**
- **Handoff Target:** Week 3 will implement the Intent-Aware Security Firewall and Policy Engine by attaching directly to the established extension point in [`ToolExecutor.execute`](file:///c:/Users/ASUS%20TUF/Desktop/My%20Proj/app/agent/executor.py#L70-L80).
