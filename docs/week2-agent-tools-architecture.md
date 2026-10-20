# AEGIS-CORE Week 2 Architecture Note: Mini AI Agent Tool Adapters

**Document Version:** 0.2.0  
**Status:** Implemented & Verified  
**Milestone:** Week 2 Foundation (Read-Only Mini AI Agent Tool Layer)  
**Author:** Principal Python Engineer & AI Agent Architect  
**Date:** October 20, 2026  

---

## 1. Executive Summary

In Week 2 of AEGIS-CORE, we transitioned from a passive mock REST API to an active, Python-callable tool execution interface tailored for autonomous AI agents. We implemented three typed, structured tool adapters:
- `read_inbox(user_id, limit, offset, is_read)`
- `get_email_details(user_id, email_id)`
- `search_emails(user_id, query, limit, offset)`

These adapters directly reuse the existing Week 1 domain business logic (`EmailService`, `UserService`) and repository persistence layer (`EmailRepository`, `UserRepository`), strictly avoiding duplicate database abstraction layers while upholding strict owner isolation and SQL injection resistance.

---

## 2. Text-Based Component & Layer Diagram

```
+===================================================================================+
|                             AUTONOMOUS AI AGENT RUNTIME                           |
|       (LangChain / LlamaIndex / OpenAI Tool Call / Anthropic Tool Use Standard)   |
+===================================================================================+
                                         |
                                         | Invokes Python Callables:
                                         | - read_inbox(user_id, limit)
                                         | - get_email_details(user_id, email_id)
                                         | - search_emails(user_id, query, limit)
                                         v
+===================================================================================+
|                        AGENT TOOL ADAPTER LAYER (app/agent/)                      |
|                                                                                   |
|  * Pydantic v2 Schemas (app.agent.schemas):                                       |
|    - ReadInboxInput, GetEmailDetailsInput, SearchEmailsInput                     |
|    - ReadInboxData, SearchEmailsData, ToolError                                   |
|    - ToolResult[DataT] envelope (success, data, error, tool_name, to_json)        |
|                                                                                   |
|  * Tool Adapters (app.agent.tools.email_tools):                                   |
|    - Input validation & bounds enforcement                                        |
|    - Session lifecycle management (contextmanager get_session_context)            |
|    - Standard JSON schema tool specs (get_tool_specs, EMAIL_TOOLS registry)       |
+===================================================================================+
                                         |
                                         | Reuses Existing Domain Services:
                                         v
+===================================================================================+
|                           DOMAIN SERVICE LAYER (app/services/)                    |
|                                                                                   |
|  * UserService  : User existence verification                                     |
|  * EmailService : list_user_emails, get_user_email, search_user_emails            |
+===================================================================================+
                                         |
                                         | Reuses Existing Data Repositories:
                                         v
+===================================================================================+
|                        DATA REPOSITORY LAYER (app/repositories/)                  |
|                                                                                   |
|  * UserRepository  : Bound queries for simulated tenants                         |
|  * EmailRepository : Owner-scoped SQL queries, ILIKE search, and wildcard escape   |
+===================================================================================+
                                         |
                                         v
+===================================================================================+
|                        SQLITE PERSISTENCE (app/db/ & SQLite Engine)               |
|                                                                                   |
|  * PRAGMA foreign_keys = ON; composite index (owner_id, received_at)              |
+===================================================================================+
```

---

## 3. Package Structure

The new modular structure is housed within `app/agent/`:

```
app/agent/
├── __init__.py                # Package exports (ToolResult, ToolError, tools, specs)
├── schemas.py                 # Pydantic v2 models for inputs, outputs, envelopes, and errors
└── tools/
    ├── __init__.py            # Tools package exports
    └── email_tools.py         # Python-callable tool adapters & JSON schema specs
```

---

## 4. Key Architectural & Defensive Guarantees

### 4.1 Strict Domain Reuse (No Second Database Access Layer)
The agent tool adapters do **not** query SQLAlchemy models or write SQL directly. All calls route through `EmailService` and `UserService`, preserving single-source business invariants and avoiding architectural drift.

### 4.2 SQL LIKE Wildcard Escaping
When executing keyword searches across email subjects and bodies, user queries may contain SQL wildcards (`%`, `_`) or escape characters (`/`). The repository implements `escape_like_wildcards`:
```python
def escape_like_wildcards(term: str, escape_char: str = "/") -> str:
    return (
        term.replace(escape_char, escape_char + escape_char)
        .replace("%", escape_char + "%")
        .replace("_", escape_char + "_")
    )
```
Combined with bound parameters and SQLAlchemy's `ilike(pattern, escape="/")`, wildcards are matched literally, preventing pattern-expansion denial of service or filter bypasses.

### 4.3 Defense-in-Depth Ownership Isolation
- **Search:** Query statements strictly include `.where(EmailMessage.owner_id == owner_id)`. An agent cannot search across tenant boundaries.
- **Lookup:** When an email ID does not exist OR belongs to another simulated user, the tool returns `EMAIL_NOT_FOUND` (`"Email with ID {email_id} not found for user {user_id}"`). It never returns a forbidden status or metadata that reveals cross-user email existence (anti-enumeration).

### 4.4 Standardized Structured Envelopes
Every tool returns a `ToolResult[DataT]` model with:
- `success: bool`: Unambiguous execution state.
- `tool_name: str`: Traceable tool origin.
- `data: DataT | None`: Typed Pydantic response models (`ReadInboxData`, `SearchEmailsData`, `EmailMessageResponse`).
- `error: ToolError | None`: Structured error containing `code`, `message`, and `details`.
- `.to_dict()` and `.to_json()`: Guaranteed JSON-serializable representation for LLM context windows.

---

## 5. Security Model & Access Boundary Warning

> [!WARNING]
> **SIMULATION IDENTITY NOTICE:**
> The `user_id` argument across these tool adapters is an **experimental tenant partitioner** within a local research simulator, **NOT** an authenticated identity.
>
> In production or full-agent deployment, agents must **never** supply their own `user_id` as a tool argument. In upcoming roadmap milestones (Weeks 3-5), tool calls will be intercepted by the AEGIS-CORE execution firewall, which will resolve tenant identities from authenticated agent session tokens and enforce strict permission manifests.

---

## 6. Handoff for Week 3: Tool-Call Interception & Firewall Proxy

In Week 3, the AEGIS-CORE team will build the **Tool-Call Interception Proxy**:
1. **Dynamic Tool Wrapping:** Wrap `read_inbox`, `get_email_details`, and `search_emails` with firewall interceptors.
2. **Intent & Provenance Metadata:** Capture caller Agent ID, task context, and correlation IDs before tool execution.
3. **Adversarial Benchmark Evaluation:** Benchmark baseline agent vulnerability against the 6 benign prompt-injection probes in the mock email dataset.
