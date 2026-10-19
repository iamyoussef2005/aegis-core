# AEGIS-CORE Architecture Specification

**Document Version:** 1.0.0  
**Status:** Approved (Week 1 Foundation Milestone)  
**Target Environment:** Local Python 3.12+ / FastAPI / SQLite Simulation  

---

## 1. Executive Architecture Overview

AEGIS-CORE is an experimental execution firewall and control plane designed to mediate autonomous AI agent operations. As autonomous agents are granted tool-calling access to system environments (such as reading inboxes, executing file operations, and dispatching webhooks), they become vulnerable to indirect prompt injection, data exfiltration, and privilege escalation.

AEGIS-CORE solves this by placing a deterministic, policy-enforcing mediation layer between the AI agent and underlying execution tools.

### Week 1 Foundation Scope
The goal of Week 1 is strictly the architectural and infrastructural foundation:
1. **Application Shell:** FastAPI application factory with structured logging, lifecycle management, and request correlation.
2. **Persistence Layer:** SQLAlchemy 2.x ORM models, session lifecycle, and repository abstractions backed by SQLite with strict foreign-key enforcement.
3. **Simulated Domain:** An academic email environment featuring synthetic users, bilingual (English & Arabic) communications, and labeled benign adversarial prompt injection benchmarks.
4. **REST API Interface:** Strict tenant-isolated endpoints for reading simulated emails with deterministic pagination and ordering.
5. **Quality Assurance:** Full test suite executing in memory with transactional isolation, achieving >94% statement and branch coverage.

---

## 2. Text-Based Architecture Diagram

```
+===================================================================================+
|                              AUTONOMOUS AI AGENT                                  |
|         (Client: CLI, LLM Agent Runtime, Evaluation Harness, or cURL)            |
+===================================================================================+
                                         |
                                         | HTTP / JSON Requests
                                         v
+===================================================================================+
|                                 FASTAPI APPLICATION                               |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  | Middleware Stack:                                                           |  |
|  |  * Security & Provenance Middleware (X-Correlation-ID, X-Response-Time-MS,  |  |
|  |    nosniff, DENY)                                                           |  |
|  |  * Strict CORS Middleware (Whitelisted localhost origins only)               |  |
|  |  * Global Exception Handler (JSON 500 masking with correlation ID)           |  |
|  +-----------------------------------------------------------------------------+  |
|                                         |                                         |
|                                         v                                         |
|  +-----------------------------------------------------------------------------+  |
|  | API Routing Layer (/api/v1):                                                |  |
|  |  * /health                          -> Service Readiness & DB ping          |  |
|  |  * /users                           -> List simulated tenant accounts       |  |
|  |  * /users/{user_id}/emails          -> Paginated & filtered email list      |  |
|  |  * /users/{user_id}/emails/count    -> Aggregated email counts              |  |
|  |  * /users/{user_id}/emails/recent   -> Bounded recent communications        |  |
|  |  * /users/{user_id}/emails/{email_id}-> Single message (owner verified)     |  |
|  +-----------------------------------------------------------------------------+  |
+===================================================================================+
                                         |
                                         v
+===================================================================================+
|                                DOMAIN SERVICE LAYER                               |
|                                                                                   |
|  * UserService   : Validates user existence and transforms to Pydantic responses  |
|  * EmailService  : Enforces tenant isolation, pagination limits, and sorting      |
|  * HealthService : Evaluates subsystem readiness and measures system uptime       |
+===================================================================================+
                                         |
                                         v
+===================================================================================+
|                              DATA REPOSITORY LAYER                                |
|                                                                                   |
|  * BaseRepository<T> : Generic CRUD abstraction using SQLAlchemy 2.x Select       |
|  * UserRepository    : Bound queries for User lookup by ID and unique email       |
|  * EmailRepository   : Strict owner-scoped queries (owner_id + received_at desc)  |
+===================================================================================+
                                         |
                                         v
+===================================================================================+
|                            PERSISTENCE & STORAGE LAYER                            |
|                                                                                   |
|  * SQLAlchemy 2.x Engine : SessionLocal, connection pooling, and get_db generator |
|  * SQLite Event Listener : PRAGMA foreign_keys = ON enforced on every connection  |
|  * ORM Entities          : User (1) <==== cascade ====> (N) EmailMessage          |
|  * Physical Storage      : Local SQLite database file (./aegis.db)                |
+===================================================================================+
```

---

## 3. Module Responsibilities & Separation of Concerns

The repository enforces strict separation across four distinct software tiers:

| Tier | Package | Primary Responsibilities | Allowed Dependencies | Forbidden Dependencies |
|---|---|---|---|---|
| **API & Routing** | `app.api.v1.routes` | Request routing, path/query validation, HTTP status mapping, error responses | `app.services`, `app.schemas`, `app.core` | Direct SQL / ORM queries, database models |
| **Domain Services** | `app.services` | Business invariants, tenant verification, pagination bounding, response mapping | `app.repositories`, `app.schemas`, `app.models` | HTTP requests/responses, FastAPI exceptions |
| **Data Repositories** | `app.repositories`| SQL query construction, ORM interactions, bound parameters, filtering | `app.models`, `app.db`, `sqlalchemy` | HTTP constructs, Pydantic API schemas |
| **Data Models** | `app.models` | Relational table schemas, column types, foreign keys, indexes, cascades | `app.db.base`, `sqlalchemy` | Services, Repositories, API routes |
| **Schemas** | `app.schemas` | Pydantic v2 data validation, serialization, OpenAPI schema definitions | `pydantic` | Database ORM models, Repositories |
| **Infrastructure** | `app.core`, `app.db` | Configuration parsing, structured logging, database engine lifecycle | `pydantic_settings`, `sqlalchemy` | High-level domain services |

---

## 4. Key Design Decisions & Rationale

### 4.1 SQLAlchemy 2.x Declarative 2.0 Style
- **Decision:** Utilize `DeclarativeBase` with type-annotated `Mapped[...]` and `mapped_column(...)`.
- **Rationale:** Provides static type safety, avoids legacy SQLAlchemy 1.x implicit session behaviors, and prevents typing drift when audited by Ruff or Mypy.

### 4.2 SQLite with Explicit Foreign Keys via Connect Event
- **Decision:** Attach `@event.listens_for(Engine, "connect")` executing `PRAGMA foreign_keys = ON;`.
- **Rationale:** SQLite defaults to disabling relational foreign-key integrity. By attaching an engine-level connect listener, every connection (whether production SQLite file or in-memory test database) guarantees relational integrity without relying on manual configuration.

### 4.3 Strict Tenant Isolation via Repository Scoping
- **Decision:** All email queries (`list_by_owner`, `get_by_id_and_owner`, `count_by_owner`) require `owner_id`. If an email exists but belongs to User A, a lookup by User B returns `404 Not Found` rather than `403 Forbidden`.
- **Rationale:** Returning `404` prevents adversary agents from probing whether a specific email ID exists in another user's inbox (enumeration defense).

### 4.4 Decoupled Pydantic Schemas vs. ORM Models
- **Decision:** ORM models (`app.models`) and Pydantic schemas (`app.schemas`) are strictly separated. Serialization uses `model_validate(obj, from_attributes=True)`.
- **Rationale:** Prevents accidental leakage of internal database attributes or configuration secrets, while allowing response schemas to evolve independently of storage layout.

### 4.5 Structured Logging with Sensitive Data Scrubbing
- **Decision:** Implement `SensitiveDataFilter` and `JSONFormatter` in `app.core.logging`.
- **Rationale:** AI agent security logs will eventually handle tool parameters containing credentials, API keys, and private tokens. Scrubbing regexes prevent secrets from ever hitting standard output or audit sinks.

---

## 5. Architectural Extension Points (Roadmap Alignment)

AEGIS-CORE Week 1 was built explicitly as an extensible foundation for the 10-week roadmap:

```
[Agent Request]
       |
       v
+-------------------------------+
|  1. Interception Proxy        | <--- Extension Point: Week 3 Tool-Call Interceptor
|     (Inspect tool call args)  |
+-------------------------------+
       |
       v
+-------------------------------+
|  2. Policy Enforcement Engine  | <--- Extension Point: Week 4 Deterministic Engine
|     (Allow / Deny / Prompt)   |      (Rules, Role-Based Access, LLM Guardrails)
+-------------------------------+
       |
       v
+-------------------------------+
|  3. Human-in-the-Loop Approval| <--- Extension Point: Week 5 Approval Gateway
+-------------------------------+
       |
       v
+-------------------------------+
|  4. Provenance & Audit Log    | <--- Extension Point: Week 6 Cryptographic Audit
|     (Record X-Correlation-ID) |
+-------------------------------+
       |
       v
[Domain Service / Tool Execution: Mock Email API]
```

### Planned Extension Hooks:
1. **Week 2: Agent Session & Authentication Middleware**
   - Location: `app/main.py` middleware stack.
   - Mechanism: Add token validation middleware replacing simulated `user_id` routing with authenticated session contexts.
2. **Week 3: Tool-Call Interception Layer**
   - Location: `app/api/` or dedicated proxy package `app/firewall/interceptor/`.
   - Mechanism: Inspect inbound agent tool calls before routing to underlying services.
3. **Week 4: Deterministic Policy Engine**
   - Location: `app/firewall/policies/`.
   - Mechanism: Evaluate agent tool calls against user-defined security policies (e.g., deny access to emails containing adversarial triggers).
4. **Week 6: Cryptographic Provenance Tracking**
   - Location: Hook into `request.state.correlation_id` set by `security_provenance_middleware`.
   - Mechanism: Persist execution traces and data provenance records to an append-only audit trail.
