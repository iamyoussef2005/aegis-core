# AEGIS-CORE

**AEGIS-CORE** is a research-oriented security firewall for autonomous AI agents. It provides a mediation and control plane designed to intercept AI agent tool invocations, enforce user-approved task permissions, track data provenance, and prevent unauthorized actions.

This repository reflects the completed **Week 3: Task-Scoped Security Policy Engine & Execution Firewall** milestone of our 10-week development roadmap.

---

## 🎯 Problem Statement

As autonomous AI agents are granted access to execute system tools—such as inspecting private mailboxes, dispatching web requests, querying corporate databases, and modifying file systems—they face critical security vulnerabilities:
1. **Indirect Prompt Injection:** Adversarial instructions embedded in untrusted external data (e.g., incoming emails or web pages) can hijack agent reasoning and force malicious tool calls.
2. **Data Exfiltration:** Malicious payloads can trick an agent into transmitting sensitive user credentials or private records to untrusted endpoints.
3. **Privilege Escalation:** Unchecked agent autonomous loops can exceed intended operational boundaries and perform destructive actions without human authorization.

**AEGIS-CORE** addresses these threats by providing an intent-aware execution firewall that inspects tool calls, enforces deterministic policy rules, tracks request provenance, and mandates human-in-the-loop approval before sensitive actions execute.

---

## 📦 Milestone Progress & Scope

### Week 1 Foundation (Completed)
- **FastAPI Core:** Application factory, configuration parsing, structured JSON logging with sensitive data redaction.
- **Relational Persistence:** SQLite engine with SQLAlchemy 2.x ORM models (`User`, `EmailMessage`), foreign-key enforcement, and cascade deletion.
- **Simulated Domain:** Realistic mock academic email environment featuring 3 synthetic users, 30 bilingual (English & Arabic) messages, and 6 labeled benign adversarial prompt injection benchmarks.
- **REST API:** Endpoints for simulated users and emails with deterministic pagination, read-status filtering, and cross-tenant ownership isolation.

### Week 2 Mini AI Agent (Completed & Verified)
- **Controlled Tool Execution Pipeline:** Single execution entry point via `ToolExecutor` and `ToolRegistry` with strict allowlist enforcement, schema conversion, and immutable server-controlled identity injection.
- **Read-Only Python Tool Adapters:** Three strictly read-only tools (`read_inbox`, `get_email_details`, `search_emails`) with parameter validation, pagination bounds, SQL wildcard escaping, and tenant ownership scoping.
- **Vendor-Agnostic LLM Provider Layer:** Abstract `BaseLLMProvider` interface with a 100% offline, deterministic research provider (`FakeLLMProvider`) and an official SDK v1-compatible provider (`OpenAIProvider`).
- **Bounded ReAct Orchestrator:** Multi-turn loop with strict execution bounds (`max_tool_calls`, `max_iterations`, timeouts), untrusted data boundary demarcation, and privacy-preserving sanitized execution tracing.
- **REST API:** `POST /api/v1/agent/run` with structured request and response models (`AgentRunRequest`, `AgentResponse`).

### Week 3 Security Policy Engine & Execution Firewall (Completed & Verified)
- **Centralized Security Enforcement Gate:** `ToolExecutor` acts as a mandatory authorization choke point. Every tool call must pass through `PolicyEngine.evaluate()` before dispatch.
- **Deterministic Default-Deny Policy Engine:** Implements fail-closed evaluation (`ALLOW` or `DENY`) against server-owned, immutable `TaskPolicy` instances.
- **Task-Scoped Parameter Constraints:** Deterministic argument boundaries (`ReadInboxConstraint`, `GetEmailDetailsConstraint`, `SearchEmailsConstraint`) enforcing limits, offsets, allowed email IDs, and query lengths.
- **Anti-Escalation & Identity Scrubbing:** Model-generated arguments attempting to inject `policy`, `user_id`, or `task_id` are scrubbed before validation. The agent cannot alter its own permissions.
- **Zero-Invocation Guarantee on Denials:** Denied tool calls invoke underlying adapters or database operations **zero times**.
- **Comprehensive Quality Assurance:** 404 automated tests passing (100%) with 95.49% combined statement and branch coverage, clean Ruff linting, and 0 regressions.
- **Comparative Security Benchmark:** Reproducible 50-operation benchmark (`scripts/run_security_benchmark.py`) proving a **0.00% Unauthorized Execution Rate (UER)** and sub-millisecond decision latency ($128.55\ \mu\text{s}$).

---

## 🛠️ Tech Stack & Technologies Used

- **Language:** Python 3.12+ (tested on Python 3.14)
- **API Framework:** FastAPI 0.115+
- **ASGI Server:** Uvicorn
- **ORM & Database:** SQLAlchemy 2.0+ with SQLite
- **Validation & Settings:** Pydantic v2 & Pydantic-Settings
- **LLM Integration:** OpenAI Python SDK v1+ (`openai>=1.30.0`)
- **Test Automation:** Pytest 8.2+, pytest-asyncio, pytest-cov, HTTPX
- **Linter & Formatter:** Ruff 0.5+
- **Version Control:** Git

---

## 🏛️ Modular Architecture

```
aegis-core/
├── app/
│   ├── __init__.py               # Package metadata and version definition
│   ├── main.py                   # Application factory, lifespan, CORS, and provenance middleware
│   ├── agent/                    # Mini AI Agent runtime & LLM tool integration
│   │   ├── __init__.py           # Agent package exports
│   │   ├── exceptions.py         # Agent domain exceptions hierarchy
│   │   ├── executor.py           # ToolExecutor: controlled tool execution gate & Week 3 firewall hook
│   │   ├── orchestrator.py       # AgentOrchestrator: bounded multi-turn ReAct loop
│   │   ├── prompts.py            # Contextualized system prompts with indirect prompt-injection defenses
│   │   ├── runner.py             # Backward-compatible agent runner
│   │   ├── schemas.py            # Pydantic v2 tool input/output envelopes
│   │   ├── tool_registry.py      # ToolRegistry: static allowlist, schema conversion, user_id binding
│   │   ├── tracing.py            # ExecutionTracer: privacy-preserving sanitized traces & AgentResponse
│   │   ├── providers/            # LLM provider implementations
│   │   │   ├── __init__.py       # Provider factory (get_provider)
│   │   │   ├── base.py           # BaseLLMProvider ABC and normalized message models
│   │   │   ├── fake_provider.py  # FakeLLMProvider: deterministic offline research provider
│   │   │   └── openai_provider.py# OpenAIProvider: official OpenAI SDK v1+ client
│   │   └── tools/                # Python-callable tool adapters
│   │       ├── __init__.py       # Tools package exports
│   │       └── email_tools.py    # read_inbox, get_email_details, search_emails adapters
│   ├── api/                      # Presentation layer
│   │   ├── __init__.py
│   │   └── v1/
│   │       ├── __init__.py       # v1 API router aggregation
│   │       └── routes/
│   │           ├── __init__.py
│   │           ├── agent.py      # POST /api/v1/agent/run agent execution endpoint
│   │           ├── health.py     # GET /api/v1/health diagnostic endpoint
│   │           └── users.py      # Simulated users and mock email REST endpoints
│   ├── core/                     # Infrastructure foundations
│   │   ├── __init__.py
│   │   ├── config.py             # Type-safe environment settings (Pydantic v2 Settings)
│   │   └── logging.py            # Structured JSON/Console logging with sensitive data redaction
│   ├── db/                       # Persistence foundations
│   │   ├── __init__.py
│   │   ├── base.py               # SQLAlchemy 2.x DeclarativeBase and TimestampMixin
│   │   └── session.py            # Engine lifecycle, SQLite FK connect listener, get_db generator
│   ├── models/                   # SQLAlchemy ORM mapped entities
│   │   ├── __init__.py
│   │   ├── user.py               # User mapped model (1-to-many relationship)
│   │   └── email_message.py      # EmailMessage mapped model (owner_id FK, composite indexes)
│   ├── schemas/                  # Pydantic v2 request/response schemas
│   │   ├── __init__.py
│   │   ├── email.py              # EmailMessageResponse, EmailListResponse, EmailCountResponse
│   │   ├── health.py             # HealthResponse & DatabaseHealth schemas
│   │   └── user.py               # UserBase, UserCreate, UserResponse schemas
│   ├── security/                 # Task-scoped deterministic security policy engine
│   │   ├── __init__.py           # Security exports (PolicyEngine, TaskPolicy, constraints)
│   │   ├── context.py            # Trusted TaskContext (task_id, user_id, policy)
│   │   ├── exceptions.py         # SecurityPolicyError hierarchy
│   │   ├── policy_engine.py      # Deterministic, fail-closed policy evaluator
│   │   ├── profiles.py           # Predefined demonstration profiles & factory methods
│   │   └── schemas.py            # TaskPolicy, PolicyDecision, ToolExecutionRequest, constraints
│   ├── repositories/             # Data access repository layer (Repository Pattern)
│   │   ├── __init__.py
│   │   ├── base.py               # Generic BaseRepository CRUD implementation
│   │   ├── user.py               # UserRepository with bound parameter queries
│   │   └── email.py              # EmailRepository with owner-scoped queries and wildcards
│   └── services/                 # Domain business logic layer
│       ├── __init__.py
│       ├── email.py              # Email domain service with tenant isolation
│       ├── health.py             # System uptime and health inspection service
│       └── user.py               # User domain service
├── docs/                         # Architecture, API, testing, and handoff documentation
│   ├── architecture.md           # System architecture, module boundaries, diagrams
│   ├── api.md                    # REST API reference, schemas, curl examples
│   ├── testing.md                # QA testing guide, categories, isolation guarantees
│   ├── week1-report.md           # Week 1 audit and acceptance report
│   ├── week2-agent-tools-architecture.md # Tool adapters architecture
│   ├── agent-provider.md         # LLM provider specification
│   ├── agent-runtime.md          # Agent runtime & orchestration specification
│   ├── week2-testing.md          # Week 2 QA automation & verification report
│   ├── week2-report.md           # Week 2 independent audit and acceptance report
│   ├── week3-handoff.md          # Week 3 engineering handoff guide
│   ├── week3-policy-design.md    # Week 3 policy contract and schema design
│   ├── week3-enforcement.md      # Week 3 execution gate integration guide
│   ├── week3-security-testing.md # Week 3 comprehensive security verification & benchmark report
│   ├── week3-report.md           # Week 3 milestone acceptance and independent audit report
│   └── week4-handoff.md          # Week 4 engineering handoff guide
├── tests/                        # Automated test suite (404 tests, in-memory SQLite)
│   ├── __init__.py
│   ├── conftest.py               # Pytest fixtures (in-memory SQLite, HTTP clients)
│   ├── test_adversarial_injection_scenarios.py # Indirect prompt injection attack scenarios
│   ├── test_agent_orchestrator.py# Agent orchestrator ReAct loop, bounds, tracing, REST API
│   ├── test_agent_providers.py   # Fake & OpenAI providers, tool registry, argument validation
│   ├── test_agent_tools.py       # Python tool adapters unit tests
│   ├── test_api_users_emails.py  # User & email API integration tests
│   ├── test_comparative_benchmark.py # Automated comparative benchmark assertion suite
│   ├── test_config.py            # Environment configuration validation tests
│   ├── test_database.py          # Database connectivity, sessions, and CRUD tests
│   ├── test_deterministic_constraints.py # Tool argument constraints unit tests
│   ├── test_edge_cases.py        # Empty inbox, boundary limits, and malformed parameter tests
│   ├── test_execution_integration_verification.py # Mock counter zero-invocation verification
│   ├── test_firewall_integration.py # Centralized execution gate integration tests
│   ├── test_health.py            # Health and diagnostic probe tests
│   ├── test_logging.py           # Structured logging and secret redaction tests
│   ├── test_mock_email_env.py    # Foreign keys, cascades, and seed reproducibility tests
│   ├── test_policy_unit_verification.py # Comprehensive PolicyEngine unit verification
│   ├── test_security_boundaries.py # Tenant isolation, SQLi, and traceback masking tests
│   ├── test_security_policy.py   # TaskPolicy schemas and validation tests
│   └── test_startup.py           # Application factory, routing, and OpenAPI tests
├── scripts/
│   ├── __init__.py
│   ├── benchmark_engine.py       # 50-operation comparative benchmark harness
│   ├── demo_agent.py             # Reproducible end-to-end offline agent demo with firewall
│   ├── run_dev.py                # Development server runner
│   ├── run_security_benchmark.py # CLI runner for comparative security benchmark
│   └── seed_mock_data.py         # Deterministic, idempotent mock email seeding script
├── .env.example                  # Environment configuration template
├── .gitignore                    # Git exclusions
├── pyproject.toml                # Project packaging, dependencies, Ruff, & pytest config
└── README.md                     # Project documentation
```

---

## 🚀 Installation & Environment Setup

### 1. Prerequisites
Ensure Python 3.12 or newer is installed:
```bash
python --version
```

### 2. Environment Setup
Create and activate a virtual environment:
```bash
# Windows (PowerShell)
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Linux / macOS
python -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies
Install the package in editable mode with development dependencies:
```bash
pip install -e ".[dev]"
```

### 4. Configure Environment Variables
Copy `.env.example` to `.env`:
```bash
# Windows (PowerShell)
Copy-Item .env.example .env

# Linux / macOS
cp .env.example .env
```
Default settings configure a local SQLite database (`./aegis.db`) bound strictly to `127.0.0.1` and `LLM_PROVIDER="fake"`.

---

## 🗄️ Database Initialization & Demo Data Seeding

### 1. Database Initialization
Tables are automatically created on application startup via the lifespan event handler (`init_db()`).

### 2. Seed Deterministic Mock Data
Populate the database with 3 demo academic users and 30 realistic academic emails:
```bash
python -m scripts.seed_mock_data
```

---

## 🤖 Running the Mini AI Agent Demo

AEGIS-CORE includes a standalone, 100% offline reproducible demo script that executes the complete agent tool-calling pipeline with the deterministic security firewall enabled, requiring no API keys or external network connections:

```bash
python scripts/demo_agent.py
```

This script verifies:
1. "Read my latest 3 emails and summarize them in Arabic" (`ALLOW`).
2. "Search for emails about assignments" (`ALLOW`).
3. "Show me the details of email 1" (`ALLOW`).
4. Unknown user handling (`UserNotFoundError` $\rightarrow$ 404).
5. Missing email handling (`EMAIL_NOT_FOUND`).
6. Cross-user isolation (User 1 cannot access User 2's email; blocked with `USER_MISMATCH`).
7. Invalid tool rejection (arbitrary `execute_shell` rejected with `TOOL_NOT_ALLOWED`).
8. Malformed argument handling (`ARGUMENT_INVALID`).
9. Tool-call budget limit enforcement (`max_tool_calls_exceeded`).
10. Provider timeout handling (`ProviderTimeoutError`).
11. Untrusted indirect prompt-injection content treated strictly as body text.

---

## 🛡️ Running the Comparative Security Benchmark

Week 3 features a reproducible comparative benchmark contrasting an unprotected baseline agent with the AEGIS-CORE protected firewall across 50 operations (25 legitimate, 25 unauthorized):

```bash
python scripts/run_security_benchmark.py
```

### Benchmark Results
- **Unauthorized Execution Rate (UER):** **0.00%** under AEGIS-CORE (vs. 72.00% unprotected baseline).
- **Legitimate Operation Allow Rate (LOAR):** **100.00%** (zero usability penalty).
- **False Denial Rate (FDR):** **0.00%**.
- **Mean Policy Decision Latency:** **$128.55\ \mu\text{s}$** (sub-millisecond evaluation).

---

## 💻 Starting the REST API

### Launch via Uvicorn
```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### API Documentation Locations
- **Interactive Swagger UI:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc Documentation:** [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)
- **OpenAPI 3.x JSON Specification:** [http://127.0.0.1:8000/openapi.json](http://127.0.0.1:8000/openapi.json)

---

## 🩺 REST API Endpoint Summary

| Method | Endpoint | Description | Status Codes |
|---|---|---|---|
| `POST` | `/api/v1/agent/run` | Execute bounded Mini AI Agent task with task policy enforcement & audit trace | `200`, `404`, `422`, `503` |
| `GET` | `/api/v1/health` | Service diagnostics, database ping, uptime | `200`, `503` |
| `GET` | `/api/v1/users` | List demo academic users | `200` |
| `GET` | `/api/v1/users/{user_id}/emails` | List owner emails with limit, offset, and is_read filters | `200`, `404`, `422` |
| `GET` | `/api/v1/users/{user_id}/emails/count` | Total email count with optional is_read filter | `200`, `404`, `422` |
| `GET` | `/api/v1/users/{user_id}/emails/recent` | Latest emails ordered by received_at desc (1-10 messages) | `200`, `404`, `422` |
| `GET` | `/api/v1/users/{user_id}/emails/{email_id}` | Fetch single email with strict ownership isolation | `200`, `404` |

---

## 🧪 Running Tests & Quality Verification

All 404 tests run against in-memory SQLite instances with zero side-effects on local developer databases:

```bash
# Execute the full 404-test suite with statement and branch coverage
pytest --cov=app --cov-branch --cov-report=term-missing

# Run code style and lint checks with Ruff
ruff check .

# Check code formatting with Ruff
ruff format --check .
```

---

## ⚠️ Known Limitations & Research Boundaries

1. **Simulation Identity Model:** The `user_id` parameter serves as an experimental tenant/inbox selector in a local simulator, **not** an authenticated session. Cryptographic session tokens and manifests are scheduled for future phases.
2. **Read-Only Scope:** The agent cannot send, update, forward, or delete emails. The tool registry strictly enforces read-only operations.
3. **Static Pre-Scoping:** Week 3 evaluates pre-scoped policies assigned at task initialization. Dynamic natural-language intent inference and dynamic policy proposals are scheduled for Week 4.
4. **Local Database:** Built on SQLite for reproducible research. Distributed databases will be addressed in Week 8.

---

## 🗺️ 10-Week Research Roadmap

- **Week 1 (Completed):** Project foundation, modular architecture, SQLite models, mock academic email environment, REST API, QA automation.
- **Week 2 (Completed):** Mini AI Agent runtime, read-only tool adapters, LLM provider abstraction, ReAct orchestrator, sanitized tracing, and `POST /api/v1/agent/run` API.
- **Week 3 (Completed):** Task-Scoped Deterministic Security Policy Engine & Centralized Execution Gate (`ToolExecutor`). Default-deny evaluation, argument constraints, anti-escalation, zero-call guarantee.
- **Week 4 (Next):** Natural-language intent inference and dynamic permission proposal with trusted approval gates.
- **Week 5:** Interactive human-in-the-loop (HITL) approval mechanism.
- **Week 6:** Immutable data provenance tracking and cryptographic audit log.
- **Week 7:** Anomaly detection and behavioral rate-limiting.
- **Week 8:** Agent sandbox execution integration (MCP, local runners).
- **Week 9:** End-to-end red-teaming and prompt-injection resistance testing.
- **Week 10:** Production hardening, research release, and documentation.

See [docs/week4-handoff.md](docs/week4-handoff.md) for the detailed engineering handoff guide for Week 4.
