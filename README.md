# 🛡️ AEGIS-CORE

> **An Intent-Aware Execution Firewall & Least-Privilege Authorization Runtime for Autonomous AI Agents**

[![Python 3.12+](https://img.shields.io/badge/python-3.12%20%7C%203.14-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/license-Apache_2.0-blue.svg)](pyproject.toml)
[![Tests](https://img.shields.io/badge/tests-591%20passed-brightgreen.svg)](tests/)
[![Coverage](https://img.shields.io/badge/coverage-93.79%25-success.svg)](tests/)

**AEGIS-CORE** is a research-oriented security firewall for autonomous AI agents. It provides a mediation and control plane designed to intercept AI agent tool invocations, enforce user-approved task permissions, track data provenance, and prevent unauthorized actions.

This repository reflects the completed **Week 4: Intent Extraction, Least-Privilege Permission Proposals, and Trusted Approval Gate** milestone of our 10-week development roadmap.

---

## 🎯 Problem Statement

As autonomous AI agents are granted access to execute system tools—such as inspecting private mailboxes, dispatching web requests, querying corporate databases, and modifying file systems—they face critical security vulnerabilities:
1. **Indirect Prompt Injection:** Adversarial instructions embedded in untrusted external data (e.g., incoming emails or web pages) can hijack agent reasoning and force malicious tool calls.
2. **Data Exfiltration:** Malicious payloads can trick an agent into transmitting sensitive user credentials or private records to untrusted endpoints.
3. **Privilege Escalation:** Unchecked agent autonomous loops can exceed intended operational boundaries and perform destructive actions without human authorization.
4. **Autonomous Self-Approval:** Stochastic LLM agents cannot be trusted to approve or broaden their own security permissions midway through execution.

**AEGIS-CORE** addresses these threats by providing an intent-aware execution firewall that extracts structured task intent, derives minimal permission proposals, mandates trusted supervisor approval before execution, and enforces deterministic policy rules at the runtime gate.

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
- **Comparative Security Benchmark:** Reproducible 50-operation benchmark (`scripts/run_security_benchmark.py`) proving a **0.00% Unauthorized Execution Rate (UER)** and sub-millisecond decision latency.

### Week 4 Intent-to-Policy & Trusted Permission Approval (Completed & Verified)
- **Multilingual Deterministic Intent Parser:** Natural-language intent extraction supporting English and Arabic (`app/intent/parser.py`), handling Eastern Arabic numerals, number words, Alef normalizations, and proclitic stripping.
- **Least-Privilege Permission Proposals:** Automated, deterministic mapping (`app/intent/mappings.py`) from validated `TaskIntent` models to minimal `PermissionProposal` specifications with zero wildcards.
- **Controlled Approval State Machine:** 5-state lifecycle (`PENDING` $\rightarrow$ `APPROVED` | `REJECTED` | `EXPIRED` $\rightarrow$ `CONSUMED`) guarded by `threading.RLock` and unforgeable proposal tokens (`app/intent/approval.py`).
- **Trusted Supervisor Boundary:** Strict enforcement requiring explicit authorization headers (`X-AEGIS-Controller: local-supervisor`); untrusted model self-approvals (`llm_agent`) and missing credentials fail closed (HTTP 403 Forbidden).
- **Secured Execution Runtime:** `POST /api/v1/tasks/{task_id}/execute` resolving server-owned state with at-most-once execution guarantees to prevent token replay attacks.
- **Legacy Mode Containment:** `POST /api/v1/agent/run` permanently tagged with warning audit headers as an unapproved benchmark-only mode.
- **Comprehensive Verification:** 591 automated tests passing (100%) with 94.70% code coverage, 0 regressions, and 100% accuracy on the 48-sample hold-out intent benchmark.

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
│   │   │   ├── fake_provider.py  # FakeLLMProvider: deterministic offline research provider (EN/AR)
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
│   │           ├── agent.py      # POST /api/v1/agent/run (isolated legacy benchmark endpoint)
│   │           ├── health.py     # GET /api/v1/health diagnostic endpoint
│   │           ├── permissions.py# POST /permissions/propose, /{id}/approve, /{id}/reject
│   │           ├── tasks.py      # POST /api/v1/tasks/{task_id}/execute secured execution endpoint
│   │           └── users.py      # Simulated users and mock email REST endpoints
│   ├── intent/                   # NEW: Week 4 Intent extraction & approval lifecycle subsystem
│   │   ├── __init__.py           # Public exports
│   │   ├── approval.py           # PermissionApprovalService & thread-safe ProposalStore
│   │   ├── evaluation.py         # 48-sample hold-out intent benchmark dataset & runner
│   │   ├── exceptions.py         # IntentError and ProposalSecurityError hierarchy
│   │   ├── mappings.py           # Least-privilege intent-to-constraint mapping
│   │   ├── parser.py             # Multilingual regex/NLP deterministic IntentParser (EN/AR)
│   │   ├── proposals.py          # ProposalGenerator, SHA-256 revision hashing, validation
│   │   └── schemas.py            # Pydantic v2 TaskIntent, PermissionProposal, ApprovalReceipt
│   ├── security/                 # Task-scoped deterministic security policy engine
│   │   ├── __init__.py           # Security exports (PolicyEngine, TaskPolicy, constraints)
│   │   ├── context.py            # Trusted TaskContext (task_id, user_id, policy)
│   │   ├── exceptions.py         # SecurityPolicyError hierarchy
│   │   ├── policy_engine.py      # Deterministic, fail-closed policy evaluator
│   │   ├── profiles.py           # Predefined demonstration profiles & factory methods
│   │   └── schemas.py            # TaskPolicy, PolicyDecision, ToolExecutionRequest, constraints
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
├── docs/                         # Milestone specifications, architecture, and verification reports
│   ├── week1-report.md           # Week 1 audit and acceptance report
│   ├── week2-report.md           # Week 2 independent audit and acceptance report
│   ├── week3-report.md           # Week 3 milestone acceptance and independent audit report
│   ├── week4-intent-design.md    # Week 4 intent extraction architecture & Arabic normalizer
│   ├── week4-proposals.md        # Week 4 least-privilege permission proposal specifications
│   ├── week4-approval.md         # Week 4 approval controller state machine and trust model
│   ├── week4-testing.md          # Week 4 comprehensive security verification & QA report
│   ├── week4-report.md           # Week 4 milestone acceptance and independent audit report
│   └── week5-handoff.md          # Week 5 engineering handoff guide (Provenance & Trust Tiers)
├── tests/                        # Automated test suite (591 tests, in-memory SQLite)
├── scripts/
│   ├── benchmark_engine.py       # 50-operation comparative benchmark harness
│   ├── run_security_benchmark.py # CLI runner for comparative security benchmark
│   ├── seed_mock_data.py         # Deterministic, idempotent mock email seeding script
│   └── week4_demo.py             # Week 4 end-to-end interactive / offline approval demo
└── pyproject.toml                # Project packaging, dependencies, Ruff, & pytest config
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

## 🤖 Running the Week 4 Approval & Execution Demo

AEGIS-CORE includes a standalone, 100% offline reproducible demo script that demonstrates the entire intent-to-execution workflow with the approval gate enabled:

```bash
python scripts/week4_demo.py
```

This script verifies:
1. **Scenario 1 (English Read):** *"Read my latest 3 emails."* $\rightarrow$ Proposes `read_inbox` (limit 3) $\rightarrow$ Supervisor approves $\rightarrow$ Executed through `PolicyEngine` firewall.
2. **Scenario 2 (Arabic Summarize):** *"لخص آخر 2 إيميلات بالعربي."* $\rightarrow$ Proposes `read_inbox` (limit 2) $\rightarrow$ Approved $\rightarrow$ Returns Arabic deterministic summary.
3. **Scenario 3 (Search Scoping):** *"Search emails for assignment."* $\rightarrow$ Proposes `search_emails` (exact term: `assignment`) $\rightarrow$ Firewall verifies exact match.
4. **Scenario 4 (Security Gates):** Demonstrates real-time blocking of unapproved execution (409), replay attacks (409), and untrusted model self-approval (403).

---

## 📊 Running the Intent Parsing Evaluation Benchmark

Evaluate the deterministic intent parser and proposal generator against the 48-sample hold-out benchmark:

```bash
python app/intent/evaluation.py
```

### Benchmark Metrics
- **Overall Classification Accuracy:** **100.00%** (48/48)
- **Proposal Generation Accuracy:** **100.00%**
- **False Denial Count:** **0**
- **False Acceptance Count:** **0**
- **Mean Latency:** **~55 µs** (sub-millisecond parsing)

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
- **Underlying Adapter Calls on Denials:** **0 calls** (Zero-invocation guarantee).

---

## 🩺 REST API Endpoint Summary

| Method | Endpoint | Description | Status Codes |
|---|---|---|---|
| `POST` | `/api/v1/permissions/propose` | Parse natural language intent into bounded PermissionProposal (`PENDING`) | `200`, `404`, `422` |
| `POST` | `/api/v1/permissions/{proposal_id}/approve` | Trusted controller approves proposal and seals immutable `TaskPolicy` | `200`, `403`, `404`, `409`, `410` |
| `POST` | `/api/v1/permissions/{proposal_id}/reject` | Explicitly reject a pending proposal | `200`, `404`, `409` |
| `POST` | `/api/v1/tasks/{task_id}/execute` | Execute task under approved policy with at-most-once consumption | `200`, `403`, `404`, `409`, `410`, `503` |
| `POST` | `/api/v1/agent/run` | Legacy unapproved benchmark execution mode (isolated with audit headers) | `200`, `404`, `422`, `503` |
| `GET` | `/api/v1/health` | Service diagnostics, database ping, uptime | `200`, `503` |
| `GET` | `/api/v1/users` | List demo academic users | `200` |
| `GET` | `/api/v1/users/{user_id}/emails` | List owner emails with limit, offset, and is_read filters | `200`, `404`, `422` |

---

## 🧪 Running Tests & Quality Verification

All 591 tests run against in-memory SQLite instances with zero side-effects on local developer databases:

```bash
# Execute the full 591-test suite with statement and branch coverage
pytest --cov=app --cov-branch --cov-report=term-missing

# Run code style and lint checks with Ruff
ruff check .

# Check code formatting with Ruff
ruff format --check .
```

---

## ⚠️ Known Limitations & Research Boundaries

1. **Simulation Demonstration Trust Boundary:** The approval mechanism (`X-AEGIS-Controller: local-supervisor`) is designed for local research and automated benchmark verification. In production environments, this endpoint must be anchored to cryptographically signed tokens, mutual TLS (mTLS), hardware security keys (FIDO2), or an interactive administrative console.
2. **Deterministic Fake LLM vs Live Stochastic Models:** The default test provider (`FakeLLMProvider`) generates deterministic rule-based outputs. In live deployments with LLMs (e.g., GPT-4o), model outputs are stochastic, but the deterministic execution firewall (`PolicyEngine`) inspects and validates the raw tool arguments before execution.
3. **Read-Only Scope:** The agent cannot send, update, forward, or delete emails. The tool registry and proposal mappings strictly enforce read-only operations.
4. **Task-Scoped Ephemeral Storage:** The current `ProposalStore` operates in-memory with thread-safe locking. Distributed deployments will require persistent transaction-locked datastores.

---

## 🗺️ 10-Week Research Roadmap

- **Week 1 (Completed):** Project foundation, modular architecture, SQLite models, mock academic email environment, REST API, QA automation.
- **Week 2 (Completed):** Mini AI Agent runtime, read-only tool adapters, LLM provider abstraction, ReAct orchestrator, sanitized tracing, and `POST /api/v1/agent/run` API.
- **Week 3 (Completed):** Task-Scoped Deterministic Security Policy Engine & Centralized Execution Gate (`ToolExecutor`). Default-deny evaluation, argument constraints, anti-escalation, zero-call guarantee.
- **Week 4 (Completed):** Intent-to-Policy & Permission Approval. Deterministic intent parsing (EN/AR), least-privilege permission proposals, trusted approval gate, at-most-once secured execution.
- **Week 5 (Next):** Data Provenance Tracking & Trust-Tier Isolation (tracking data origins, taint propagation, preventing untrusted content from widening authorization).
- **Week 6:** Immutable cryptographic audit log & hash-chained execution trails.
- **Week 7:** Anomaly detection and behavioral rate-limiting.
- **Week 8:** Agent sandbox execution integration (MCP, local runners).
- **Week 9:** End-to-end red-teaming and prompt-injection resistance testing.
- **Week 10:** Production hardening, research release, and documentation.

See [docs/week5-handoff.md](docs/week5-handoff.md) for the detailed engineering handoff guide for Week 5.
