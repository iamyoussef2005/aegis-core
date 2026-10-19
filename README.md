# AEGIS-CORE

**AEGIS-CORE** is a research-oriented security firewall for autonomous AI agents. It provides a mediation and control plane designed to intercept AI agent tool invocations, enforce user-approved task permissions, track data provenance, and prevent unauthorized actions.

This repository reflects the completed **Week 1: Project Foundation** milestone of our 10-week development roadmap.

---

## 🎯 Problem Statement

As autonomous AI agents are granted access to execute system tools—such as inspecting private mailboxes, dispatching web requests, querying corporate databases, and modifying file systems—they face critical security vulnerabilities:
1. **Indirect Prompt Injection:** Adversarial instructions embedded in untrusted external data (e.g., incoming emails or web pages) can hijack agent reasoning and force malicious tool calls.
2. **Data Exfiltration:** Malicious payloads can trick an agent into transmitting sensitive user credentials or private records to untrusted endpoints.
3. **Privilege Escalation:** Unchecked agent autonomous loops can exceed intended operational boundaries and perform destructive actions without human authorization.

**AEGIS-CORE** addresses these threats by providing an intent-aware execution firewall that inspects tool calls, enforces deterministic policy rules, tracks request provenance, and mandates human-in-the-loop approval before sensitive actions execute.

---

## 📦 Week 1 Foundation Scope

Week 1 establishes the architectural foundation and local simulation environment:
- **Application Core:** Modular FastAPI backend with application factory, configuration parsing, and structured logging.
- **Relational Persistence:** SQLite engine with SQLAlchemy 2.x ORM models, session lifecycle management, and strict foreign-key enforcement.
- **Simulated Domain:** Realistic mock academic email environment featuring 3 synthetic users, 30 bilingual (English & Arabic) messages, and 6 labeled benign adversarial prompt injection benchmarks.
- **REST API Interface:** Endpoints for simulated users and emails with deterministic pagination, read-status filtering, and cross-tenant ownership isolation.
- **Quality Assurance:** 61 automated tests running against in-memory SQLite with 94.95% statement and branch coverage.

---

## 🛠️ Tech Stack & Technologies Used

- **Language:** Python 3.12+ (tested on Python 3.14)
- **API Framework:** FastAPI 0.115+
- **ASGI Server:** Uvicorn
- **ORM & Database:** SQLAlchemy 2.0+ with SQLite
- **Validation & Settings:** Pydantic v2 & Pydantic-Settings
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
│   ├── api/                      # Presentation layer
│   │   ├── __init__.py
│   │   └── v1/
│   │       ├── __init__.py       # v1 API router aggregation
│   │       └── routes/
│   │           ├── __init__.py
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
│   │   ├── health.py             # HealthResponse & DatabaseHealth schemas
│   │   ├── user.py               # UserBase, UserCreate, UserResponse schemas
│   │   └── email.py              # EmailMessageResponse, EmailListResponse, EmailCountResponse
│   ├── repositories/             # Data access repository layer (Repository Pattern)
│   │   ├── __init__.py
│   │   ├── base.py               # Generic BaseRepository CRUD implementation
│   │   ├── user.py               # UserRepository with bound parameter queries
│   │   └── email.py              # EmailRepository with owner-scoped queries and ordering
│   └── services/                 # Domain business logic layer
│       ├── __init__.py
│       ├── health.py             # System uptime and health inspection service
│       ├── user.py               # User domain service
│       └── email.py              # Email domain service with tenant isolation
├── docs/                         # Architecture, API, testing, and handoff documentation
│   ├── architecture.md           # System architecture, module boundaries, diagrams
│   ├── api.md                    # REST API reference, schemas, curl examples
│   ├── testing.md                # QA testing guide, categories, isolation guarantees
│   ├── week1-report.md           # Independent audit and acceptance report
│   └── week2-handoff.md          # Week 2 engineering handoff guide
├── tests/                        # Automated test suite (61 tests, in-memory SQLite)
│   ├── __init__.py
│   ├── conftest.py               # Pytest fixtures (in-memory SQLite, HTTP clients)
│   ├── test_startup.py           # Application factory, routing, and OpenAPI tests
│   ├── test_database.py          # Database connectivity, sessions, and CRUD tests
│   ├── test_mock_email_env.py    # Foreign keys, cascades, and seed reproducibility tests
│   ├── test_api_users_emails.py  # User & email API integration tests
│   ├── test_security_boundaries.py # Tenant isolation, SQLi, and traceback masking tests
│   ├── test_edge_cases.py        # Empty inbox, boundary limits, and malformed parameter tests
│   ├── test_config.py            # Environment configuration validation tests
│   └── test_logging.py           # Structured logging and secret redaction tests
├── scripts/
│   ├── __init__.py
│   ├── run_dev.py                # Development server runner
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
Default settings configure a local SQLite database (`./aegis.db`) bound strictly to `127.0.0.1`.

---

## 🗄️ Database Initialization & Demo Data Seeding

### 1. Database Initialization
Tables are automatically created on application startup via the lifespan event handler (`init_db()`).

### 2. Seed Deterministic Mock Data
Populate the database with 3 demo academic users and 30 realistic academic emails:
```bash
python -m scripts.seed_mock_data
```

**Seeding Guarantees:**
- **Exact Counts:** 3 demo users and 30 emails (10 per user).
- **Idempotent:** Safe to run repeatedly without creating duplicate records or modifying existing entries.
- **Multilingual Support:** Fully validates UTF-8 Arabic and English text.
- **Adversarial Safety Probes:** Includes 6 labeled benign test prompts (`[SECURITY RESEARCH BENCHMARK - BENIGN TEST]`) for evaluating upcoming firewall interception and prompt-injection filters without external exfiltration.

---

## 💻 Starting the API

### Direct Launch with Uvicorn
```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### Launch via Development Runner Script
```bash
python -m scripts.run_dev
```

### API Documentation Locations
Once the application is running:
- **Interactive Swagger UI:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc Documentation:** [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)
- **OpenAPI 3.x JSON Specification:** [http://127.0.0.1:8000/openapi.json](http://127.0.0.1:8000/openapi.json)

---

## 🩺 REST API Endpoint Summary

| Method | Endpoint | Description | Status Codes |
|---|---|---|---|
| `GET` | `/api/v1/health` | Service diagnostics, database ping, uptime | `200`, `503` |
| `GET` | `/api/v1/users` | List demo academic users | `200` |
| `GET` | `/api/v1/users/{user_id}/emails` | List owner emails with limit, offset, and is_read filters | `200`, `404`, `422` |
| `GET` | `/api/v1/users/{user_id}/emails/count` | Total email count with optional is_read filter | `200`, `404`, `422` |
| `GET` | `/api/v1/users/{user_id}/emails/recent` | Latest emails ordered by received_at desc (1-10 messages) | `200`, `404`, `422` |
| `GET` | `/api/v1/users/{user_id}/emails/{email_id}` | Fetch single email with strict ownership isolation | `200`, `404` |

See [docs/api.md](docs/api.md) for full parameter specifications and curl request/response examples.

---

## 🧪 Running Tests & Quality Verification

All tests run against in-memory SQLite instances with zero side-effects on local developer databases.

```bash
# Execute the full 61-test QA suite with coverage measurement
pytest -v

# Run code style and lint checks with Ruff
ruff check .

# Check code formatting with Ruff
ruff format --check .
```

See [docs/testing.md](docs/testing.md) for testing methodology and isolation guarantees.

---

## ⚠️ Known Limitations (Week 1 Scope)

1. **Simulation Identity Model:** The `user_id` route parameter serves as an experimental tenant/inbox selector in a local simulator, **not** an authenticated session. Multi-user authentication and cryptographic agent session tokens are scheduled for Week 2.
2. **Read-Only Email Operations:** Week 1 implements retrieval and inspection endpoints. Modifying or sending emails is intentionally omitted until the tool-interception proxy is added in Week 3.
3. **Local In-Process Database:** Built on SQLite for reproducible research and local benchmarking. Production distributed storage will be addressed in Week 8.
4. **No External Network Dependencies:** No live SMTP, IMAP, or third-party email providers are queried. All data is synthetic.

---

## 🗺️ Next Development Stage (10-Week Roadmap)

- **Week 1 (Completed):** Project foundation, modular architecture, SQLite models, mock academic email environment, REST API, QA automation.
- **Week 2 (Next):** Agent session models, authentication tokens, permission manifests, and agent tool definitions (`read_inbox`, `search_emails`, `get_email_details`).
- **Week 3:** Tool-call interception proxy and schema validation layer.
- **Week 4:** Deterministic policy evaluation engine (Allow / Deny / Prompt-User).
- **Week 5:** Interactive human-in-the-loop approval mechanism.
- **Week 6:** Immutable data provenance tracking and cryptographic audit log.
- **Week 7:** Anomaly detection and behavioral rate-limiting.
- **Week 8:** Agent sandbox execution integration (MCP, local runners).
- **Week 9:** End-to-end red-teaming and prompt-injection resistance testing.
- **Week 10:** Production hardening, research release, and documentation.

See [docs/week2-handoff.md](docs/week2-handoff.md) for the detailed engineering handoff guide for Week 2.
