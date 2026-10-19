# AEGIS-CORE

**AEGIS-CORE** is a research-oriented security firewall for autonomous AI agents. It provides a mediation and control plane designed to intercept AI agent tool invocations, enforce user-approved task permissions, track data provenance, and prevent unauthorized actions.

This repository reflects the completed **Week 1: Project Foundation** milestone of our 10-week roadmap.

---

## 🏛️ Week 1 Architecture & Modular Design

```
aegis-core/
├── app/
│   ├── __init__.py               # Package metadata and version definition
│   ├── main.py                   # Application factory, lifespan, CORS, and provenance middleware
│   ├── api/                      # Routing layer
│   │   ├── __init__.py
│   │   └── v1/
│   │       ├── __init__.py       # v1 API router aggregation
│   │       └── routes/
│   │           ├── __init__.py
│   │           └── health.py     # GET /api/v1/health diagnostic endpoint
│   ├── core/                     # Infrastructure foundations
│   │   ├── __init__.py
│   │   ├── config.py             # Type-safe environment settings (Pydantic v2 Settings)
│   │   └── logging.py            # Structured JSON/Console logging with sensitive data redaction
│   ├── db/                       # Persistence foundations
│   │   ├── __init__.py
│   │   ├── base.py               # SQLAlchemy 2.x DeclarativeBase and TimestampMixin
│   │   └── session.py            # Engine lifecycle, sessionmaker, and get_db dependency
│   ├── models/                   # SQLAlchemy ORM models (ready for Week 2+)
│   │   └── __init__.py
│   ├── schemas/                  # Pydantic v2 schemas
│   │   ├── __init__.py
│   │   └── health.py             # HealthResponse & DatabaseHealth schemas
│   ├── repositories/             # Data access repository layer (Repository Pattern)
│   │   ├── __init__.py
│   │   └── base.py               # BaseRepository generic CRUD implementation
│   └── services/                 # Domain business logic layer
│       ├── __init__.py
│       └── health.py             # System uptime and health inspection service
├── tests/                        # Automated test suite
│   ├── __init__.py
│   ├── conftest.py               # Pytest fixtures (in-memory SQLite, HTTP clients)
│   ├── test_config.py            # Configuration validation tests
│   ├── test_database.py          # Session lifecycle & repository CRUD tests
│   ├── test_health.py            # GET /api/v1/health & security headers tests
│   └── test_logging.py           # Structured logging & secret redaction tests
├── scripts/
│   ├── __init__.py
│   └── run_dev.py                # Development server runner
├── .env.example                  # Environment configuration template
├── .gitignore                    # Git exclusions
├── pyproject.toml                # Project packaging, dependency constraints, Ruff, & pytest config
└── README.md                     # Project documentation
```

---

## 🛠️ Tech Stack

- **Language:** Python 3.12+ (tested on Python 3.14)
- **Framework:** FastAPI
- **Database Engine:** SQLite / SQLAlchemy 2.x
- **Data Validation & Settings:** Pydantic v2 & Pydantic-Settings
- **Testing:** Pytest, pytest-asyncio, HTTPX
- **Code Quality:** Ruff (linting & formatting)
- **Version Control:** Git

---

## 🚀 Getting Started

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
Install production and development dependencies:
```bash
pip install -e ".[dev]"
```
*(Or install directly via `pip install fastapi "uvicorn[standard]" pydantic pydantic-settings "sqlalchemy>=2.0" python-dotenv pytest pytest-asyncio httpx ruff`)*

### 4. Configure Environment Variables
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Default configuration values work immediately for local development using an SQLite database (`./aegis.db`).

---

## 💻 Running the Application

### Using Uvicorn Directly
```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### Using the Development Script
```bash
python -m scripts.run_dev
```

### API Documentation
- **Interactive Swagger UI:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc Documentation:** [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)
- **OpenAPI JSON Spec:** [http://127.0.0.1:8000/openapi.json](http://127.0.0.1:8000/openapi.json)

---

## 🩺 Health Check Endpoint

### Request
```http
GET /api/v1/health HTTP/1.1
Host: 127.0.0.1:8000
```

### Structured Response (200 OK)
```json
{
  "status": "healthy",
  "project": "AEGIS-CORE",
  "version": "0.1.0",
  "environment": "development",
  "timestamp": "2026-10-19T22:30:00Z",
  "uptime_seconds": 12.34,
  "database": {
    "status": "healthy",
    "dialect": "sqlite"
  },
  "components": {
    "firewall_engine": "standby",
    "provenance_tracker": "standby",
    "policy_enforcer": "standby"
  }
}
```

### Security & Provenance Response Headers
Every response includes:
- `X-Correlation-ID`: Unique tracking UUID for request provenance and distributed tracing.
- `X-Response-Time-MS`: Request processing latency in milliseconds.
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`

---

## 🧪 Testing and Quality Assurance

### Run the Test Suite
```bash
pytest -v
```

### Run Code Linting & Formatting
```bash
# Check code style with Ruff
ruff check .

# Format code with Ruff
ruff format --check .
```

---

## 🗄️ Database Architecture & Mock Email Environment

AEGIS-CORE provides a realistic, deterministic, SQLite-backed mock academic email environment designed to evaluate AI agent security, tool-call permissions, and data exfiltration defenses.

### Entity-Relationship Model
- **`users`**:
  - `id` (INTEGER, PK, Auto-increment)
  - `display_name` (VARCHAR(150), NOT NULL)
  - `email` (VARCHAR(255), UNIQUE, INDEXED, NOT NULL)
  - `created_at` (DATETIME with UTC timezone, NOT NULL)
  - *Relationship:* 1-to-many with `email_messages` (cascade on delete)
- **`email_messages`**:
  - `id` (INTEGER, PK, Auto-increment)
  - `owner_id` (INTEGER, FK -> `users.id` ON DELETE CASCADE, INDEXED, NOT NULL)
  - `sender` (VARCHAR(255), NOT NULL)
  - `recipient` (VARCHAR(255), NOT NULL)
  - `subject` (VARCHAR(500), NOT NULL)
  - `body` (TEXT, NOT NULL)
  - `is_read` (BOOLEAN, DEFAULT FALSE, NOT NULL)
  - `received_at` (DATETIME with UTC timezone, INDEXED, NOT NULL)
  - `created_at` (DATETIME with UTC timezone, NOT NULL)
  - *Indexes:* `ix_email_messages_owner_received` (`owner_id`, `received_at`), `ix_email_messages_owner_is_read` (`owner_id`, `is_read`)

### SQLite Foreign Key Enforcement
Foreign-key enforcement is enabled across all connections via a SQLAlchemy `Engine` connect event listener executing:
```sql
PRAGMA foreign_keys = ON;
```

### Deterministic Seeding
The database seeding script generates exactly 3 demo academic users and 30 realistic academic emails (10 per user), with bilingual English and Arabic UTF-8 text and labeled benign adversarial prompt injection benchmarks:
```bash
python -m scripts.seed_mock_data
```
- **Idempotent:** Safe to run multiple times without duplicating or corrupting data.
- **Academic Scenarios:** Announcements, assignment deadlines, course registration, internships, exam schedules, student clubs, and research project discussions.
- **Safety Benchmarks:** Contains labeled benign test probes (`[SECURITY RESEARCH BENCHMARK - BENIGN TEST]`) for evaluating upcoming firewall interception and prompt-injection filters without external exfiltration.

---

## 🗺️ 10-Week Development Roadmap

- **Week 1 (Current):** Initial project foundation, modular architecture, environment config, structured logging, database engine lifecycle, and health endpoints.
- **Week 2:** Agent session models, authentication tokens, and permission manifests.
- **Week 3:** Tool-call interception proxy and schema validation layer.
- **Week 4:** Deterministic policy evaluation engine (Allow / Deny / Prompt-User).
- **Week 5:** Interactive human-in-the-loop approval mechanism.
- **Week 6:** Immutable data provenance tracking and cryptographic audit log.
- **Week 7:** Anomaly detection and behavioral rate-limiting.
- **Week 8:** Agent sandbox execution integration (MCP, local runners).
- **Week 9:** End-to-end red-teaming and prompt-injection resistance testing.
- **Week 10:** Production hardening, documentation, and research release.
