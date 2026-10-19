# AEGIS-CORE QA & Test Automation Guide

**Version:** 0.1.0  
**Test Framework:** Pytest, pytest-cov, pytest-asyncio, HTTPX, FastAPI TestClient  
**Target Coverage Threshold:** 85% minimum branch and statement coverage (Actual: >94%)

---

## 🧪 Quick Commands

### 1. Run the Entire Test Suite
By default, running `pytest` automatically measures branch/statement coverage and outputs missing line numbers:
```bash
# Windows PowerShell
.\.venv\Scripts\pytest.exe

# Linux / macOS
pytest
```

### 2. Run a Specific Test File
```bash
# Run API endpoint integration tests
pytest tests/test_api_users_emails.py

# Run security boundary tests
pytest tests/test_security_boundaries.py

# Run database relational integrity tests
pytest tests/test_database.py
```

### 3. Run a Single Test Case
Target a specific function or class:
```bash
pytest tests/test_security_boundaries.py::test_cross_user_email_isolation_returns_404 -v
```

### 4. Generate Interactive HTML Coverage Reports
```bash
pytest --cov=app --cov-report=html
```
Open `htmlcov/index.html` in any web browser to inspect line-by-line execution coverage.

---

## 🏛️ Test Architecture & Category Inventory

The test suite contains **61 automated tests** organized across 8 modular test suites:

### Category 1: Application Startup & Routing (`tests/test_startup.py`)
- Verifies application factory (`create_app`) instantiates without side-effects.
- Verifies all REST routes (`/api/v1/health`, `/api/v1/users`, `/api/v1/users/{id}/emails/...`) register cleanly.
- Verifies OpenAPI 3.x schema generation works and contains all paths and schemas.
- Verifies health endpoint returns `200 OK` when healthy and `503 Service Unavailable` when degraded.

### Category 2: Database Integrity & Sessions (`tests/test_database.py` & `tests/test_mock_email_env.py`)
- Verifies table metadata initialization (`Base.metadata.create_all`).
- Enforces SQLite `PRAGMA foreign_keys = ON` on all connections.
- Validates relational bidirectional mappings (`User.emails` <-> `EmailMessage.owner`).
- Tests `ondelete="CASCADE"` behavior (deleting a user cascades and deletes all owned emails).
- Enforces unique email constraint on `User.email` (raises `IntegrityError`).
- Tests transactional rollback and session disposal via `get_db()` generator.
- Tests database ping health check (`check_db_health`).

### Category 3: Deterministic Mock Data (`tests/test_mock_email_env.py`)
- Verifies exact seed row counts (3 users, 30 emails, 10 per user).
- Tests idempotency: subsequent seed executions skip existing records without error or duplication.
- Confirms preservation of bilingual Arabic UTF-8 text.
- Validates reproducible timestamp ordering from fixed reference dates.

### Category 4: API Endpoint Functionality (`tests/test_api_users_emails.py`)
- `GET /api/v1/users`: Validates demo user list without credential leakage.
- `GET /api/v1/users/{user_id}/emails`: Verifies limit, offset, and is_read filtering.
- `GET /api/v1/users/{user_id}/emails/count`: Validates exact counts and read/unread filters.
- `GET /api/v1/users/{user_id}/emails/recent`: Tests bounded recent message retrieval.
- `GET /api/v1/users/{user_id}/emails/{email_id}`: Tests single email retrieval.
- Verifies Pydantic v2 response model validation across all endpoints.

### Category 5: Security Boundaries & Defensive Invariants (`tests/test_security_boundaries.py`)
- **Tenant Isolation:** Cross-user email retrieval (`/users/1/emails/11`) returns `404 Not Found` rather than `403 Forbidden`, preventing attacker enumeration of valid email IDs across tenant boundaries.
- **SQL Injection Resistance:** Confirms SQL injection strings (`' OR '1'='1`, `'; DROP TABLE ...`) in query parameters are bound safely by the ORM.
- **Traceback Masking:** Confirms unhandled exceptions trigger the global 500 handler, masking internal stack traces from API responses while attaching a tracking `correlation_id`.
- **CORS Restrictions:** Verifies wildcard `*` is forbidden in CORS configuration.
- **Security Headers:** Validates `X-Correlation-ID`, `X-Response-Time-MS`, `X-Content-Type-Options: nosniff`, and `X-Frame-Options: DENY`.

### Category 6: Edge Cases & Input Validation (`tests/test_edge_cases.py`)
- **Empty Inbox:** Verifies user with 0 emails returns `items=[]`, `total=0`, `count=0`, and `recent=[]`.
- **Invalid IDs:** Non-integer path parameters return `422 Unprocessable Entity`; negative IDs return `404`.
- **Boundary Limits:** Validates `limit=1`, `limit=100`, `count=1`, `count=10`.
- **Malformed Parameters:** `limit=0`, `limit=101`, `offset=-1`, `is_read=notabool` return `422`.
- **Rich Unicode & Emojis:** Confirms Arabic text with diacritics, symbols, and emojis store and retrieve accurately.
- **Sequential Invariance:** Verifies rapid sequential calls cause no connection leaks or state mutation.

---

## 🔒 Why Isolated Databases Matter

1. **Zero Pollution of Developer State:** Tests run against in-memory SQLite instances (`sqlite:///:memory:`) using SQLAlchemy `StaticPool`. Local databases (`./aegis.db`) are never touched or modified during test execution.
2. **Determinism and Parallel Safety:** Every test receives a clean transaction or dedicated in-memory schema. No test depends on the side-effects of another test.
3. **Foreign-Key Parity:** SQLite disables foreign-key constraints by default. By attaching a connect listener executing `PRAGMA foreign_keys = ON;`, the test database strictly mimics production relational database constraints.
4. **Fast Execution:** 61 tests execute in ~2.5 seconds directly in-memory with zero disk I/O bottlenecks.

---

## ⚠️ Current Testing Limitations (Week 1 Scope)

- **Fictional Data Only:** The email system is an academic simulation; no live SMTP/IMAP connections or external Google/Microsoft APIs are used.
- **Simulation Selector vs. Real Auth:** `user_id` is an experimental tenant selector for AI agent evaluation. Full cryptographic token authentication and agent authorization manifests will be implemented in Week 2.
- **No Agent Interception Engine:** Autonomous agent tool-call interception proxies and deterministic firewall policy engines are scheduled for Weeks 3 and 4.
- **In-Memory SQLite:** Testing is currently optimized for SQLite. Production clustering and multi-node PostgreSQL tests will be introduced during infrastructure scaling in Week 8.
