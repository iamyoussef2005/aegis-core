# AEGIS-CORE

**A local research prototype for controlling the tools an AI agent can use.**

An agent may encounter instructions hidden in data it retrieves, such as an email asking it to read more messages or use an unrelated tool. AEGIS-CORE explores a deterministic authorization layer that checks proposed tool calls against permissions derived from the user's task.

The current prototype uses a **simulated email inbox** with fictional users and messages. It supports reading recent messages, searching for a keyword, and viewing a specific message. It does not connect to a real mailbox or provide production-ready authentication.

> **Research boundary:** Approval is simulated with a caller-supplied controller identifier. That identifier is not authenticated and can be impersonated. Keep this application local and use synthetic data.

## How it works

```text
User request
    -> Deterministic intent parser (English / Arabic)
    -> Bounded permission proposal (PENDING)
    -> Simulated supervisor approval
    -> Task policy bound to the request and simulated user
    -> Agent proposes a tool call
    -> Policy engine allows or denies the call
    -> Tool result and execution trace
```

For example, **“Read my latest 3 emails”** produces a proposal for `read_inbox` with a maximum limit of 3 and an offset of 0. After simulated approval, the agent can request that tool; a request for 10 messages or for a different tool is denied by the policy engine.

Each proposal authorizes one tool and expires after five minutes by default. The approved task is consumed when execution starts, so it cannot be executed again in the same server process. Ambiguous or unsupported requests do not produce an approved policy.

### Main components

- **Intent and proposals:** `app/intent/` parses supported requests and creates single-tool permission proposals.
- **Approval and policy:** `app/intent/approval.py` manages proposal state; `app/security/` defines task policies and evaluates tool calls.
- **Agent runtime:** `app/agent/orchestrator.py` runs the bounded agent loop, and `app/agent/executor.py` checks calls through the policy engine before dispatch.
- **Simulation:** `app/models/`, `app/repositories/`, and `app/services/` provide a SQLite-backed inbox with three synthetic users and 30 messages.
- **API:** `app/api/v1/routes/` exposes proposal, approval, execution, and simulated inbox endpoints.

The stack is Python 3.12+, FastAPI, Pydantic, SQLAlchemy, and SQLite. The default provider is an offline, deterministic fake that returns demonstration responses rather than generating real summaries. An OpenAI provider is also available.

## Quick start

Clone the repository and create a virtual environment:

```bash
git clone https://github.com/iamyoussef2005/aegis-core.git
cd aegis-core
python -m venv .venv
```

Activate it:

```powershell
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
```

```bash
# macOS / Linux
source .venv/bin/activate
```

Install the project and development dependencies, seed the local demo database, and run the offline walkthrough:

```bash
python -m pip install -e ".[dev]"
python -m scripts.seed_mock_data
python scripts/week4_demo.py
```

The seed command creates the configured database tables and adds fictional data without overwriting existing records. With the default configuration, it uses `./aegis.db`. The demo uses the configured database and the fake provider; it does not require an API key.

## Try the API

After seeding, start the server on the local loopback interface:

```bash
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) for the interactive API. The following examples use `curl` in a POSIX shell; the interactive docs can also be used on Windows.

**1. Propose a permission.** Copy the returned `proposal_id` and `task_id` for the next steps.

```bash
curl -sS -X POST "http://127.0.0.1:8000/api/v1/permissions/propose" \
  -H "Content-Type: application/json" \
  -d '{"user_id":1,"message":"Read my latest 3 emails."}'
```

The response includes `status: "PENDING"`, `requested_tool: "read_inbox"`, and the proposed limit and offset. No tool runs at this stage.

**2. Approve the proposal.** Replace `<proposal_id>` with the returned value.

```bash
curl -sS -X POST "http://127.0.0.1:8000/api/v1/permissions/<proposal_id>/approve" \
  -H "X-AEGIS-Controller: local-supervisor"
```

This header is a demonstration identity, not authentication. Approval creates the policy used by the task.

**3. Execute the task.** Replace `<task_id>` with the value from step 1, using the same server process and acting before the proposal expires.

```bash
curl -sS -X POST "http://127.0.0.1:8000/api/v1/tasks/<task_id>/execute" \
  -H "Content-Type: application/json" \
  -d '{"provider":"fake"}'
```

The response contains the demonstration answer, tool steps, and policy decisions. Repeating the execution request for the same task returns a conflict because the proposal has already been consumed.

## Tests and experiments

After installing the development dependencies, seed the **configured** application database before running the tests:

```bash
python -m scripts.seed_mock_data
python -m pytest
```

Most tests use isolated SQLite fixtures, but a few also access the configured application database and expect seeded data. A local run with an isolated, seeded application database passed **591 tests**. The test count and results may change as the project evolves.

Two offline evaluation scripts are included:

```bash
# Classify a fixed set of 48 English and Arabic requests
python -m app.intent.evaluation

# Compare policy decisions on 50 synthetic operations
python scripts/run_security_benchmark.py
```

In a local run, the intent evaluation classified all 48 curated examples as expected. In the 50-operation comparison, the protected policy denied all 25 cases labeled unauthorized and allowed all 25 labeled legitimate. The comparison **infers adapter-invocation counts from decisions**; it does not execute adapters to measure those counts. Separate integration tests check dispatch behavior for selected cases. These small, fixed experiments do not establish real-world security or general language accuracy.

## Current limitations

- **No authenticated approval or user sessions.** The approval endpoint accepts an asserted controller name, and `user_id` is a simulated inbox selector. This does not establish a human approval or a real user's identity.
- **Other access paths exist.** The legacy `POST /api/v1/agent/run` endpoint uses demonstration policy profiles and bypasses the proposal approval workflow. The simulated inbox API also exposes data without that workflow, and the older `AgentRunner` dispatches directly through the registry.
- **Local, temporary approval state.** Proposals, receipts, and policies are stored in memory and lost when the process restarts. The lock protects threads in one process, not multiple server workers.
- **Limited intent coverage.** The parser uses rules for specific English and Arabic patterns. It supports Eastern Arabic digits, but does not generally parse written number words or arbitrary multi-step requests.
- **Untrusted content remains a risk.** Tool results are labeled as untrusted, but full provenance tracking and trust-tier isolation are planned for a later milestone. Prompt-injection tests use simulated model behavior.
- **Fake provider by default.** Its responses are predetermined demonstration text. To use the optional OpenAI provider, set `OPENAI_API_KEY` in the environment or a `.env` file and explicitly select `"provider": "openai"` in the API request. That mode sends the task and retrieved simulated content to the configured provider. See [`.env.example`](.env.example) for available settings.

## Project status

The repository contains the Week 1–4 prototype: the simulated email environment, agent runtime, policy engine, and intent-to-approval workflow. The next planned milestone is data provenance and trust-tier isolation; see [the Week 5 handoff](docs/week5-handoff.md). The milestone documents under `docs/` describe the project at different points in its development and may include earlier plans or historical results.
