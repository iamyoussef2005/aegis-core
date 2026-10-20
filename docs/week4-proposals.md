# AEGIS-CORE Week 4 Architecture & Design: Deterministic Permission Proposal Engine

**Document Version:** 1.0.0  
**Milestone:** Week 4 of 10 (Phase 2: Deterministic Permission Proposal System)  
**Role:** Lead Authorization Engineer  
**Date:** October 20, 2026  
**Status:** Implemented, Tested, and Verified  
**Test Suite Health:** 536 / 536 Passed (100%) | Combined Statement & Branch Coverage: 95.12% | Regressions: 0  

---

## 1. Executive Summary

In Week 4 Phase 1, AEGIS-CORE implemented a deterministic parser (`app/intent/parser.py`) converting English and Arabic user requests into structured `TaskIntent` instances. 

**Week 4 Phase 2** implements the **Deterministic Permission Proposal Engine** (`app/intent/proposals.py` and `app/intent/mappings.py`). This component maps resolved `TaskIntent` models to minimal, tightly scoped `PermissionProposal` objects.

```
[User Natural Language Prompt]
              │
              ▼
   [Deterministic Parser] (Phase 1)
              │
              ▼ (Validated TaskIntent)
[Permission Proposal Engine] (Phase 2 - Current)
              │
              ▼ (Immutable PermissionProposal: status=PENDING)
     [TRUST BOUNDARY]
              │  (A proposal is NOT a policy; cannot authorize execution)
              ▼
 [Trusted Approval Gate / HITL] (Phase 3 - Upcoming)
              │
              ▼ (Approved & Sealed TaskPolicy)
   [ToolExecutor Firewall] (Week 3 Gate)
```

---

## 2. Critical Trust Rule & Security Invariants

### 2.1 The Critical Trust Rule

> [!CAUTION]
> **A proposal is NOT an approved policy.**
> A `PermissionProposal` must **NEVER** directly authorize execution. It encapsulates an unapproved draft permission perimeter. Neither `ToolExecutor` nor `PolicyEngine` will accept or evaluate a proposal as an active policy. The proposal remains strictly in `status = ProposalStatus.PENDING` until a trusted authority explicitly reviews, approves, and seals it into an immutable `TaskPolicy`.

### 2.2 Core Security Invariants

1. **Strict Tool Allowlisting:** Each simple intent maps to exactly **one** allowlisted system tool (`read_inbox`, `search_emails`, `get_email_details`). No multi-tool bundling, no wildcards, no arbitrary tool names.
2. **Exact Least-Privilege Parameter Constraints:**
   - Reading inbox: Limit capped strictly to requested count $N$ ($1 \le N \le 20$), offset locked to $0$.
   - Searching emails: Limit capped to $5$, offset locked to $0$, query locked to an exact allowlist (`allowed_search_terms = frozenset({query})`). `forbidden_substrings` is never used as a substitute for exact query scoping.
   - Inspecting details: Email ID locked to a single explicit allowed ID (`allowed_email_ids = frozenset({id})`).
3. **Decoupling of Presentation Language:** Output language preferences (`response_language = "ar"` or `"en"`) dictate response formatting only and confer **zero additional tool permissions**.
4. **Fail-Closed on Ambiguity:** Ambiguous, compound, or unresolvable intents (`is_ambiguous=True` or `requires_clarification=True`) produce **zero proposals** and raise `ProposalSecurityError`.
5. **CSPRNG Unforgeable Proposal IDs:** Every proposal receives a cryptographically unpredictable identifier (`prop_<32 hex chars>`) generated via `secrets.token_hex(16)`.
6. **Proposal Immutability:** `PermissionProposal` models are frozen Pydantic v2 schemas (`frozen=True, extra="forbid"`). State cannot be tampered with post-creation.
7. **Zero Side Effects:** Proposal generation performs pure in-memory contract derivation. Tool adapters, database sessions, and network calls are invoked **zero times**.

---

## 3. Architecture & Data Contracts

### 3.1 `PermissionProposal` (`app/intent/proposals.py`)

```python
class ProposalStatus(StrEnum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class PermissionProposal(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    proposal_id: str  # Cryptographic unforgeable ID (prop_<hex>)
    task_id: str  # Server-controlled correlation task ID
    user_id: int  # Server-verified simulated user ID
    normalized_intent: TaskIntent  # Validated, unambiguous source intent
    requested_tool: str  # Exact single allowlisted tool name
    requested_constraints: dict[str, BaseToolConstraint]  # Bounded argument constraints
    human_readable_summary: str  # Clear summary for human auditor
    rationale: str  # Security justification under least privilege
    expires_at: datetime | None  # Expiration timestamp
    created_at: datetime  # UTC creation timestamp
    status: ProposalStatus = PENDING  # Lifecycle status (strictly PENDING on creation)
    proposal_version: str = "1.0.0"  # Proposal schema version
```

### 3.2 Proposal Lifecycle Integrity Invariants

- **Tool Whitelist Enforcement:** `requested_tool` is validated against `ALLOWED_TOOL_NAMES` and `KNOWN_SYSTEM_TOOLS`.
- **Single-Tool Invariant:** `len(requested_constraints) == 1` and `requested_tool in requested_constraints`.
- **Temporal Validity:** If `expires_at` is set, it must be strictly after `created_at`.
- **Ambiguity Guard:** `normalized_intent.is_ambiguous` or `requires_clarification` immediately raises `ValueError`.

---

## 4. Deterministic Intent-to-Permission Mapping Table

| User Prompt (English / Arabic) | Validated `TaskIntent` | Requested Tool | Proposed Argument Constraints | Security Rationale |
|---|---|:---:|---|---|
| `"Read my latest 3 emails."` / `"اقرأ آخر 3 إيميلات."` | `READ_LATEST_EMAILS`<br/>`count=3` | `read_inbox` | `ReadInboxConstraint`<br/>• `max_limit = 3`<br/>• `max_offset = 0`<br/>• `allowed_is_read = None` | Bounded strictly to $N=3$ and offset $0$. Prevents pagination traversal. |
| `"Summarize my latest 2 emails in Arabic."` / `"لخص آخر 2 إيميل بالعربي."` | `SUMMARIZE_RECENT_EMAILS`<br/>`count=2`<br/>`response_language="ar"` | `read_inbox` | `ReadInboxConstraint`<br/>• `max_limit = 2`<br/>• `max_offset = 0` | Reading inbox is required for summarization. Response language confers zero extra tool rights. |
| `"Search emails for assignment."` / `"ابحث عن إيميلات فيها كلمة واجب."` | `SEARCH_EMAILS`<br/>`search_query="assignment"` | `search_emails` | `SearchEmailsConstraint`<br/>• `max_limit = 5`<br/>• `max_offset = 0`<br/>• `allowed_search_terms = {"assignment"}` | Scoped to exact query allowlist. Any other query or limit expansion is denied. |
| `"Show email 7."` / `"اعرض الإيميل رقم 7."` | `READ_EMAIL_DETAILS`<br/>`email_id=7` | `get_email_details` | `GetEmailDetailsConstraint`<br/>• `allowed_email_ids = {7}`<br/>• `max_email_id = 7` | Strictly allows inspecting body of email ID 7 only. Prohibits reading other messages. |
| `"Read emails."` / `"شوف الرسائل"` | `AMBIGUOUS`<br/>`requires_clarification=True` | *None* | *None* (Fails Closed) | Ambiguous requests raise `ProposalSecurityError`. Zero permissions proposed. |

---

## 5. Constraint Enforcement Demonstration

When a proposal is eventually approved into a `TaskPolicy` (Phase 3), Week 3's `PolicyEngine` enforces these constraints deterministically:

### 5.1 `read_inbox` Constraint Enforcement
```python
# Proposed: ReadInboxConstraint(max_limit=3, max_offset=0)
constraint.validate_arguments({"limit": 3, "offset": 0})  # ALLOW
constraint.validate_arguments({"limit": 4, "offset": 0})  # DENY: exceeds limit (3)
constraint.validate_arguments({"limit": 3, "offset": 1})  # DENY: exceeds offset (0)
```

### 5.2 `search_emails` Exact Term Enforcement
```python
# Proposed: SearchEmailsConstraint(max_limit=5, max_offset=0, allowed_search_terms={"assignment"})
constraint.validate_arguments({"query": "assignment", "limit": 5, "offset": 0})  # ALLOW
constraint.validate_arguments(
    {"query": "Assignment", "limit": 5, "offset": 0}
)  # ALLOW (case-normalized)
constraint.validate_arguments(
    {"query": "passwords", "limit": 5, "offset": 0}
)  # DENY: not in allowlist
constraint.validate_arguments(
    {"query": "assignment", "limit": 6, "offset": 0}
)  # DENY: exceeds limit (5)
```

### 5.3 `get_email_details` Single ID Enforcement
```python
# Proposed: GetEmailDetailsConstraint(allowed_email_ids={7}, max_email_id=7)
constraint.validate_arguments({"email_id": 7})  # ALLOW
constraint.validate_arguments(
    {"email_id": 8}
)  # DENY: not in allowed_email_ids whitelist
constraint.validate_arguments(
    {"email_id": 1}
)  # DENY: not in allowed_email_ids whitelist
```

---

## 6. Empirical Verification & Test Results

The full test suite was executed across all existing and new components:

| Test Module | Test Count | Status | Notes |
|---|:---:|:---:|---|
| Baseline Foundation (Weeks 1-3) | 404 | **PASS** | Existing tests fully green, 0 regressions |
| Intent Parsing Suite (`tests/test_intent_parser.py`) | 112 | **PASS** | Natural language regexes & Unicode normalization |
| Permission Proposals Suite (`tests/test_permission_proposals.py`) | 20 | **PASS** | Mappings, constraints, immutability, zero-execution |
| **Total Automated Tests** | **536** | **100% PASS** | **Combined Coverage: 95.12%** |

### Static Analysis & Linter Verification
- `ruff check .`: **Passed (0 errors)**
- `ruff format --check .`: **Passed (104 files inspected, 0 formatting issues)**

---

## 7. Current Limitations & Next Step (Prompt 3)

1. **No Automatic Approval:** Proposals exist exclusively in `status = ProposalStatus.PENDING`. No approval or task execution occurs in Prompt 2.
2. **Single-Tool Bounds:** Proposals currently support single-tool requests corresponding to single simple intents. Compound multi-tool requests require clarification or separate requests.
3. **Readiness for Prompt 3:** The permission proposal engine is fully tested and ready for **Prompt 3: Trusted Approval Gate & Policy Activation**, which will introduce the human-in-the-loop/supervisor approval mechanism and seal approved proposals into active `TaskPolicy` instances within `TaskContext`.
