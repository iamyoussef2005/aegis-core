"""Evaluation dataset and metrics runner for AEGIS-CORE Week 4 intent extraction.

==============================================================================
CRITICAL ASSURANCE:
------------------------------------------------------------------------------
This evaluation module executes against a curated hold-out dataset of 48
independent labeled examples across English, Arabic, unsupported operations,
and ambiguous queries. It measures intent accuracy, proposal correctness,
false denial rate, and parser latency.
==============================================================================
"""

import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from statistics import mean, median
from typing import Any

# Ensure project root is in sys.path when executed directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from app.intent.exceptions import (
    AmbiguousIntentError,
    IntentError,
    UnsupportedIntentError,
)
from app.intent.mappings import map_intent_to_proposal
from app.intent.parser import parse_intent
from app.intent.schemas import ActionType, IntentType, TaskIntent


@dataclass(frozen=True)
class LabeledIntentExample:
    """A labeled ground-truth intent example for benchmarking."""

    id: str
    prompt: str
    language: str  # "en" or "ar"
    category: str  # "valid", "unsupported", "ambiguous"
    expected_intent_type: IntentType | None
    expected_action: ActionType | None = None
    expected_count: int | None = None
    expected_query: str | None = None
    expected_email_id: int | None = None
    expected_tool: str | None = None
    description: str = ""


# Independent hold-out evaluation dataset (48 items)
EVALUATION_DATASET: list[LabeledIntentExample] = [
    # --- Category 1: Valid English Requests (12 items) ---
    LabeledIntentExample(
        id="EN-VAL-01",
        prompt="Please read my latest 5 emails.",
        language="en",
        category="valid",
        expected_intent_type=IntentType.READ_LATEST_EMAILS,
        expected_action=ActionType.READ,
        expected_count=5,
        expected_tool="read_inbox",
        description="Standard English inbox read with count 5 and polite prefix",
    ),
    LabeledIntentExample(
        id="EN-VAL-02",
        prompt="Fetch my latest 1 email.",
        language="en",
        category="valid",
        expected_intent_type=IntentType.READ_LATEST_EMAILS,
        expected_action=ActionType.READ,
        expected_count=1,
        expected_tool="read_inbox",
        description="Single email read in English",
    ),
    LabeledIntentExample(
        id="EN-VAL-03",
        prompt="Fetch the most recent 10 emails.",
        language="en",
        category="valid",
        expected_intent_type=IntentType.READ_LATEST_EMAILS,
        expected_action=ActionType.READ,
        expected_count=10,
        expected_tool="read_inbox",
        description="Higher count inbox read in English",
    ),
    LabeledIntentExample(
        id="EN-VAL-04",
        prompt="Summarize my latest 4 emails.",
        language="en",
        category="valid",
        expected_intent_type=IntentType.SUMMARIZE_RECENT_EMAILS,
        expected_action=ActionType.SUMMARIZE,
        expected_count=4,
        expected_tool="read_inbox",
        description="Standard English inbox summary with count 4",
    ),
    LabeledIntentExample(
        id="EN-VAL-05",
        prompt="Summarize recent 2 emails in English.",
        language="en",
        category="valid",
        expected_intent_type=IntentType.SUMMARIZE_RECENT_EMAILS,
        expected_action=ActionType.SUMMARIZE,
        expected_count=2,
        expected_tool="read_inbox",
        description="English summary with explicit English language tag",
    ),
    LabeledIntentExample(
        id="EN-VAL-06",
        prompt="Give me a summary of latest 3 emails.",
        language="en",
        category="valid",
        expected_intent_type=IntentType.SUMMARIZE_RECENT_EMAILS,
        expected_action=ActionType.SUMMARIZE,
        expected_count=3,
        expected_tool="read_inbox",
        description="English summary with alternative phrasing 'give me a summary of'",
    ),
    LabeledIntentExample(
        id="EN-VAL-07",
        prompt="Search emails for syllabus.",
        language="en",
        category="valid",
        expected_intent_type=IntentType.SEARCH_EMAILS,
        expected_action=ActionType.SEARCH,
        expected_query="syllabus",
        expected_tool="search_emails",
        description="English email search with query 'syllabus'",
    ),
    LabeledIntentExample(
        id="EN-VAL-08",
        prompt="Search emails for project.",
        language="en",
        category="valid",
        expected_intent_type=IntentType.SEARCH_EMAILS,
        expected_action=ActionType.SEARCH,
        expected_query="project",
        expected_tool="search_emails",
        description="English inbox search with query 'project'",
    ),
    LabeledIntentExample(
        id="EN-VAL-09",
        prompt="Find emails containing midterm.",
        language="en",
        category="valid",
        expected_intent_type=IntentType.SEARCH_EMAILS,
        expected_action=ActionType.SEARCH,
        expected_query="midterm",
        expected_tool="search_emails",
        description="English search using 'find emails containing'",
    ),
    LabeledIntentExample(
        id="EN-VAL-10",
        prompt="Show email 12.",
        language="en",
        category="valid",
        expected_intent_type=IntentType.READ_EMAIL_DETAILS,
        expected_action=ActionType.SHOW,
        expected_email_id=12,
        expected_tool="get_email_details",
        description="English show email by ID 12",
    ),
    LabeledIntentExample(
        id="EN-VAL-11",
        prompt="Display email #4.",
        language="en",
        category="valid",
        expected_intent_type=IntentType.READ_EMAIL_DETAILS,
        expected_action=ActionType.SHOW,
        expected_email_id=4,
        expected_tool="get_email_details",
        description="English display email with hash prefix #4",
    ),
    LabeledIntentExample(
        id="EN-VAL-12",
        prompt="View email details 19.",
        language="en",
        category="valid",
        expected_intent_type=IntentType.READ_EMAIL_DETAILS,
        expected_action=ActionType.SHOW,
        expected_email_id=19,
        expected_tool="get_email_details",
        description="English view email details for message 19",
    ),
    # --- Category 2: Valid Arabic Requests (12 items) ---
    LabeledIntentExample(
        id="AR-VAL-01",
        prompt="اقرأ آخر 5 إيميلات.",
        language="ar",
        category="valid",
        expected_intent_type=IntentType.READ_LATEST_EMAILS,
        expected_action=ActionType.READ,
        expected_count=5,
        expected_tool="read_inbox",
        description="Arabic read latest 5 emails",
    ),
    LabeledIntentExample(
        id="AR-VAL-02",
        prompt="اقرأ آخر 1 رسالة.",
        language="ar",
        category="valid",
        expected_intent_type=IntentType.READ_LATEST_EMAILS,
        expected_action=ActionType.READ,
        expected_count=1,
        expected_tool="read_inbox",
        description="Arabic read single latest message",
    ),
    LabeledIntentExample(
        id="AR-VAL-03",
        prompt="استعرض آخر 4 رسائل.",
        language="ar",
        category="valid",
        expected_intent_type=IntentType.READ_LATEST_EMAILS,
        expected_action=ActionType.READ,
        expected_count=4,
        expected_tool="read_inbox",
        description="Arabic review latest 4 messages",
    ),
    LabeledIntentExample(
        id="AR-VAL-04",
        prompt="لخص آخر 2 إيميلات.",
        language="ar",
        category="valid",
        expected_intent_type=IntentType.SUMMARIZE_RECENT_EMAILS,
        expected_action=ActionType.SUMMARIZE,
        expected_count=2,
        expected_tool="read_inbox",
        description="Arabic summarize latest 2 emails",
    ),
    LabeledIntentExample(
        id="AR-VAL-05",
        prompt="لخص لي آخر 3 رسائل بالعربي.",
        language="ar",
        category="valid",
        expected_intent_type=IntentType.SUMMARIZE_RECENT_EMAILS,
        expected_action=ActionType.SUMMARIZE,
        expected_count=3,
        expected_tool="read_inbox",
        description="Arabic summarize latest 3 messages in Arabic",
    ),
    LabeledIntentExample(
        id="AR-VAL-06",
        prompt="اعطني ملخص لآخر 4 إيميلات.",
        language="ar",
        category="valid",
        expected_intent_type=IntentType.SUMMARIZE_RECENT_EMAILS,
        expected_action=ActionType.SUMMARIZE,
        expected_count=4,
        expected_tool="read_inbox",
        description="Arabic give summary of latest 4 emails",
    ),
    LabeledIntentExample(
        id="AR-VAL-07",
        prompt="ابحث عن إيميلات فيها كلمة مشروع.",
        language="ar",
        category="valid",
        expected_intent_type=IntentType.SEARCH_EMAILS,
        expected_action=ActionType.SEARCH,
        expected_query="مشروع",
        expected_tool="search_emails",
        description="Arabic search emails for word 'مشروع'",
    ),
    LabeledIntentExample(
        id="AR-VAL-08",
        prompt="ابحث في البريد عن تسجيل.",
        language="ar",
        category="valid",
        expected_intent_type=IntentType.SEARCH_EMAILS,
        expected_action=ActionType.SEARCH,
        expected_query="تسجيل",
        expected_tool="search_emails",
        description="Arabic search inbox for 'تسجيل'",
    ),
    LabeledIntentExample(
        id="AR-VAL-09",
        prompt="ابحث عن رسائل تحتوي على واجب.",
        language="ar",
        category="valid",
        expected_intent_type=IntentType.SEARCH_EMAILS,
        expected_action=ActionType.SEARCH,
        expected_query="واجب",
        expected_tool="search_emails",
        description="Arabic search messages containing 'واجب'",
    ),
    LabeledIntentExample(
        id="AR-VAL-10",
        prompt="اعرض الإيميل رقم 9.",
        language="ar",
        category="valid",
        expected_intent_type=IntentType.READ_EMAIL_DETAILS,
        expected_action=ActionType.SHOW,
        expected_email_id=9,
        expected_tool="get_email_details",
        description="Arabic show email number 9",
    ),
    LabeledIntentExample(
        id="AR-VAL-11",
        prompt="اظهر الرسالة رقم 3.",
        language="ar",
        category="valid",
        expected_intent_type=IntentType.READ_EMAIL_DETAILS,
        expected_action=ActionType.SHOW,
        expected_email_id=3,
        expected_tool="get_email_details",
        description="Arabic show message number 3",
    ),
    LabeledIntentExample(
        id="AR-VAL-12",
        prompt="عرض تفاصيل الإيميل 15.",
        language="ar",
        category="valid",
        expected_intent_type=IntentType.READ_EMAIL_DETAILS,
        expected_action=ActionType.SHOW,
        expected_email_id=15,
        expected_tool="get_email_details",
        description="Arabic display details of email 15",
    ),
    # --- Category 3: Unsupported Requests (12 items) ---
    LabeledIntentExample(
        id="UNSUP-01",
        prompt="Send an email to Dr. Layla.",
        language="en",
        category="unsupported",
        expected_intent_type=None,
        description="English email sending request",
    ),
    LabeledIntentExample(
        id="UNSUP-02",
        prompt="Delete email 7.",
        language="en",
        category="unsupported",
        expected_intent_type=None,
        description="English email deletion request",
    ),
    LabeledIntentExample(
        id="UNSUP-03",
        prompt="Forward the last email to my personal address.",
        language="en",
        category="unsupported",
        expected_intent_type=None,
        description="English email forwarding request",
    ),
    LabeledIntentExample(
        id="UNSUP-04",
        prompt="Draft an email to the registrar.",
        language="en",
        category="unsupported",
        expected_intent_type=None,
        description="English email drafting request",
    ),
    LabeledIntentExample(
        id="UNSUP-05",
        prompt="Update user profile settings.",
        language="en",
        category="unsupported",
        expected_intent_type=None,
        description="English settings modification request",
    ),
    LabeledIntentExample(
        id="UNSUP-06",
        prompt="Export all emails to CSV.",
        language="en",
        category="unsupported",
        expected_intent_type=None,
        description="English bulk export request",
    ),
    LabeledIntentExample(
        id="UNSUP-07",
        prompt="أرسل إيميل للدكتور.",
        language="ar",
        category="unsupported",
        expected_intent_type=None,
        description="Arabic email sending request",
    ),
    LabeledIntentExample(
        id="UNSUP-08",
        prompt="احذف الإيميل رقم 3.",
        language="ar",
        category="unsupported",
        expected_intent_type=None,
        description="Arabic email deletion request",
    ),
    LabeledIntentExample(
        id="UNSUP-09",
        prompt="قم بإعادة توجيه الرسالة.",
        language="ar",
        category="unsupported",
        expected_intent_type=None,
        description="Arabic email forwarding request",
    ),
    LabeledIntentExample(
        id="UNSUP-10",
        prompt="اكتب مسودة بريد جديدة.",
        language="ar",
        category="unsupported",
        expected_intent_type=None,
        description="Arabic email drafting request",
    ),
    LabeledIntentExample(
        id="UNSUP-11",
        prompt="عدل معلومات الحساب.",
        language="ar",
        category="unsupported",
        expected_intent_type=None,
        description="Arabic account modification request",
    ),
    LabeledIntentExample(
        id="UNSUP-12",
        prompt="تصدير كافة الرسائل إلى ملف.",
        language="ar",
        category="unsupported",
        expected_intent_type=None,
        description="Arabic bulk export request",
    ),
    # --- Category 4: Ambiguous / Vague Requests (12 items) ---
    LabeledIntentExample(
        id="AMBIG-01",
        prompt="Read emails.",
        language="en",
        category="ambiguous",
        expected_intent_type=None,
        description="English reading request missing count",
    ),
    LabeledIntentExample(
        id="AMBIG-02",
        prompt="Summarize my inbox.",
        language="en",
        category="ambiguous",
        expected_intent_type=None,
        description="English summary request missing count",
    ),
    LabeledIntentExample(
        id="AMBIG-03",
        prompt="Search emails.",
        language="en",
        category="ambiguous",
        expected_intent_type=None,
        description="English search missing keyword",
    ),
    LabeledIntentExample(
        id="AMBIG-04",
        prompt="Show email.",
        language="en",
        category="ambiguous",
        expected_intent_type=None,
        description="English detail request missing ID",
    ),
    LabeledIntentExample(
        id="AMBIG-05",
        prompt="اقرأ الإيميلات.",
        language="ar",
        category="ambiguous",
        expected_intent_type=None,
        description="Arabic reading request missing count",
    ),
    LabeledIntentExample(
        id="AMBIG-06",
        prompt="لخص البريد.",
        language="ar",
        category="ambiguous",
        expected_intent_type=None,
        description="Arabic summary request missing count",
    ),
    LabeledIntentExample(
        id="AMBIG-07",
        prompt="ابحث في الإيميلات.",
        language="ar",
        category="ambiguous",
        expected_intent_type=None,
        description="Arabic search missing keyword",
    ),
    LabeledIntentExample(
        id="AMBIG-08",
        prompt="اعرض الإيميل.",
        language="ar",
        category="ambiguous",
        expected_intent_type=None,
        description="Arabic detail request missing ID",
    ),
    LabeledIntentExample(
        id="AMBIG-09",
        prompt="Read latest 5 emails and delete them.",
        language="en",
        category="ambiguous",
        expected_intent_type=None,
        description="Compound request containing destructive action",
    ),
    LabeledIntentExample(
        id="AMBIG-10",
        prompt="What is the weather today in Riyadh?",
        language="en",
        category="ambiguous",
        expected_intent_type=None,
        description="Out of domain general query",
    ),
    LabeledIntentExample(
        id="AMBIG-11",
        prompt="Show me everything you can find.",
        language="en",
        category="ambiguous",
        expected_intent_type=None,
        description="Vague catch-all prompt",
    ),
    LabeledIntentExample(
        id="AMBIG-12",
        prompt="لخص الإيميلات وافعل ما يلزم.",
        language="ar",
        category="ambiguous",
        expected_intent_type=None,
        description="Vague Arabic compound instruction",
    ),
]


@dataclass
class EvaluationReport:
    """Summary metrics of the intent evaluation benchmark."""

    total_samples: int
    successful_classifications: int
    accuracy_rate: float
    valid_category_accuracy: float
    unsupported_detection_rate: float
    ambiguity_detection_rate: float
    false_denial_count: int
    false_acceptance_count: int
    proposal_generation_accuracy: float
    mean_latency_us: float
    median_latency_us: float
    p95_latency_us: float
    failures: list[dict[str, Any]] = field(default_factory=list)


def evaluate_intent_dataset(
    dataset: list[LabeledIntentExample] | None = None,
) -> EvaluationReport:
    """Run full deterministic evaluation across the labeled dataset."""
    items = dataset or EVALUATION_DATASET
    latencies: list[float] = []

    successes = 0
    valid_successes = 0
    valid_total = 0
    unsupported_successes = 0
    unsupported_total = 0
    ambiguity_successes = 0
    ambiguity_total = 0

    false_denials = 0
    false_acceptances = 0
    proposal_successes = 0
    failures: list[dict[str, Any]] = []

    for item in items:
        start_t = time.perf_counter()
        caught_unsupported = False
        caught_ambiguity = False
        parsed_intent: TaskIntent | None = None

        try:
            parsed_intent = parse_intent(item.prompt)
        except UnsupportedIntentError:
            caught_unsupported = True
        except (AmbiguousIntentError, IntentError):
            caught_ambiguity = True

        elapsed_us = (time.perf_counter() - start_t) * 1_000_000.0
        latencies.append(elapsed_us)

        # Category: Valid
        if item.category == "valid":
            valid_total += 1
            if parsed_intent is None or caught_unsupported or caught_ambiguity:
                false_denials += 1
                failures.append(
                    {
                        "id": item.id,
                        "prompt": item.prompt,
                        "error": "Valid prompt falsely denied or rejected.",
                    }
                )
            elif (
                parsed_intent.intent_type == item.expected_intent_type
                and parsed_intent.requested_action == item.expected_action
                and (
                    item.expected_count is None
                    or parsed_intent.requested_count == item.expected_count
                )
                and (
                    item.expected_query is None
                    or parsed_intent.search_query == item.expected_query
                )
                and (
                    item.expected_email_id is None
                    or parsed_intent.requested_email_id == item.expected_email_id
                )
            ):
                valid_successes += 1
                successes += 1

                # Verify proposal mapping
                try:
                    proposal = map_intent_to_proposal(
                        intent=parsed_intent, user_id=1, task_id="test_eval_task"
                    )
                    if (
                        proposal.requested_tool == item.expected_tool
                        and proposal.requested_tool in proposal.requested_constraints
                    ):
                        proposal_successes += 1
                    else:
                        failures.append(
                            {
                                "id": item.id,
                                "prompt": item.prompt,
                                "error": f"Proposal tool mismatch: expected {item.expected_tool}, got {proposal.requested_tool}",
                            }
                        )
                except Exception as ex:
                    failures.append(
                        {
                            "id": item.id,
                            "prompt": item.prompt,
                            "error": f"Proposal generation raised exception: {ex}",
                        }
                    )
            else:
                failures.append(
                    {
                        "id": item.id,
                        "prompt": item.prompt,
                        "error": f"Parsed intent mismatch: {parsed_intent}",
                    }
                )

        # Category: Unsupported
        elif item.category == "unsupported":
            unsupported_total += 1
            if caught_unsupported:
                unsupported_successes += 1
                successes += 1
            else:
                false_acceptances += 1
                failures.append(
                    {
                        "id": item.id,
                        "prompt": item.prompt,
                        "error": "Unsupported prompt was not detected as unsupported.",
                    }
                )

        # Category: Ambiguous
        elif item.category == "ambiguous":
            ambiguity_total += 1
            if (
                caught_ambiguity
                or caught_unsupported
                or (
                    parsed_intent
                    and (
                        parsed_intent.is_ambiguous
                        or parsed_intent.requires_clarification
                    )
                )
            ):
                ambiguity_successes += 1
                successes += 1
            else:
                false_acceptances += 1
                failures.append(
                    {
                        "id": item.id,
                        "prompt": item.prompt,
                        "error": "Ambiguous prompt was falsely accepted as valid intent.",
                    }
                )

    total_samples = len(items)
    accuracy_rate = (successes / total_samples) * 100.0 if total_samples else 0.0
    valid_acc = (valid_successes / valid_total) * 100.0 if valid_total else 0.0
    unsup_rate = (
        (unsupported_successes / unsupported_total) * 100.0
        if unsupported_total
        else 0.0
    )
    ambig_rate = (
        (ambiguity_successes / ambiguity_total) * 100.0 if ambiguity_total else 0.0
    )
    prop_acc = (proposal_successes / valid_total) * 100.0 if valid_total else 0.0

    sorted_lat = sorted(latencies)
    p95_idx = int(0.95 * len(sorted_lat)) - 1
    p95_lat = sorted_lat[max(0, p95_idx)] if sorted_lat else 0.0

    return EvaluationReport(
        total_samples=total_samples,
        successful_classifications=successes,
        accuracy_rate=accuracy_rate,
        valid_category_accuracy=valid_acc,
        unsupported_detection_rate=unsup_rate,
        ambiguity_detection_rate=ambig_rate,
        false_denial_count=false_denials,
        false_acceptance_count=false_acceptances,
        proposal_generation_accuracy=prop_acc,
        mean_latency_us=mean(latencies) if latencies else 0.0,
        median_latency_us=median(latencies) if latencies else 0.0,
        p95_latency_us=p95_lat,
        failures=failures,
    )


def print_evaluation_report() -> None:
    """Run and print the benchmark evaluation report."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    print("\n" + "=" * 80)
    print(" AEGIS-CORE WEEK 4 — INTENT PARSING & PROPOSAL EVALUATION BENCHMARK")
    print("=" * 80)

    report = evaluate_intent_dataset()

    print(f"Total Evaluation Samples:       {report.total_samples}")
    print(
        f"Overall Accuracy Rate:          {report.accuracy_rate:.2f}% "
        f"({report.successful_classifications}/{report.total_samples})"
    )
    print(f"Valid Intent Accuracy:          {report.valid_category_accuracy:.2f}%")
    print(f"Proposal Generation Accuracy:   {report.proposal_generation_accuracy:.2f}%")
    print(f"Unsupported Intent Detection:   {report.unsupported_detection_rate:.2f}%")
    print(f"Ambiguity Detection Rate:       {report.ambiguity_detection_rate:.2f}%")
    print(f"False Denial Count:             {report.false_denial_count}")
    print(f"False Acceptance Count:         {report.false_acceptance_count}")
    print("-" * 80)
    print(f"Mean Latency:                   {report.mean_latency_us:.2f} µs")
    print(f"Median Latency:                 {report.median_latency_us:.2f} µs")
    print(f"P95 Latency:                    {report.p95_latency_us:.2f} µs")
    print("=" * 80)
    if report.failures:
        print(f"FAILURES DETECTED ({len(report.failures)}):")
        for f in report.failures:
            print(f"  - [{f.get('id')}] {f.get('prompt')}: {f.get('error')}")
    else:
        print("RESULT: ALL 48 EVALUATION BENCHMARKS PASSED WITH 100% ACCURACY")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    print_evaluation_report()
