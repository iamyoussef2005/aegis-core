"""Unit and regression tests asserting intent evaluation benchmarks for AEGIS-CORE Week 4."""

from app.intent.evaluation import (
    EVALUATION_DATASET,
    EvaluationReport,
    evaluate_intent_dataset,
)


def test_intent_evaluation_dataset_size_and_coverage() -> None:
    """Ensure the evaluation dataset contains >= 40 diverse examples across all required categories."""
    assert len(EVALUATION_DATASET) >= 40

    categories = {item.category for item in EVALUATION_DATASET}
    assert "valid" in categories
    assert "unsupported" in categories
    assert "ambiguous" in categories

    languages = {item.language for item in EVALUATION_DATASET}
    assert "en" in languages
    assert "ar" in languages

    # Count samples per category
    valid_count = sum(1 for x in EVALUATION_DATASET if x.category == "valid")
    unsup_count = sum(1 for x in EVALUATION_DATASET if x.category == "unsupported")
    ambig_count = sum(1 for x in EVALUATION_DATASET if x.category == "ambiguous")

    assert valid_count >= 12
    assert unsup_count >= 10
    assert ambig_count >= 10


def test_intent_evaluation_benchmark_metrics() -> None:
    """Execute the full 48-sample evaluation benchmark and assert security & accuracy thresholds."""
    report: EvaluationReport = evaluate_intent_dataset()

    # Accuracy must exceed 95% on the hold-out dataset
    assert report.accuracy_rate >= 95.0, (
        f"Accuracy fell below threshold: {report.accuracy_rate}%"
    )
    assert report.valid_category_accuracy >= 95.0
    assert report.unsupported_detection_rate == 100.0
    assert report.ambiguity_detection_rate == 100.0

    # Strict Security Invariants
    assert report.false_denial_count == 0, f"False denials detected: {report.failures}"
    assert report.false_acceptance_count == 0, (
        f"False acceptances detected: {report.failures}"
    )
    assert report.proposal_generation_accuracy == 100.0

    # Latency Invariant: Deterministic parser must operate well under 1 millisecond (1000 us)
    assert report.mean_latency_us < 500.0, (
        f"Mean latency exceeded limit: {report.mean_latency_us} us"
    )
    assert report.p95_latency_us < 1000.0, (
        f"P95 latency exceeded limit: {report.p95_latency_us} us"
    )
    assert len(report.failures) == 0
