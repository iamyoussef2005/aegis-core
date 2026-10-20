"""Phase D — Automated Comparative Benchmark Test for AEGIS-CORE.

Verifies the 50-operation comparative benchmark asserting:
1. Protected Unauthorized Execution Rate is strictly 0.0%.
2. Protected Legitimate Operation Allow Rate is strictly 100.0%.
3. Protected False Denial Rate is strictly 0.0%.
4. Protected adapter calls for unauthorized actions is strictly 0.
5. Baseline (unprotected simulation) executes unauthorized actions due to lack of policy checks.
6. Mean policy decision latency is sub-millisecond (< 1.0 ms).
"""

from sqlalchemy.orm import Session

from scripts.benchmark_engine import BenchmarkHarness


def test_comparative_security_benchmark_metrics(seeded_session: Session) -> None:
    """Run the 50-operation comparative benchmark and verify all security metrics."""
    harness = BenchmarkHarness(session=seeded_session)
    metrics = harness.run_benchmark()

    # 1. Volume assertions
    assert metrics.total_operations == 50
    assert metrics.total_legitimate == 25
    assert metrics.total_unauthorized == 25

    # 2. Baseline allows unauthorized actions because there is no policy engine
    assert metrics.baseline_unauthorized_execution_rate > 0.0
    assert metrics.baseline_adapter_invocations > metrics.protected_adapter_invocations

    # 3. Protected configuration enforces strict boundary security:
    # 0.0% unauthorized execution rate
    assert metrics.protected_unauthorized_execution_rate == 0.0

    # 100.0% legitimate operation allow rate
    assert metrics.protected_legitimate_allow_rate == 100.0

    # 0.0% false denial rate
    assert metrics.protected_false_denial_rate == 0.0

    # Adapter calls for legitimate operations is exactly 25
    assert metrics.protected_adapter_invocations == 25

    # 4. Latency performance: mean latency must be sub-millisecond (< 1000 microseconds)
    assert metrics.protected_mean_latency_us < 1000.0
    assert metrics.protected_median_latency_us < 1000.0


def test_comparative_benchmark_all_unauthorized_cases_denied_with_reasons(
    seeded_session: Session,
) -> None:
    """Verify every single one of the 25 unauthorized operations receives a valid DENY decision."""
    harness = BenchmarkHarness(session=seeded_session)
    metrics = harness.run_benchmark()

    protected_unauthorized = [
        r
        for r in metrics.detailed_results
        if r.mode == "PROTECTED" and not r.is_legitimate
    ]
    assert len(protected_unauthorized) == 25

    expected_deny_codes = {
        "TOOL_NOT_ALLOWED",
        "CONSTRAINT_VIOLATION",
        "ARGUMENT_INVALID",
        "POLICY_MISSING",
        "POLICY_EXPIRED",
        "TASK_MISMATCH",
        "USER_MISMATCH",
    }

    for res in protected_unauthorized:
        assert res.decision == "DENY", f"Op {res.op_id} was unexpectedly allowed!"
        assert res.reason_code in expected_deny_codes, (
            f"Op {res.op_id} produced unexpected reason code: {res.reason_code}"
        )
        assert res.adapter_invoked is False, (
            f"Op {res.op_id} invoked underlying adapter despite being unauthorized!"
        )


def test_comparative_benchmark_all_legitimate_cases_allowed(
    seeded_session: Session,
) -> None:
    """Verify every single one of the 25 legitimate operations receives an ALLOW decision."""
    harness = BenchmarkHarness(session=seeded_session)
    metrics = harness.run_benchmark()

    protected_legitimate = [
        r for r in metrics.detailed_results if r.mode == "PROTECTED" and r.is_legitimate
    ]
    assert len(protected_legitimate) == 25

    for res in protected_legitimate:
        assert res.decision == "ALLOW", (
            f"Legitimate op {res.op_id} was unexpectedly denied!"
        )
        assert res.reason_code == "ALLOW"
        assert res.adapter_invoked is True
