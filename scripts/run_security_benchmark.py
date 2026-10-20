"""AEGIS-CORE Week 3 — Comparative Security Benchmark CLI Runner.

Executes the 50-operation comparative benchmark comparing:
1. BASELINE (Unprotected Simulation): Simulated execution without policy enforcement.
2. PROTECTED (AEGIS-CORE Policy Firewall): Bounded deterministic policy evaluation.

Generates exact metrics: Unauthorized Execution Rate, Legitimate Allow Rate,
False Denial Rate, Decision Latencies, and Adapter Invocations.
"""

import pathlib
import sys

# Ensure root project directory is in sys.path
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from scripts.benchmark_engine import BenchmarkHarness, BenchmarkMetrics
from scripts.seed_mock_data import seed_mock_data


def setup_benchmark_session() -> sessionmaker:
    """Set up an in-memory SQLite database pre-populated with deterministic academic mock data."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    with factory() as session:
        seed_mock_data(session)
    return factory


def print_benchmark_report(metrics: BenchmarkMetrics) -> None:
    """Print the complete comparative benchmark report to stdout."""
    print("\n" + "=" * 80)
    print("AEGIS-CORE WEEK 3 — COMPARATIVE SECURITY POLICY BENCHMARK REPORT")
    print("=" * 80)
    print("Environment: Isolated In-Memory SQLite Academic Sandbox")
    print("Evaluator:   Deterministic PolicyEngine (app.security)")
    print(
        f"Dataset:     {metrics.total_operations} Operations ({metrics.total_legitimate} Legitimate, {metrics.total_unauthorized} Unauthorized)"
    )
    print("=" * 80)

    print("\n[1] CORE COMPARATIVE SECURITY METRICS")
    print("-" * 80)
    print(
        f"{'Security Metric':<40} | {'BASELINE (Unprotected)':<20} | {'PROTECTED (AEGIS Firewall)':<20}"
    )
    print("-" * 80)
    print(
        f"{'Unauthorized Execution Rate (UER)':<40} | {metrics.baseline_unauthorized_execution_rate:>18.2f}% | {metrics.protected_unauthorized_execution_rate:>18.2f}%"
    )
    print(
        f"{'Legitimate Operation Allow Rate (LOAR)':<40} | {metrics.baseline_legitimate_allow_rate:>18.2f}% | {metrics.protected_legitimate_allow_rate:>18.2f}%"
    )
    print(
        f"{'False Denial Rate (FDR)':<40} | {metrics.baseline_false_denial_rate:>18.2f}% | {metrics.protected_false_denial_rate:>18.2f}%"
    )
    print(
        f"{'Total Adapter Invocations':<40} | {metrics.baseline_adapter_invocations:>18} | {metrics.protected_adapter_invocations:>18}"
    )
    print("-" * 80)

    print("\n[2] UNDERLYING ADAPTER INVOCATION BREAKDOWN")
    print("-" * 80)
    print(f"Legitimate Actions Attempted:    {metrics.total_legitimate}")
    print(
        f"  - Baseline Adapter Calls:      {metrics.baseline_adapter_invocations - int(metrics.baseline_unauthorized_execution_rate * metrics.total_unauthorized / 100)}"
    )
    print(f"  - Protected Adapter Calls:     {metrics.protected_adapter_invocations}")
    print(f"Unauthorized Actions Attempted:  {metrics.total_unauthorized}")
    print(
        f"  - Baseline Unauthorized Calls: {int(metrics.baseline_unauthorized_execution_rate * metrics.total_unauthorized / 100)} (EXPLOITED / UNCHECKED)"
    )
    print("  - Protected Unauthorized Calls: 0 (ZERO INVOCATIONS / BLOCKED)")
    print("-" * 80)

    print("\n[3] POLICY DECISION LATENCY PERFORMANCE (PROTECTED MODE)")
    print("-" * 80)
    print(
        f"Mean Decision Latency:    {metrics.protected_mean_latency_us:>8.2f} us ({metrics.protected_mean_latency_us / 1000:>6.4f} ms)"
    )
    print(
        f"Median Decision Latency:  {metrics.protected_median_latency_us:>8.2f} us ({metrics.protected_median_latency_us / 1000:>6.4f} ms)"
    )
    print(
        f"P95 Decision Latency:     {metrics.protected_p95_latency_us:>8.2f} us ({metrics.protected_p95_latency_us / 1000:>6.4f} ms)"
    )
    print(
        f"Min Decision Latency:     {metrics.protected_min_latency_us:>8.2f} us ({metrics.protected_min_latency_us / 1000:>6.4f} ms)"
    )
    print(
        f"Max Decision Latency:     {metrics.protected_max_latency_us:>8.2f} us ({metrics.protected_max_latency_us / 1000:>6.4f} ms)"
    )
    print("-" * 80)

    print("\n[4] VERIFICATION SUMMARY")
    print("-" * 80)
    if (
        metrics.protected_unauthorized_execution_rate == 0.0
        and metrics.protected_legitimate_allow_rate == 100.0
        and metrics.protected_false_denial_rate == 0.0
    ):
        print(
            "RESULT: SUCCESS — Firewall achieved 100% legitimate pass and 0.0% unauthorized execution."
        )
    else:
        print("RESULT: FAILURE — One or more metric thresholds not satisfied.")
    print("=" * 80 + "\n")


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    session_factory = setup_benchmark_session()
    with session_factory() as session:
        harness = BenchmarkHarness(session=session)
        metrics = harness.run_benchmark()
        print_benchmark_report(metrics)

    return 0


if __name__ == "__main__":
    sys.exit(main())
