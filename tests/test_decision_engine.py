from app.decision_engine import decide_investigation
from app.models import Evidence


def test_database_timeout_maps_to_high_confidence_database_rca() -> None:
    evidence = Evidence(
        service="checkout-api",
        incident_id="inc-db",
        event_count=15,
        error_types=["database_timeout"],
        hosts=["checkout-01", "checkout-02"],
        endpoints=["/checkout"],
        max_latency_ms=3200,
        max_db_pool_pct=97,
    )

    result = decide_investigation(evidence)

    assert result.severity == "HIGH"
    assert result.root_cause == "database connection pool exhaustion"
    assert result.confidence_score >= 0.8
    assert result.safe_remediation_actions[0].startswith("SIMULATE:")
