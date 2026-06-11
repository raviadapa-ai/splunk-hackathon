from collections import Counter

from app.models import Evidence, InvestigationResult


ROOT_CAUSE_MAP = {
    "database_timeout": ("database connection pool exhaustion", ["Recycle saturated DB connections", "Scale checkout-api workers", "Escalate to database owner"]),
    "upstream_api_failure": ("payment gateway dependency failure", ["Fail over payment gateway route", "Open provider escalation", "Throttle retries"]),
    "auth_failure": ("identity provider authentication failure", ["Fail over identity provider", "Invalidate bad sessions", "Escalate auth service"]),
    "deployment_regression": ("recent deployment regression", ["Rollback deployment", "Disable risky feature flag", "Escalate release owner"]),
    "cpu_saturation": ("service CPU saturation", ["Scale service instances", "Restart overloaded worker", "Reduce background job concurrency"]),
    "latency_regression": ("latency regression under load", ["Scale service instances", "Warm cache", "Inspect slow endpoint"]),
}


def _most_common(values: list[str], default: str = "unknown") -> str:
    clean = [value for value in values if value and value != "null"]
    if not clean:
        return default
    return Counter(clean).most_common(1)[0][0]


def decide_investigation(evidence: Evidence, source: str = "rules_fallback") -> InvestigationResult:
    dominant_error = _most_common(evidence.error_types, "latency_regression")
    root_cause, actions = ROOT_CAUSE_MAP.get(
        dominant_error,
        ("correlated service anomaly", ["Open service-owner escalation", "Review correlated traces", "Continue monitoring"]),
    )

    score = 0.55
    if evidence.event_count >= 10:
        score += 0.15
    if evidence.max_latency_ms >= 1500:
        score += 0.1
    if evidence.max_db_pool_pct >= 90 or evidence.max_cpu_pct >= 90:
        score += 0.1
    if len(set(evidence.hosts)) > 1:
        score += 0.05
    confidence = min(round(score, 2), 0.95)

    severity = "LOW"
    if evidence.event_count >= 20 or evidence.max_cpu_pct >= 95 or evidence.max_db_pool_pct >= 95:
        severity = "HIGH"
    elif evidence.event_count >= 10 or evidence.max_latency_ms >= 2000:
        severity = "MEDIUM"
    if dominant_error in {"database_timeout", "upstream_api_failure", "deployment_regression"} and evidence.event_count >= 10:
        severity = "HIGH"

    service = evidence.service or "unknown-service"
    affected_hosts = ", ".join(sorted(set(evidence.hosts))[:4]) or "unknown hosts"
    affected_endpoints = ", ".join(sorted(set(evidence.endpoints))[:4]) or "unknown endpoints"
    summary = (
        f"{evidence.event_count} correlated events for {service}; "
        f"dominant signal={dominant_error}; hosts={affected_hosts}; "
        f"endpoints={affected_endpoints}; max_latency_ms={evidence.max_latency_ms:.0f}."
    )
    ai_summary = (
        f"RCA for {service}: root cause appears to be {root_cause}. "
        f"Confidence {confidence:.2f}. {summary} "
        f"Recommended actions: {', '.join(actions)}."
    )

    return InvestigationResult(
        incident_id=evidence.incident_id,
        service=service,
        severity=severity,
        root_cause=root_cause,
        confidence_score=confidence,
        evidence_summary=summary,
        ai_summary=ai_summary,
        recommended_actions=actions,
        safe_remediation_actions=[f"SIMULATE: {action}" for action in actions],
        source=source,
    )
