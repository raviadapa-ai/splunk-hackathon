from collections import Counter
from typing import cast

from app.models import Evidence, InvestigationResult, Severity

ROOT_CAUSE_MAP = {
    "database_timeout": (
        "database connection pool exhaustion",
        [
            "Recycle saturated DB connections",
            "Scale checkout-api workers",
            "Escalate to database owner",
        ],
    ),
    "upstream_api_failure": (
        "payment gateway dependency failure",
        [
            "Fail over payment gateway route",
            "Open provider escalation",
            "Throttle retries",
        ],
    ),
    "auth_failure": (
        "identity provider authentication failure",
        [
            "Fail over identity provider",
            "Invalidate bad sessions",
            "Escalate auth service",
        ],
    ),
    "deployment_regression": (
        "recent deployment regression",
        ["Rollback deployment", "Disable risky feature flag", "Escalate release owner"],
    ),
    "cpu_saturation": (
        "service CPU saturation",
        [
            "Scale service instances",
            "Restart overloaded worker",
            "Reduce background job concurrency",
        ],
    ),
    "latency_regression": (
        "latency regression under load",
        ["Scale service instances", "Warm cache", "Inspect slow endpoint"],
    ),
    "memory_pressure": (
        "service memory pressure",
        [
            "Scale service instances",
            "Restart memory-saturated worker",
            "Inspect heap and cache growth",
        ],
    ),
}

FALLBACK_RULES = {
    "database_timeout": (
        "Database connection pool saturation or database timeout",
        "HIGH",
        0.8,
        [
            "Recycle saturated DB connections",
            "Scale checkout-api workers",
            "Escalate to database owner",
        ],
    ),
    "upstream_api_failure": (
        "Upstream dependency failure",
        "HIGH",
        0.75,
        [
            "Fail over upstream dependency",
            "Open provider escalation",
            "Throttle retries",
        ],
    ),
    "auth_failure": (
        "Authentication provider or token validation failure",
        "MEDIUM",
        0.7,
        [
            "Fail over identity provider",
            "Invalidate bad sessions",
            "Escalate auth service",
        ],
    ),
    "cpu_saturation": (
        "Host resource saturation",
        "HIGH",
        0.75,
        [
            "Scale service instances",
            "Restart overloaded worker",
            "Reduce background job concurrency",
        ],
    ),
    "latency_regression": (
        "Service latency regression",
        "MEDIUM",
        0.65,
        ["Scale service instances", "Warm cache", "Inspect slow endpoint"],
    ),
    "memory_pressure": (
        "Service memory pressure",
        "HIGH",
        0.75,
        [
            "Scale service instances",
            "Restart memory-saturated worker",
            "Inspect heap and cache growth",
        ],
    ),
    "deployment_regression": (
        "Recent deployment regression",
        "HIGH",
        0.78,
        ["Rollback deployment", "Disable risky feature flag", "Escalate release owner"],
    ),
}


def _most_common(values: list[str], default: str = "unknown") -> str:
    clean = [value for value in values if value and value != "null"]
    if not clean:
        return default
    return Counter(clean).most_common(1)[0][0]


def decide_investigation(
    evidence: Evidence, source: str = "rules_fallback"
) -> InvestigationResult:
    dominant_error = _most_common(evidence.error_types, "latency_regression")
    root_cause, actions = ROOT_CAUSE_MAP.get(
        dominant_error,
        (
            "correlated service anomaly",
            [
                "Open service-owner escalation",
                "Review correlated traces",
                "Continue monitoring",
            ],
        ),
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
    if (
        evidence.event_count >= 20
        or evidence.max_cpu_pct >= 95
        or evidence.max_db_pool_pct >= 95
    ):
        severity = "HIGH"
    elif evidence.event_count >= 10 or evidence.max_latency_ms >= 2000:
        severity = "MEDIUM"
    if (
        dominant_error
        in {"database_timeout", "upstream_api_failure", "deployment_regression"}
        and evidence.event_count >= 10
    ):
        severity = "HIGH"

    service = evidence.service or "unknown-service"
    affected_hosts = ", ".join(sorted(set(evidence.hosts))[:4]) or "unknown hosts"
    affected_endpoints = (
        ", ".join(sorted(set(evidence.endpoints))[:4]) or "unknown endpoints"
    )
    summary = (
        f"{evidence.event_count} correlated events for {service}; "
        f"dominant signal={dominant_error}; hosts={affected_hosts}; "
        f"endpoints={affected_endpoints}; max_latency_ms={evidence.max_latency_ms:.0f}."
    )
    fallback_rca_summary = (
        f"RCA for {service}: root cause appears to be {root_cause}. "
        f"Confidence {confidence:.2f}. {summary} "
        f"Recommended actions: {', '.join(actions)}."
    )

    return InvestigationResult(
        incident_id=evidence.incident_id,
        service=service,
        severity=cast(Severity, severity),
        root_cause=root_cause,
        confidence_score=confidence,
        evidence_summary=summary,
        ai_summary=None,
        fallback_rca_summary=fallback_rca_summary,
        recommended_actions=actions,
        safe_remediation_actions=[f"SIMULATE: {action}" for action in actions],
        source=source,
    )


def build_fallback_rca_from_mcp_evidence(
    evidence: Evidence,
    source: str = "python_mcp_client_rules_fallback",
) -> InvestigationResult:
    errors = {value for value in evidence.error_types if value and value != "null"}
    selected = "latency_regression"
    if "database_timeout" in errors or evidence.max_db_pool_pct >= 90:
        selected = "database_timeout"
    elif "upstream_api_failure" in errors:
        selected = "upstream_api_failure"
    elif "auth_failure" in errors:
        selected = "auth_failure"
    elif "deployment_regression" in errors:
        selected = "deployment_regression"
    elif "memory_pressure" in errors or evidence.max_memory_pct >= 90:
        selected = "memory_pressure"
    elif "cpu_saturation" in errors or evidence.max_cpu_pct >= 90:
        selected = "cpu_saturation"
    elif "latency_regression" in errors:
        selected = "latency_regression"

    root_cause, severity, minimum_confidence, actions = FALLBACK_RULES[selected]
    baseline = decide_investigation(evidence, source=source)
    confidence = max(baseline.confidence_score, minimum_confidence)
    if selected == "database_timeout" and (
        evidence.max_db_pool_pct >= 95 or evidence.event_count >= 25
    ):
        severity = "CRITICAL"
        confidence = max(confidence, 0.85)

    service = evidence.service or "unknown-service"
    affected_hosts = ", ".join(sorted(set(evidence.hosts))[:4]) or "unknown hosts"
    affected_endpoints = (
        ", ".join(sorted(set(evidence.endpoints))[:4]) or "unknown endpoints"
    )
    evidence_summary = (
        f"{evidence.event_count} MCP evidence events for {service}; "
        f"signals={', '.join(sorted(errors)) or selected}; hosts={affected_hosts}; "
        f"endpoints={affected_endpoints}; max_latency_ms={evidence.max_latency_ms:.0f}; "
        f"max_cpu_pct={evidence.max_cpu_pct:.0f}; max_db_pool_pct={evidence.max_db_pool_pct:.0f}."
    )
    fallback_rca_summary = (
        f"RCA for {service}: {root_cause}. Confidence {confidence:.2f}. "
        f"{evidence_summary} Recommended actions: {', '.join(actions)}."
    )
    return InvestigationResult(
        incident_id=evidence.incident_id,
        service=service,
        severity=cast(Severity, severity),
        root_cause=root_cause,
        confidence_score=round(min(confidence, 0.95), 2),
        evidence_summary=evidence_summary,
        ai_summary=None,
        fallback_rca_summary=fallback_rca_summary,
        recommended_actions=actions,
        safe_remediation_actions=[f"SIMULATE: {action}" for action in actions],
        source=source,
        mcp_investigation=source.startswith("python_mcp_client"),
        mcp_tools_used=(
            ["splunk_run_query"] if source.startswith("python_mcp_client") else []
        ),
        mcp_log_event_count=evidence.event_count,
    )
