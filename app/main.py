import asyncio
import math
from html import escape
import os
import secrets
from typing import Any

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
import httpx
from pydantic import BaseModel, ConfigDict, Field

from app.config import AI_TRIAGE_SOURCETYPE
from app.decision_engine import (
    build_fallback_rca_from_mcp_evidence,
    decide_investigation,
)
from app.llm_agent import CodexRcaAgent
from app.models import Evidence, Incident, Severity, log_timestamp, utc_now
from app.splunk_mcp_client import SplunkMCPClient, extract_result_rows, extract_result_text
from app.storage import (
    load_jsonl_events,
    load_incidents,
    upsert_incident,
    write_ai_triage_event,
    write_correlation_event,
    write_index_health_event,
    write_incident_event,
    write_investigation_event,
    write_metadata_snapshot_event,
    write_remediation_event,
    write_splunk_ai_activity_event,
    write_system_health_event,
    write_timeline_event,
)
from app.telemetry import inject_incident, normal_event, write_event

app = FastAPI(title="Agentic Ops Observability", version="1.0.0")

PUBLIC_PATHS = {"/health"}
STARTUP_VERIFICATION_CACHE: dict[str, Any] = {}

INCIDENT_SERVICE_MAP = {
    "database_timeout": "checkout-api",
    "upstream_api_failure": "payment-api",
    "auth_failure": "auth-api",
    "deployment_regression": "checkout-api",
    "cpu_saturation": "catalog-api",
    "latency_regression": "checkout-api",
    "memory_pressure": "catalog-api",
}


class CreateIncidentRequest(BaseModel):
    service: str = "checkout-api"
    severity: Severity = "MEDIUM"
    incident_type: str | None = None
    inject_burst: bool = True


class GenerateLogsRequest(BaseModel):
    count: int = Field(default=25, ge=1, le=1000)
    include_incident: bool = False
    incident_type: str | None = None


class ApprovalRequest(BaseModel):
    approved_by: str = "demo-operator"


class SplunkAlertRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    search_name: str | None = None
    host: str | None = None
    service: str | None = None
    incident_id: str | None = None
    trigger_time: str | None = None
    severity: str | None = None
    result: dict[str, Any] | None = None


def _timestamp() -> str:
    return log_timestamp()


def _nested_value(payload: dict[str, Any], *keys: str) -> Any:
    result = payload.get("result")
    for key in keys:
        value = payload.get(key)
        if value is not None and value != "":
            return value
        if isinstance(result, dict):
            nested_value = result.get(key)
            if nested_value is not None and nested_value != "":
                return nested_value
    return None


def _alert_field(payload: dict[str, Any], default: str, *keys: str) -> str:
    value = _nested_value(payload, *keys)
    return str(value) if value not in {None, ""} else default


def _alert_incident_id(payload: dict[str, Any]) -> str | None:
    value = _nested_value(payload, "incident_id", "sid")
    if value in {None, "", "none"}:
        return None
    return str(value)


def _env_flag(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _first_row(payload: dict[str, Any]) -> dict[str, Any]:
    rows = extract_result_rows(payload)
    return rows[0] if rows else {}


def _row_value(row: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        value = row.get(key)
        if value not in {None, ""}:
            return value
    return default


def _write_timeline(
    incident: Incident,
    event: str,
    *,
    details: dict[str, Any] | None = None,
) -> None:
    write_timeline_event(
        {
            "timestamp": _timestamp(),
            "incident_id": incident.incident_id,
            "service": incident.service,
            "severity": incident.severity,
            "status": incident.status,
            "event": event,
            "root_cause": incident.root_cause,
            "confidence_score": incident.confidence_score,
            "mcp_investigation": incident.mcp_investigation,
            "mcp_tools_used": incident.mcp_tools_used,
            "remediation_status": incident.remediation_status,
            "details": details or {},
            "sourcetype": "aiops-timeline",
        }
    )


def _write_correlation_from_evidence(
    incident: Incident,
    evidence: Evidence,
    *,
    incident_class: str,
    source: str,
) -> None:
    signals = sorted({item for item in evidence.error_types if item and item != "null"})
    hosts = sorted({item for item in evidence.hosts if item})
    endpoints = sorted({item for item in evidence.endpoints if item})
    correlation_score = evidence.event_count + len(signals) * 2 + len(hosts)
    write_correlation_event(
        {
            "timestamp": _timestamp(),
            "incident_id": incident.incident_id,
            "service": incident.service,
            "host": hosts[0] if hosts else "unknown-host",
            "hosts": hosts,
            "endpoint": endpoints[0] if endpoints else "unknown-endpoint",
            "endpoints": endpoints,
            "error_type": signals[0] if signals else "unknown",
            "signals": signals,
            "incident_class": incident_class,
            "window": "5m",
            "correlation_score": correlation_score,
            "event_count": evidence.event_count,
            "source": source,
            "sourcetype": "aiops-correlation",
        }
    )


async def _record_splunk_ai_assistant_activity(
    client: SplunkMCPClient,
    incident: Incident,
    evidence: Evidence,
) -> None:
    seed_spl = (
        'index=main sourcetype="agentic-ops" '
        f'service="{incident.service}" incident_id="{incident.incident_id}" '
        "| stats count avg(latency_ms) max(latency_ms) max(cpu_pct) "
        "max(db_connection_pool_pct) by service host endpoint error_type"
    )
    prompt = (
        f"{incident.root_cause or 'service anomaly'} on {incident.service}; "
        f"signals={', '.join(evidence.error_types) or 'unknown'}"
    )
    record: dict[str, Any] = {
        "timestamp": _timestamp(),
        "incident_id": incident.incident_id,
        "service": incident.service,
        "original_spl": seed_spl,
        "optimized_spl": seed_spl,
        "generated_spl": seed_spl,
        "spl_explanation": "Splunk AI Assistant is disabled because the feature is not activated.",
        "ai_reasoning": "Splunk AI Assistant is disabled; investigation continues without SAIA.",
        "status": "disabled",
        "fallback_reason": "feature_not_activated",
        "sourcetype": "aiops-splunk-ai-activity",
    }
    write_splunk_ai_activity_event(record)


async def _verify_startup_with_splunk_mcp() -> dict[str, Any]:
    if STARTUP_VERIFICATION_CACHE:
        return STARTUP_VERIFICATION_CACHE

    client = SplunkMCPClient(timeout=0.75)
    summary: dict[str, Any] = {
        "startup_timestamp": _timestamp(),
        "system_health": "unknown",
        "main_index": "unknown",
        "metadata_snapshot": "unknown",
    }

    try:
        info_payload = await client.get_info()
        info = _first_row(info_payload)
        summary.update(
            {
                "system_health": "ok",
                "splunk_version": _row_value(info, "version"),
                "server_name": _row_value(info, "serverName", "server_name"),
                "build": _row_value(info, "build"),
            }
        )
        write_system_health_event(
            {
                "timestamp": _timestamp(),
                "status": "ok",
                "splunk_version": summary["splunk_version"],
                "server_name": summary["server_name"],
                "build": summary["build"],
                "startup_timestamp": summary["startup_timestamp"],
                "sourcetype": "aiops-system-health",
            }
        )
    except Exception as exc:
        summary["system_health"] = "failed"
        write_system_health_event(
            {
                "timestamp": _timestamp(),
                "status": "failed",
                "startup_timestamp": summary["startup_timestamp"],
                "fallback_reason": str(exc)[:500],
                "sourcetype": "aiops-system-health",
            }
        )
        write_index_health_event(
            {
                "timestamp": _timestamp(),
                "index_name": "main",
                "exists": False,
                "event_count": 0,
                "verification_time": _timestamp(),
                "status": "skipped",
                "fallback_reason": "system_health_check_failed",
                "sourcetype": "aiops-index-health",
            }
        )
        write_metadata_snapshot_event(
            {
                "timestamp": _timestamp(),
                "known_sourcetypes": [],
                "known_hosts": [],
                "known_sources": [],
                "status": "skipped",
                "fallback_reason": "system_health_check_failed",
                "sourcetype": "aiops-metadata",
            }
        )
        STARTUP_VERIFICATION_CACHE.update(summary)
        return summary

    try:
        indexes_payload = await client.get_indexes()
        indexes = extract_result_rows(indexes_payload)
        main_row = next(
            (
                row
                for row in indexes
                if str(_row_value(row, "title", "name", "index", default="")) == "main"
            ),
            {},
        )
        summary["main_index"] = "ok" if main_row else "missing"
        write_index_health_event(
            {
                "timestamp": _timestamp(),
                "index_name": "main",
                "exists": bool(main_row),
                "event_count": _row_value(
                    main_row,
                    "totalEventCount",
                    "event_count",
                    "total_event_count",
                    default=0,
                ),
                "verification_time": _timestamp(),
                "sourcetype": "aiops-index-health",
            }
        )
    except Exception as exc:
        summary["main_index"] = "failed"
        write_index_health_event(
            {
                "timestamp": _timestamp(),
                "index_name": "main",
                "exists": False,
                "event_count": 0,
                "verification_time": _timestamp(),
                "fallback_reason": str(exc)[:500],
                "sourcetype": "aiops-index-health",
            }
        )

    metadata: dict[str, list[str]] = {"sourcetypes": [], "hosts": [], "sources": []}
    for metadata_type, field_name in (
        ("sourcetypes", "sourcetypes"),
        ("hosts", "hosts"),
        ("sources", "sources"),
    ):
        try:
            payload = await client.get_metadata(metadata_type)
            rows = extract_result_rows(payload)
            metadata[field_name] = [
                str(_row_value(row, metadata_type[:-1], metadata_type, "name", "value"))
                for row in rows
                if _row_value(row, metadata_type[:-1], metadata_type, "name", "value")
            ][:50]
        except Exception:
            metadata[field_name] = []
    summary["metadata_snapshot"] = "ok" if any(metadata.values()) else "empty"
    write_metadata_snapshot_event(
        {
            "timestamp": _timestamp(),
            "known_sourcetypes": metadata["sourcetypes"],
            "known_hosts": metadata["hosts"],
            "known_sources": metadata["sources"],
            "sourcetype": "aiops-metadata",
        }
    )

    STARTUP_VERIFICATION_CACHE.update(summary)
    return summary


@app.middleware("http")
async def _optional_bearer_auth(request: Request, call_next: Any) -> Any:
    api_token = os.getenv("AGENTIC_OPS_API_TOKEN", "").strip()
    if not api_token or request.url.path in PUBLIC_PATHS:
        return await call_next(request)

    expected = f"Bearer {api_token}"
    provided = request.headers.get("authorization", "")
    if not secrets.compare_digest(provided, expected):
        return JSONResponse({"detail": "Unauthorized"}, status_code=401)
    return await call_next(request)


def _evidence_from_alert_context(
    incident: Incident,
    payload: dict[str, Any],
    raw_events: list[dict[str, Any]],
) -> Evidence:
    result = payload.get("result") if isinstance(payload.get("result"), dict) else {}
    rows = raw_events or ([result] if result else [])
    service = incident.service
    error_types = [
        str(row.get("error_type"))
        for row in rows
        if row.get("error_type") not in {None, "", "null"}
    ]
    hosts = [str(row.get("host")) for row in rows if row.get("host")]
    endpoints = [str(row.get("endpoint")) for row in rows if row.get("endpoint")]
    dependencies = [str(row.get("dependency")) for row in rows if row.get("dependency")]
    regions = [str(row.get("user_region")) for row in rows if row.get("user_region")]
    versions = [
        str(row.get("deployment_version"))
        for row in rows
        if row.get("deployment_version")
    ]

    if not error_types:
        alert_name = _alert_field(
            payload, "", "search_name", "alert_name", "name"
        ).lower()
        for known in INCIDENT_SERVICE_MAP:
            if known in alert_name.replace(" ", "_"):
                error_types.append(known)
                break

    def max_value(field: str) -> float:
        values = []
        for row in rows:
            try:
                values.append(float(row.get(field) or 0))
            except (TypeError, ValueError):
                continue
        return max(values) if values else 0

    latencies = []
    for row in rows:
        try:
            latencies.append(float(row.get("latency_ms") or 0))
        except (TypeError, ValueError):
            continue

    return Evidence(
        service=service,
        incident_id=incident.incident_id,
        event_count=max(len(rows), 1),
        error_types=error_types or ["latency_regression"],
        hosts=hosts or [_alert_field(payload, "unknown-host", "host")],
        endpoints=endpoints,
        dependencies=dependencies,
        regions=regions,
        avg_latency_ms=sum(latencies) / len(latencies) if latencies else 0,
        max_latency_ms=max(latencies) if latencies else 0,
        max_cpu_pct=max_value("cpu_pct"),
        max_memory_pct=max_value("memory_pct"),
        max_db_pool_pct=max_value("db_connection_pool_pct"),
        deployment_versions=versions,
        raw_events=raw_events,
    )


def _format_ai_summary(alert_name: str, incident: Incident) -> str:
    actions = (
        "; ".join(incident.recommended_actions)
        if incident.recommended_actions
        else "Continue monitoring"
    )
    return (
        f"Alert '{alert_name}' was triaged for {incident.service}. "
        f"Root cause: {incident.root_cause or 'undetermined service anomaly'}. "
        f"Severity: {incident.severity}. Confidence: {incident.confidence_score or 0:.2f}. "
        f"Evidence: {incident.evidence_summary or 'No evidence summary available.'} "
        f"Recommended actions: {actions}."
    )


def _explanatory_ai_summary(
    *,
    alert_name: str,
    incident: Incident,
    summary_text: str | None = None,
) -> str:
    base_summary = (summary_text or incident.ai_summary or "").strip()
    if not base_summary:
        base_summary = _format_ai_summary(alert_name, incident)

    recommended = (
        "; ".join(incident.recommended_actions[:3])
        if incident.recommended_actions
        else "continue monitoring and gather more evidence"
    )
    mcp_note = (
        f"MCP supplied {incident.mcp_log_event_count} correlated events"
        if incident.mcp_log_event_count
        else "MCP evidence was limited or unavailable"
    )
    explanation = (
        "Reasoning: this summary interprets the evidence rather than repeating it. "
        f"{mcp_note}; the RCA confidence is {incident.confidence_score or 0:.2f}, "
        f"so the recommended operator path is: {recommended}."
    )
    if "Reasoning:" in base_summary:
        return base_summary
    return f"{base_summary} {explanation}".strip()


async def save_ai_summary_to_splunk(
    *,
    summary_text: str,
    host: str,
    alert_name: str,
    incident: Incident,
    alert_payload: dict[str, Any],
) -> dict[str, str]:
    hec_url = os.getenv("SPLUNK_HEC_URL", "").strip()
    hec_token = os.getenv("SPLUNK_HEC_TOKEN", "").strip()
    if not hec_url or not hec_token:
        return {"status": "skipped", "reason": "hec_not_configured"}

    verify_tls = os.getenv("SPLUNK_HEC_VERIFY_TLS", "true").lower() not in {
        "0",
        "false",
        "no",
    }
    index = os.getenv("SPLUNK_HEC_AI_TRIAGE_INDEX", "ai_triages")
    event_payload = {
        "host": host,
        "source": "ai-mcp-triage-agent",
        "sourcetype": "_json",
        "index": index,
        "event": {
            "timestamp": _timestamp(),
            "status": "TRIAGED",
            "original_alert": alert_name,
            "target_host": host,
            "incident_id": incident.incident_id,
            "service": incident.service,
            "severity": incident.severity,
            "confidence_score": incident.confidence_score,
            "llm_provider": incident.llm_provider,
            "ai_summary": _explanatory_ai_summary(
                alert_name=alert_name, incident=incident, summary_text=summary_text
            ),
            "ai_reasoning": _explanatory_ai_summary(
                alert_name=alert_name, incident=incident, summary_text=summary_text
            ),
            "ai_root_cause_summary": _explanatory_ai_summary(
                alert_name=alert_name, incident=incident, summary_text=summary_text
            ),
            "mcp_evidence_summary": incident.mcp_evidence_summary,
            "alert_payload": alert_payload,
        },
    }
    headers = {"Authorization": f"Splunk {hec_token}"}
    try:
        async with httpx.AsyncClient(timeout=15, verify=verify_tls) as client:
            response = await client.post(hec_url, json=event_payload, headers=headers)
            response.raise_for_status()
    except httpx.HTTPError as exc:
        return {"status": "failed", "reason": str(exc)}
    return {"status": "saved", "index": index}


def _fallback_evidence(
    incident: Incident, incident_type: str | None = None
) -> Evidence:
    error_type = incident_type or "latency_regression"
    return Evidence(
        service=incident.service,
        incident_id=incident.incident_id,
        event_count=12,
        error_types=[error_type],
        hosts=[
            f"{incident.service.split('-')[0]}-01",
            f"{incident.service.split('-')[0]}-02",
        ],
        endpoints=["/checkout" if incident.service == "checkout-api" else "/health"],
        dependencies=[
            (
                "postgres"
                if error_type in {"database_timeout", "deployment_regression"}
                else "none"
            )
        ],
        regions=["us-east"],
        avg_latency_ms=2200,
        max_latency_ms=3400,
        max_cpu_pct=92 if error_type == "cpu_saturation" else 76,
        max_memory_pct=94 if error_type == "memory_pressure" else 88,
        max_db_pool_pct=(
            96 if error_type in {"database_timeout", "deployment_regression"} else 55
        ),
        deployment_versions=["2026.06.3"],
    )


def _format_mcp_evidence_summary(evidence: Evidence) -> str:
    hosts = ", ".join(sorted(set(evidence.hosts))[:4]) or "unknown hosts"
    endpoints = ", ".join(sorted(set(evidence.endpoints))[:4]) or "unknown endpoints"
    errors = ", ".join(sorted(set(evidence.error_types))[:4]) or "unknown errors"
    dependencies = (
        ", ".join(sorted(set(evidence.dependencies))[:4]) or "unknown dependencies"
    )
    return (
        f"MCP evidence for {evidence.service}: {evidence.event_count} events; "
        f"errors={errors}; hosts={hosts}; endpoints={endpoints}; dependencies={dependencies}; "
        f"avg_latency_ms={evidence.avg_latency_ms:.0f}; max_latency_ms={evidence.max_latency_ms:.0f}; "
        f"max_cpu_pct={evidence.max_cpu_pct:.0f}; max_db_pool_pct={evidence.max_db_pool_pct:.0f}."
    )


def _fallback_mcp_summary(incident_id: str) -> str:
    return f"MCP evidence unavailable for incident {incident_id}."


def _mcp_summary(evidence: Evidence | None) -> str | None:
    if not evidence:
        return None
    return f"MCP client call: {_format_mcp_evidence_summary(evidence)}"


def _apply_investigation_result(
    incident: Incident,
    result: Any,
    *,
    mcp_evidence: Evidence | None,
    mcp_evidence_summary: str | None,
) -> None:
    incident.status = "COMPLETED"
    incident.severity = result.severity
    incident.root_cause = result.root_cause
    incident.confidence_score = result.confidence_score
    incident.evidence_summary = result.evidence_summary
    incident.ai_summary = result.ai_summary
    incident.llm_provider = result.source
    incident.mcp_evidence_summary = mcp_evidence_summary
    incident.mcp_investigation = mcp_evidence is not None or bool(
        getattr(result, "mcp_investigation", False)
    )
    incident.mcp_tools_used = list(
        dict.fromkeys(getattr(result, "mcp_tools_used", []) or [])
    )
    incident.spl_queries_used = list(
        dict.fromkeys(getattr(result, "spl_queries_used", []) or [])
    )
    incident.mcp_log_event_count = max(
        mcp_evidence.event_count if mcp_evidence else 0,
        int(getattr(result, "mcp_log_event_count", 0) or 0),
    )
    if mcp_evidence and "splunk_run_query" not in incident.mcp_tools_used:
        incident.mcp_tools_used.insert(0, "splunk_run_query")
    incident.recommended_actions = result.recommended_actions
    incident.safe_remediation_actions = result.safe_remediation_actions
    incident.updated_at = utc_now()


def _spl_query_context(
    *,
    incident: Incident,
    evidence: Evidence,
    raw_events: list[dict[str, Any]] | None = None,
    alert_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    service_filter = incident.service.replace('"', '\\"')
    incident_filter = incident.incident_id.replace('"', '\\"')
    queries = [
        (
            "index=main sourcetype=agentic-ops "
            f'(incident_id="{incident_filter}" OR service="{service_filter}") '
            "| stats count as event_count avg(latency_ms) as avg_latency_ms "
            "max(latency_ms) as max_latency_ms max(cpu_pct) as max_cpu_pct "
            "max(db_connection_pool_pct) as max_db_pool_pct by service host endpoint error_type"
        )
    ]
    return {
        "preferred_index": "main",
        "preferred_sourcetype": "agentic-ops",
        "seed_queries": queries,
        "python_mcp_evidence": evidence.model_dump(mode="json"),
        "raw_events": (raw_events or [])[:10],
        "alert_payload": alert_payload or {},
    }


def _investigation_record(
    incident: Incident,
    result: Any,
    *,
    mcp_evidence: Evidence | None,
    mcp_evidence_summary: str | None,
    evidence_source: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    record = result.model_dump(mode="json")
    record.update(
        {
            "timestamp": _timestamp(),
            "status": "COMPLETED",
            "incident_status": incident.status,
            "investigation_status": "COMPLETED",
            "llm_provider": incident.llm_provider,
            "investigation_source": incident.llm_provider,
            "mcp_investigation": incident.mcp_investigation,
            "mcp_evidence_summary": mcp_evidence_summary,
            "mcp_tools_used": incident.mcp_tools_used,
            "spl_queries_used": incident.spl_queries_used,
            "mcp_log_event_count": incident.mcp_log_event_count,
            "evidence_source": evidence_source,
            "mcp_evidence_source": "splunk_mcp_client_call" if mcp_evidence else None,
            "source": incident.llm_provider,
            "sourcetype": "aiops-investigations",
        }
    )
    if extra:
        record.update(extra)
    return record


def _has_approval_ready_rca(incident: Incident) -> bool:
    return bool(
        incident.status not in {"OPEN"}
        and incident.root_cause
        and incident.confidence_score is not None
        and incident.recommended_actions
        and incident.evidence_summary
    )


def _maybe_codex_enhancement(
    *,
    alert_name: str,
    incident: Incident,
    evidence: Evidence,
    raw_events: list[dict[str, Any]],
    alert_payload: dict[str, Any] | None = None,
) -> Any:
    agent = CodexRcaAgent()
    try:
        return agent.analyze_with_splunk_mcp(
            alert_name=alert_name,
            incident=incident,
            spl_query_context=_spl_query_context(
                incident=incident,
                evidence=evidence,
                raw_events=raw_events,
                alert_payload=alert_payload,
            ),
        )
    except Exception as exc:
        try:
            result = agent.analyze(
                alert_name=alert_name,
                incident=incident,
                evidence=evidence,
                raw_events=raw_events,
            )
            if getattr(result, "source", "") in {
                "rules_fallback",
                "rules_fallback_after_ai_unavailable",
            }:
                result.source = "fallback_alternative_after_codex_unavailable"
            if not result.ai_summary:
                result.ai_summary = (
                    f"RCA for {incident.service}: root cause appears to be {result.root_cause}. "
                    f"Confidence {result.confidence_score:.2f}. {result.evidence_summary}"
                )
            result.raw_response = (
                (result.raw_response or "")
                + f"\nCodex MCP enhancement failed: {str(exc)[:500]}"
            ).strip()
            return result
        except Exception:
            result = decide_investigation(
                evidence, source="fallback_alternative_after_codex_failure"
            )
            result.ai_summary = (
                f"Mandatory Codex reasoning failed, so deterministic RCA was used for continuity. "
                f"RCA for {incident.service}: root cause appears to be {result.root_cause}. "
                f"Confidence {result.confidence_score:.2f}. {result.evidence_summary}"
            )
            result.raw_response = f"Mandatory Codex reasoning failed: {str(exc)[:500]}"
            return result


async def _persist_ai_triage_record(
    *,
    incident: Incident,
    alert_name: str,
    host: str,
    summary_text: str,
    alert_payload: dict[str, Any],
    hec_status: dict[str, str],
    mcp_tool_used: bool,
    mcp_log_event_count: int,
) -> None:
    expanded_summary = _explanatory_ai_summary(
        alert_name=alert_name, incident=incident, summary_text=summary_text
    )
    write_ai_triage_event(
        {
            "timestamp": _timestamp(),
            "incident_id": incident.incident_id,
            "service": incident.service,
            "status": incident.status,
            "severity": incident.severity,
            "root_cause": incident.root_cause,
            "confidence_score": incident.confidence_score,
            "evidence_summary": incident.evidence_summary,
            "ai_summary": expanded_summary,
            "ai_reasoning": expanded_summary,
            "llm_provider": incident.llm_provider,
            "mcp_evidence_summary": incident.mcp_evidence_summary,
            "original_alert": alert_name,
            "target_host": host,
            "mcp_investigation": mcp_tool_used,
            "mcp_tools_used": incident.mcp_tools_used,
            "spl_queries_used": incident.spl_queries_used,
            "mcp_log_event_count": mcp_log_event_count,
            "hec_status": hec_status,
            "alert_payload": alert_payload,
            "source": incident.llm_provider or "rules_fallback",
            "sourcetype": AI_TRIAGE_SOURCETYPE,
        }
    )


def _apply_remediation_outcome(
    incident: Incident,
    *,
    status: str,
    remediation_status: str,
    action: str,
    result: str,
    approved_by: str | None = None,
) -> Incident:
    incident.status = status  # type: ignore[assignment]
    incident.remediation_status = remediation_status
    incident.remediation_result = result
    if approved_by is not None:
        incident.approved_by = approved_by
    incident.updated_at = utc_now()
    upsert_incident(incident)
    write_incident_event(
        {
            "timestamp": _timestamp(),
            "incident_id": incident.incident_id,
            "service": incident.service,
            "status": incident.status,
            "severity": incident.severity,
            "root_cause": incident.root_cause,
            "approved_by": incident.approved_by,
            "incident_status": incident.status,
            "remediation_status": incident.remediation_status,
            "remediation_result": incident.remediation_result,
            "action": action,
            "sourcetype": "aiops-incidents",
        }
    )
    write_remediation_event(
        {
            "timestamp": _timestamp(),
            "incident_id": incident.incident_id,
            "service": incident.service,
            "status": incident.status,
            "severity": incident.severity,
            "root_cause": incident.root_cause,
            "remediation_status": incident.remediation_status,
            "approved_by": incident.approved_by,
            "evidence_summary": incident.evidence_summary,
            "mcp_evidence_summary": incident.mcp_evidence_summary,
            "investigation_status": incident.status,
            "mcp_investigation": incident.mcp_investigation,
            "mcp_tools_used": incident.mcp_tools_used,
            "spl_queries_used": incident.spl_queries_used,
            "mcp_log_event_count": incident.mcp_log_event_count,
            "action": action,
            "mode": "simulate",
            "result": incident.remediation_result,
            "sourcetype": "aiops-remediation",
        }
    )
    _write_timeline(incident, action, details={"result": incident.remediation_result})
    return incident


def _wants_html(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    return "text/html" in accept and "application/json" not in accept


def _incident_action_urls(request: Request, incident_id: str) -> dict[str, str]:
    return {
        "investigate": str(
            request.url_for("investigate_incident", incident_id=incident_id)
        ),
        "approve": str(request.url_for("approve_incident", incident_id=incident_id)),
        "execute": str(request.url_for("execute_remediation", incident_id=incident_id)),
        "reject": str(request.url_for("reject_remediation", incident_id=incident_id)),
        "close": str(request.url_for("close_incident", incident_id=incident_id)),
    }


def _count_by_field(events: list[dict[str, Any]], field: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for event in events:
        value = str(event.get(field) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: item[1], reverse=True)[:8])


def _noise_reduction_summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(events)
    signal_events = 0
    for event in events:
        try:
            status_code = int(event.get("status_code") or 0)
            latency_ms = float(event.get("latency_ms") or 0)
        except (TypeError, ValueError):
            status_code = 0
            latency_ms = 0
        error_type = str(event.get("error_type") or "null")
        if status_code >= 500 or error_type != "null" or latency_ms >= 1000:
            signal_events += 1
    noise_events = max(total - signal_events, 0)
    reduction_pct = round((noise_events / total) * 100, 2) if total else 0
    return {
        "total_events": total,
        "signal_events": signal_events,
        "noise_events": noise_events,
        "noise_reduction": f"{reduction_pct}%",
        "method": "Noise is filtered when status_code is below 500, error_type is null, and latency_ms is below 1000. Remaining events are treated as investigation signals.",
    }


def _recent_events(filename: str, limit: int = 6) -> list[dict[str, Any]]:
    events = load_jsonl_events(filename, limit=200)
    return sorted(
        events,
        key=lambda item: str(item.get("timestamp") or ""),
        reverse=True,
    )[:limit]


def _latest_incident_events(
    events: list[dict[str, Any]], limit: int = 6
) -> list[dict[str, Any]]:
    by_incident: dict[str, dict[str, Any]] = {}
    for event in sorted(events, key=lambda item: str(item.get("timestamp") or "")):
        incident_id = str(event.get("incident_id") or "")
        if incident_id and incident_id != "none":
            by_incident[incident_id] = event
    return sorted(
        by_incident.values(),
        key=lambda item: str(item.get("timestamp") or ""),
        reverse=True,
    )[:limit]


def _dashboard_payload(request: Request) -> dict[str, object]:
    incidents = list(load_incidents().values())
    page_size = 5
    page = _dashboard_page_number(request)
    by_status: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for incident in incidents:
        by_status[incident.status] = by_status.get(incident.status, 0) + 1
        by_severity[incident.severity] = by_severity.get(incident.severity, 0) + 1

    sorted_incidents = sorted(incidents, key=lambda item: item.updated_at, reverse=True)
    total_pages = max(1, math.ceil(len(sorted_incidents) / page_size))
    page = min(page, total_pages)
    start = (page - 1) * page_size
    end = start + page_size
    recent_incidents = []
    for incident in sorted_incidents[start:end]:
        item = incident.model_dump(mode="json")
        item["action_urls"] = _incident_action_urls(request, incident.incident_id)
        recent_incidents.append(item)
    primary_incident = recent_incidents[0] if recent_incidents else None

    def _page_url(target_page: int) -> str:
        base = str(request.url.replace_query_params(page=target_page))
        return base

    app_events = load_jsonl_events("app.log", limit=500)
    investigation_events = load_jsonl_events("aiops_investigations.log", limit=500)
    remediation_events = load_jsonl_events("aiops_remediation.log", limit=500)
    timeline_events = load_jsonl_events("timeline.log", limit=500)
    metric_events = load_jsonl_events("mcp_metrics.log", limit=500)
    ai_activity_events = load_jsonl_events("splunk_ai_activity.log", limit=500)

    return {
        "total_incidents": len(incidents),
        "page_size": page_size,
        "current_page": page,
        "total_pages": total_pages,
        "page_start": start + 1 if recent_incidents else 0,
        "page_end": min(end, len(sorted_incidents)),
        "by_status": by_status,
        "by_severity": by_severity,
        "recent_incidents": recent_incidents,
        "primary_incident": primary_incident,
        "prev_page_url": _page_url(page - 1) if page > 1 else None,
        "next_page_url": _page_url(page + 1) if page < total_pages else None,
        "noise_reduction": _noise_reduction_summary(app_events),
        "correlated_incidents": _recent_events("correlation.log"),
        "top_root_causes": _count_by_field(
            [event for event in investigation_events if event.get("root_cause")],
            "root_cause",
        ),
        "mcp_investigation_results": _latest_incident_events(investigation_events),
        "remediation_status": _count_by_field(remediation_events, "remediation_status"),
        "incident_timeline": _recent_events("timeline.log", limit=8)
        or _recent_events("incidents.log", limit=8),
        "mcp_tool_usage": _count_by_field(metric_events, "mcp_tool_usage"),
        "confidence_scores": _latest_incident_events(investigation_events),
        "investigation_source": _count_by_field(
            investigation_events, "investigation_source"
        ),
        "splunk_ai_activity": _latest_incident_events(ai_activity_events),
        "mcp_metrics": {
            "query_count": sum(int(event.get("mcp_query_count") or 0) for event in metric_events),
            "success_count": sum(int(event.get("mcp_success_count") or 0) for event in metric_events),
            "failure_count": sum(int(event.get("mcp_failure_count") or 0) for event in metric_events),
            "average_investigation_time_ms": round(
                (
                    sum(float(event.get("average_investigation_time") or 0) for event in metric_events)
                    / len(metric_events)
                ),
                2,
            )
            if metric_events
            else 0,
        },
        "last_updated": _timestamp(),
    }


def _status_counts(counts: dict[str, int]) -> str:
    if not counts:
        return "None"
    return ", ".join(
        f"{escape(status)}: {count}" for status, count in sorted(counts.items())
    )


def _action_button(label: str, url: str, disabled: bool = False) -> str:
    disabled_attr = " disabled" if disabled else ""
    class_attr = f' class="action-{label.lower()}"'
    return (
        f'<form method="post" action="{escape(url)}" target="_blank">'
        f'<button type="submit"{class_attr}{disabled_attr}>{escape(label)}</button>'
        "</form>"
    )


def _render_counts(counts: object, empty: str = "None") -> str:
    if not isinstance(counts, dict) or not counts:
        return f"<p>{escape(empty)}</p>"
    items = "".join(
        f"<li><span>{escape(str(key))}</span><strong>{escape(str(value))}</strong></li>"
        for key, value in counts.items()
    )
    return f'<ul class="kv-list">{items}</ul>'


def _event_value(event: dict[str, Any], *fields: str, default: str = "") -> str:
    for field in fields:
        value = event.get(field)
        if isinstance(value, list):
            items = [str(item) for item in value if item not in {None, ""}]
            if items:
                return ", ".join(items)
        elif value not in {None, ""}:
            return str(value)
    return default


def _event_detail_values(event: dict[str, Any], fields: tuple[str, ...]) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for field in fields:
        value = _event_value(event, field)
        if not value or value in seen:
            continue
        seen.add(value)
        values.append(value)
    return values


def _render_event_list(events: object, fields: tuple[str, ...], empty: str) -> str:
    if not isinstance(events, list) or not events:
        return f"<p>{escape(empty)}</p>"
    rows = []
    for event in events[:6]:
        if not isinstance(event, dict):
            continue
        title = _event_value(event, "incident_id", "event", "mcp_tool_usage", default="event")
        detail_values = _event_detail_values(event, fields)
        detail = " | ".join(detail_values)
        rows.append(
            "<li>"
            f"<strong>{escape(title)}</strong>"
            f"<span>{escape(detail)}</span>"
            "</li>"
        )
    return f'<ul class="event-list">{"".join(rows)}</ul>' if rows else f"<p>{escape(empty)}</p>"


def _table_text_cell(value: object, empty: str = "", preview_chars: int = 130) -> str:
    text = str(value or empty)
    preview = text if len(text) <= preview_chars else text[:preview_chars].rsplit(" ", 1)[0] + "."
    details = (
        "<details>"
        '<summary>More</summary>'
        f'<div class="cell-full">{escape(text)}</div>'
        "</details>"
        if len(text) > preview_chars
        else ""
    )
    return (
        f'<div class="cell-text" title="{escape(text)}">'
        f"{escape(preview)}"
        f"{details}"
        "</div>"
    )


def _dashboard_page_number(request: Request) -> int:
    raw_page = request.query_params.get("page", "1")
    try:
        page = int(raw_page)
    except (TypeError, ValueError):
        return 1
    return max(page, 1)


def _render_dashboard(payload: dict[str, object]) -> str:
    incidents = payload["recent_incidents"]
    primary_incident = payload.get("primary_incident")
    prev_page_url = payload.get("prev_page_url")
    next_page_url = payload.get("next_page_url")
    current_page = int(payload.get("current_page", 1) or 1)
    total_pages = int(payload.get("total_pages", 1) or 1)
    page_start = int(payload.get("page_start", 0) or 0)
    page_end = int(payload.get("page_end", 0) or 0)
    rows = []
    for incident in incidents if isinstance(incidents, list) else []:
        if not isinstance(incident, dict):
            continue
        incident_id = str(incident.get("incident_id", ""))
        status = str(incident.get("status", ""))
        remediation_status = str(incident.get("remediation_status") or "")
        can_approve = status in {"INVESTIGATED", "COMPLETED"}
        has_rca = bool(
            incident.get("root_cause")
            and incident.get("confidence_score") is not None
            and incident.get("recommended_actions")
            and incident.get("evidence_summary")
        )
        can_reject = status not in {"CLOSED", "REJECTED"}
        can_execute = status == "APPROVED"
        can_close = status == "EXECUTED" and remediation_status != "TICKET CLOSED"
        action_urls = incident.get("action_urls", {})
        if not isinstance(action_urls, dict):
            action_urls = {}
        table_ai_summary = str(incident.get("ai_summary") or "")
        if table_ai_summary and "Reasoning:" not in table_ai_summary:
            actions = incident.get("recommended_actions") or []
            if isinstance(actions, list) and actions:
                action_text = "; ".join(str(item) for item in actions[:2])
            else:
                action_text = "click Investigate for full detail analysis and recommended remediation"
            table_ai_summary = (
                f"{table_ai_summary} Reasoning: this summary interprets the evidence rather than repeating it. "
                f"MCP supplied {incident.get('mcp_log_event_count') or 0} correlated events; "
                f"confidence is {incident.get('confidence_score') or 0}. "
                f"Remediation action: {action_text}. Click Investigate for full detail analysis on the incident."
            )
        remediation_class = " remediation open" if remediation_status == "OPEN" else " remediation"
        rows.append(
            "<tr>"
            f"<td>{escape(incident_id)}</td>"
            f"<td>{escape(str(incident.get('service', '')))}</td>"
            f'<td><span class="severity-pill">{escape(str(incident.get("severity", "")))}</span></td>'
            f'<td><span class="status-pill{remediation_class}">{escape(str(incident.get("remediation_status") or ""))}</span></td>'
            f"<td>{_table_text_cell(incident.get('root_cause'), 'Pending investigation')}"
            f"<br><small>{escape(str(incident.get('llm_provider') or 'pending'))}; "
            f"MCP={escape(str(incident.get('mcp_investigation') or False))}; "
            f"events={escape(str(incident.get('mcp_log_event_count') or 0))}</small></td>"
            f"<td>{_table_text_cell(incident.get('mcp_evidence_summary'), 'No MCP evidence yet', 110)}</td>"
            f"<td>{_table_text_cell(table_ai_summary, 'No AI summary yet. Click Investigate for full detail analysis on the incident.', 125)}</td>"
            f'<td class="actions">'
            f"{_action_button('Investigate', str(action_urls.get('investigate', '')), status == 'CLOSED')}"
            f"{_action_button('Approve', str(action_urls.get('approve', '')), not (can_approve and has_rca))}"
            f"{_action_button('Execute', str(action_urls.get('execute', '')), not can_execute)}"
            f"{_action_button('Reject', str(action_urls.get('reject', '')), not can_reject)}"
            f"{_action_button('Close', str(action_urls.get('close', '')), not can_close)}"
            "</td>"
            "</tr>"
        )

    table_body = "\n".join(rows) or '<tr><td colspan="8">No incidents yet.</td></tr>'
    by_status = payload.get("by_status", {})
    by_severity = payload.get("by_severity", {})
    status_text = _status_counts(by_status if isinstance(by_status, dict) else {})
    severity_text = _status_counts(by_severity if isinstance(by_severity, dict) else {})
    last_updated = escape(str(payload.get("last_updated", "")))
    noise = payload.get("noise_reduction", {})
    if not isinstance(noise, dict):
        noise = {}
    mcp_metrics = payload.get("mcp_metrics", {})
    if not isinstance(mcp_metrics, dict):
        mcp_metrics = {}
    action_toolbar = "<p>No incidents available.</p>"
    pagination = ""
    if isinstance(primary_incident, dict):
        action_urls = primary_incident.get("action_urls", {})
        if not isinstance(action_urls, dict):
            action_urls = {}
        primary_status = str(primary_incident.get("status", ""))
        primary_remediation_status = str(primary_incident.get("remediation_status") or "")
        can_approve = primary_status in {"INVESTIGATED", "COMPLETED"}
        has_rca = bool(
            primary_incident.get("root_cause")
            and primary_incident.get("confidence_score") is not None
            and primary_incident.get("recommended_actions")
            and primary_incident.get("evidence_summary")
        )
        can_reject = primary_status not in {"CLOSED", "REJECTED"}
        can_execute = primary_status == "APPROVED"
        can_close = (
            primary_status == "EXECUTED"
            and primary_remediation_status != "TICKET CLOSED"
        )
        action_toolbar = (
            '<div class="incident-toolbar">'
            f'<div class="incident-toolbar__label">Incident actions for '
            f'{escape(str(primary_incident.get("incident_id", "")))}'
            f' / {escape(str(primary_incident.get("service", "")))}'
            "</div>"
            '<div class="actions">'
            f"{_action_button('Investigate', str(action_urls.get('investigate', '')), primary_status == 'CLOSED')}"
            f"{_action_button('Approve', str(action_urls.get('approve', '')), not (can_approve and has_rca))}"
            f"{_action_button('Execute', str(action_urls.get('execute', '')), not can_execute)}"
            f"{_action_button('Reject', str(action_urls.get('reject', '')), not can_reject)}"
            f"{_action_button('Close', str(action_urls.get('close', '')), not can_close)}"
            "</div>"
            "</div>"
        )
    if page_start and page_end:
        prev_html = (
            f'<a class="page-link" href="{escape(str(prev_page_url))}">Previous</a>'
            if prev_page_url
            else '<span class="page-link disabled">Previous</span>'
        )
        next_html = (
            f'<a class="page-link" href="{escape(str(next_page_url))}">Next</a>'
            if next_page_url
            else '<span class="page-link disabled">Next</span>'
        )
        pagination = (
            '<div class="pagination">'
            f"<span>Showing {page_start}-{page_end} of {payload.get('total_incidents', 0)} incidents</span>"
            f"<span>Page {current_page} of {total_pages}</span>"
            f"{prev_html}{next_html}"
            "</div>"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta http-equiv="refresh" content="15">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Agentic Ops Dashboard</title>
  <style>
    body {{ margin: 0; font-family: Arial, sans-serif; background: #f6f7f9; color: #17202a; }}
    main {{ max-width: 1180px; margin: 0 auto; padding: 32px 20px; }}
    h1 {{ font-size: 28px; margin: 0 0 20px; }}
    h2 {{ font-size: 15px; margin: 0 0 10px; text-transform: uppercase; color: #405166; }}
    .page-head {{ display: flex; justify-content: space-between; align-items: baseline; gap: 12px; flex-wrap: wrap; }}
    .updated {{ color: #5f6b7a; font-size: 13px; }}
    .summary {{ display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; margin-bottom: 22px; }}
    .metric {{ background: #fff; border: 1px solid #d9dee5; border-radius: 8px; padding: 14px; }}
    .metric strong {{ display: block; font-size: 24px; margin-bottom: 6px; }}
    .panel-grid {{ display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; margin: 0 0 22px; }}
    .panel {{ background: #fff; border: 1px solid #d9dee5; border-radius: 8px; padding: 14px; min-height: 120px; }}
    .kv-list, .event-list {{ list-style: none; margin: 0; padding: 0; display: grid; gap: 8px; }}
    .kv-list li {{ display: flex; justify-content: space-between; gap: 12px; border-bottom: 1px solid #eef1f5; padding-bottom: 6px; }}
    .kv-list strong {{ font-size: 14px; }}
    .event-list li {{ border-bottom: 1px solid #eef1f5; padding-bottom: 8px; }}
    .event-list strong {{ display: block; font-size: 14px; margin-bottom: 3px; }}
    .event-list span, .panel p {{ color: #5f6b7a; font-size: 13px; line-height: 1.35; }}
    .incident-toolbar {{ display: flex; flex-wrap: wrap; justify-content: space-between; gap: 12px; align-items: center; background: #fff; border: 1px solid #d9dee5; border-radius: 8px; padding: 12px 14px; margin-bottom: 12px; }}
    .incident-toolbar__label {{ font-weight: 700; color: #17202a; }}
    .pagination {{ display: flex; flex-wrap: wrap; justify-content: space-between; gap: 12px; align-items: center; margin: 0 0 10px; color: #5f6b7a; font-size: 13px; }}
    .page-link {{ color: #1f6feb; text-decoration: none; font-weight: 700; }}
    .page-link.disabled {{ color: #97a1af; pointer-events: none; }}
    .table-wrap {{ width: 100%; overflow-x: hidden; resize: horizontal; min-width: 720px; max-width: 100%; border: 1px solid #d9dee5; background: #fff; }}
    table {{ width: 100%; border-collapse: collapse; table-layout: fixed; background: #fff; }}
    th, td {{ padding: 8px 10px; border-bottom: 1px solid #e5e8ed; text-align: left; vertical-align: top; font-size: 13px; }}
    th {{ background: #eef1f5; font-size: 13px; text-transform: uppercase; resize: horizontal; overflow: auto; min-width: 72px; }}
    th:nth-child(1), td:nth-child(1) {{ width: 13%; }}
    th:nth-child(2), td:nth-child(2) {{ width: 9%; }}
    th:nth-child(3), td:nth-child(3) {{ width: 8%; }}
    th:nth-child(4), td:nth-child(4) {{ width: 11%; }}
    th:nth-child(5), td:nth-child(5) {{ width: 16%; }}
    th:nth-child(6), td:nth-child(6) {{ width: 16%; }}
    th:nth-child(7), td:nth-child(7) {{ width: 17%; }}
    th:nth-child(8), td:nth-child(8) {{ width: 10%; }}
    td:nth-child(5) small {{ color: #5f6b7a; font-size: 12px; line-height: 1.2; }}
    .cell-text {{ overflow-wrap: anywhere; line-height: 1.3; }}
    .cell-text details {{ margin-top: 3px; }}
    .cell-text summary {{ color: #1f6feb; cursor: pointer; font-weight: 700; list-style: none; }}
    .cell-text summary::-webkit-details-marker {{ display: none; }}
    .cell-full {{ margin-top: 4px; color: #334155; }}
    .actions {{ display: flex; flex-wrap: wrap; gap: 6px; min-width: 0; }}
    .status-pill, .severity-pill {{ display: inline-block; max-width: 100%; border-radius: 4px; padding: 3px 6px; background: #eef1f5; color: #17202a; font-weight: 700; font-size: 12px; line-height: 1.2; overflow-wrap: anywhere; }}
    .status-pill.remediation {{ background: #f4f1e8; }}
    .status-pill.remediation.open {{ font-weight: 900; color: #7a3e00; border: 1px solid #f2c36b; }}
    form {{ margin: 0; }}
    button {{ appearance: none; border: 1px solid #1f6feb; background: #1f6feb; color: #fff; border-radius: 6px; padding: 6px 8px; cursor: pointer; white-space: nowrap; font-size: 12px; }}
    button.action-close {{ border-color: #0f766e; background: #e6fffb; color: #134e4a; font-weight: 700; }}
    button:disabled {{ border-color: #c2c8d0; background: #e1e5ea; color: #6b7280; cursor: default; }}
    button.action-close:disabled {{ border-color: #99cfc8; background: #f0fffc; color: #4b807a; }}
    @media (max-width: 760px) {{
      .summary {{ grid-template-columns: 1fr; }}
      .panel-grid {{ grid-template-columns: 1fr; }}
      .table-wrap {{ min-width: 100%; }}
    }}
  </style>
</head>
<body>
  <main>
    <div class="page-head">
      <h1>Agentic Ops Dashboard</h1>
      <div class="updated">Last updated {last_updated}</div>
    </div>
    <section class="summary">
      <div class="metric"><strong>{payload.get("total_incidents", 0)}</strong>Total incidents</div>
      <div class="metric"><strong>Status</strong>{status_text}</div>
      <div class="metric"><strong>Severity</strong>{severity_text}</div>
    </section>
    <section class="panel-grid">
      <div class="panel"><h2>Noise Reduction</h2><p>Filters routine successful low-latency events before RCA. Signal remains when HTTP status is 500 or higher, error_type is present, or latency reaches 1000 ms.</p>{_render_counts(noise)}</div>
      <div class="panel"><h2>Correlated Incidents</h2>{_render_event_list(payload.get("correlated_incidents"), ("service", "incident_class", "correlation_score", "window"), "No correlation events yet.")}</div>
      <div class="panel"><h2>Top Root Causes</h2>{_render_counts(payload.get("top_root_causes"))}</div>
      <div class="panel"><h2>MCP Investigation Results</h2><p>Click Investigate for full detail analysis on the selected incident, including MCP tools, evidence, AI summary, and remediation actions.</p>{_render_event_list(payload.get("mcp_investigation_results"), ("service", "root_cause", "mcp_tools_used", "mcp_evidence_summary"), "No MCP investigations yet.")}</div>
      <div class="panel"><h2>Remediation Status</h2>{_render_counts(payload.get("remediation_status"))}</div>
      <div class="panel"><h2>Incident Timeline</h2>{_render_event_list(payload.get("incident_timeline"), ("event", "service", "status", "action"), "No timeline events yet.")}</div>
      <div class="panel"><h2>MCP Tool Usage</h2>{_render_counts(payload.get("mcp_tool_usage"))}</div>
      <div class="panel"><h2>Confidence Scores</h2>{_render_event_list(payload.get("confidence_scores"), ("service", "root_cause", "confidence_score"), "No confidence scores yet.")}</div>
      <div class="panel"><h2>Investigation Source</h2>{_render_counts(payload.get("investigation_source"))}</div>
      <div class="panel"><h2>MCP Metrics</h2>{_render_counts(mcp_metrics)}</div>
    </section>
    {action_toolbar}
    {pagination}
    <div class="table-wrap">
    <table>
      <thead>
        <tr><th>Incident</th><th>Service</th><th>Severity</th><th>Remediation</th><th>Root Cause</th><th>MCP Evidence</th><th>AI Summary</th><th>Actions</th></tr>
      </thead>
      <tbody>
        {table_body}
      </tbody>
    </table>
    </div>
  </main>
</body>
</html>"""


def _render_action_result(action: str, incident: Incident) -> HTMLResponse:
    root_cause = incident.root_cause or "Pending"
    evidence_summary = incident.evidence_summary or _fallback_mcp_summary(
        incident.incident_id
    )
    ai_summary = (
        incident.ai_summary or incident.evidence_summary or "No AI summary available."
    )
    mcp_evidence_summary = (
        incident.mcp_evidence_summary or "No MCP evidence summary available."
    )
    mcp_tools = ", ".join(incident.mcp_tools_used) or "None"
    spl_queries = "; ".join(incident.spl_queries_used) or "None"
    recommended_actions = (
        "".join(f"<li>{escape(item)}</li>" for item in incident.recommended_actions)
        or "<li>None</li>"
    )
    safe_actions = (
        "".join(
            f"<li>{escape(item)}</li>" for item in incident.safe_remediation_actions
        )
        or "<li>None</li>"
    )
    title = f"{escape(action)} completed"
    if action == "Investigation" and not incident.mcp_evidence_summary:
        title = "Investigation started"
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(action)} Result</title>
  <style>
    body {{ margin: 0; font-family: Arial, sans-serif; background: #f6f7f9; color: #17202a; }}
    main {{ max-width: 900px; margin: 0 auto; padding: 28px 20px; }}
    .panel {{ background: #fff; border: 1px solid #d9dee5; border-radius: 8px; padding: 18px; }}
    h1 {{ font-size: 24px; margin: 0 0 14px; }}
    dl {{ display: grid; grid-template-columns: 180px 1fr; gap: 8px 12px; }}
    dt {{ font-weight: 700; }}
    dd {{ margin: 0; }}
    a {{ color: #1f6feb; }}
  </style>
  <script>
    window.addEventListener("load", function () {{
      if (window.opener && !window.opener.closed) {{
        setTimeout(function () {{
          try {{
            window.opener.location.reload();
          }} catch (error) {{}}
        }}, 1500);
      }}
    }});
  </script>
</head>
<body>
  <main>
    <div class="panel">
      <h1>{title}</h1>
      <dl>
        <dt>Incident</dt><dd>{escape(incident.incident_id)}</dd>
        <dt>Service</dt><dd>{escape(incident.service)}</dd>
        <dt>Status</dt><dd>{escape(incident.status)}</dd>
        <dt>Severity</dt><dd>{escape(incident.severity)}</dd>
        <dt>Root cause</dt><dd>{escape(root_cause)}</dd>
        <dt>Confidence</dt><dd>{incident.confidence_score if incident.confidence_score is not None else "Pending"}</dd>
        <dt>Remediation status</dt><dd>{escape(str(incident.remediation_status or "Pending"))}</dd>
        <dt>LLM provider</dt><dd>{escape(str(incident.llm_provider or "Pending"))}</dd>
        <dt>MCP investigation</dt><dd>{escape(str(incident.mcp_investigation))}</dd>
        <dt>MCP tools used</dt><dd>{escape(mcp_tools)}</dd>
        <dt>MCP log events</dt><dd>{incident.mcp_log_event_count}</dd>
        <dt>SPL queries used</dt><dd>{escape(spl_queries)}</dd>
        <dt>AI summary</dt><dd>{escape(ai_summary)}</dd>
        <dt>Evidence</dt><dd>{escape(evidence_summary)}</dd>
        <dt>MCP evidence</dt><dd>{escape(mcp_evidence_summary)}</dd>
      </dl>
      <h2>Recommended actions</h2>
      <ul>{recommended_actions}</ul>
      <h2>Safe remediation actions</h2>
      <ul>{safe_actions}</ul>
      <p><a href="/dashboard">Open FastAPI dashboard</a></p>
    </div>
  </main>
</body>
</html>"""
    return HTMLResponse(html)


def _write_preliminary_investigation_event(incident: Incident) -> None:
    write_investigation_event(
        {
            "timestamp": _timestamp(),
            "incident_id": incident.incident_id,
            "service": incident.service,
            "status": "STARTED",
            "incident_status": incident.status,
            "severity": incident.severity,
            "root_cause": incident.root_cause,
            "confidence_score": incident.confidence_score,
            "evidence_summary": "Investigation started; awaiting Splunk MCP evidence.",
            "investigation_status": "STARTED",
            "mcp_investigation": False,
            "mcp_evidence_summary": None,
            "evidence_source": "investigation_started",
            "mcp_evidence_source": None,
            "sourcetype": "aiops-investigations",
        }
    )


async def _finalize_investigation_state(incident_id: str) -> None:
    incident = load_incidents().get(incident_id)
    if not incident:
        return

    mcp_client = SplunkMCPClient()
    mcp_evidence: Evidence | None = None
    fallback_reason: str | None = None
    try:
        mcp_evidence = await mcp_client.query_incident_evidence(
            incident.incident_id, incident.service
        )
    except Exception as exc:
        fallback_reason = f"splunk_mcp_query_failed: {exc}"

    evidence = mcp_evidence or _fallback_evidence(incident)
    mcp_evidence_summary = _mcp_summary(mcp_evidence)
    if mcp_evidence:
        result = build_fallback_rca_from_mcp_evidence(
            mcp_evidence,
            source="rules_fallback_after_ai_unavailable",
        )
        _apply_investigation_result(
            incident,
            result,
            mcp_evidence=mcp_evidence,
            mcp_evidence_summary=mcp_evidence_summary,
        )
        upsert_incident(incident)
        write_investigation_event(
            _investigation_record(
                incident,
                result,
                mcp_evidence=mcp_evidence,
                mcp_evidence_summary=mcp_evidence_summary,
                evidence_source="python_mcp_client_rules_fallback",
            )
        )
        _write_correlation_from_evidence(
            incident,
            mcp_evidence,
            incident_class=result.root_cause,
            source="splunk_mcp_evidence",
        )
        await _record_splunk_ai_assistant_activity(mcp_client, incident, mcp_evidence)

        codex_result = await asyncio.to_thread(
            _maybe_codex_enhancement,
            alert_name=f"incident:{incident.incident_id}",
            incident=incident,
            evidence=mcp_evidence,
            raw_events=[],
            alert_payload={
                "incident_id": incident.incident_id,
                "service": incident.service,
                "source": "manual_investigation",
            },
        )
        if codex_result and codex_result.root_cause and codex_result.evidence_summary:
            result = codex_result
            _apply_investigation_result(
                incident,
                result,
                mcp_evidence=mcp_evidence,
                mcp_evidence_summary=mcp_evidence_summary,
            )
    else:
        result = decide_investigation(evidence, source="rules_fallback_mcp_unavailable")
        _apply_investigation_result(
            incident,
            result,
            mcp_evidence=None,
            mcp_evidence_summary=None,
        )
        codex_result = await asyncio.to_thread(
            _maybe_codex_enhancement,
            alert_name=f"incident:{incident.incident_id}",
            incident=incident,
            evidence=evidence,
            raw_events=[],
            alert_payload={
                "incident_id": incident.incident_id,
                "service": incident.service,
                "source": "manual_investigation",
            },
        )
        if codex_result and codex_result.root_cause and codex_result.evidence_summary:
            result = codex_result
            _apply_investigation_result(
                incident,
                result,
                mcp_evidence=None,
                mcp_evidence_summary=None,
            )
        _write_correlation_from_evidence(
            incident,
            evidence,
            incident_class=result.root_cause,
            source="fallback_evidence",
        )
        await _record_splunk_ai_assistant_activity(mcp_client, incident, evidence)

    upsert_incident(incident)
    write_incident_event(
        {
            "timestamp": _timestamp(),
            "incident_id": incident.incident_id,
            "service": incident.service,
            "status": incident.status,
            "severity": incident.severity,
            "root_cause": incident.root_cause,
            "confidence_score": incident.confidence_score,
            "approved_by": incident.approved_by,
            "remediation_result": incident.remediation_result,
            "evidence_summary": incident.evidence_summary,
            "mcp_evidence_summary": incident.mcp_evidence_summary,
            "mcp_investigation": incident.mcp_investigation,
            "mcp_tools_used": incident.mcp_tools_used,
            "spl_queries_used": incident.spl_queries_used,
            "mcp_log_event_count": incident.mcp_log_event_count,
            "incident_status": incident.status,
            "investigation_status": "COMPLETED",
            "action": "investigation_completed",
            "sourcetype": "aiops-incidents",
        }
    )
    _write_timeline(
        incident,
        "investigation_completed",
        details={
            "evidence_source": (
                "splunk_mcp_evidence" if mcp_evidence else "fallback_evidence"
            ),
            "fallback_reason": fallback_reason,
        },
    )

    investigation_record = _investigation_record(
        incident,
        result,
        mcp_evidence=mcp_evidence,
        mcp_evidence_summary=incident.mcp_evidence_summary,
        evidence_source=(
            "correlated_observed_events" if mcp_evidence else "fallback_evidence"
        ),
        extra={"fallback_reason": fallback_reason} if fallback_reason else None,
    )

    ai_summary = incident.ai_summary or _format_ai_summary(
        incident.incident_id, incident
    )
    hec_status = await save_ai_summary_to_splunk(
        summary_text=ai_summary,
        host=incident.service,
        alert_name=f"incident:{incident.incident_id}",
        incident=incident,
        alert_payload={
            "incident_id": incident.incident_id,
            "service": incident.service,
            "source": "incident_investigation",
            "mcp_investigation": incident.mcp_investigation,
        },
    )
    await _persist_ai_triage_record(
        incident=incident,
        alert_name=f"incident:{incident.incident_id}",
        host=incident.service,
        summary_text=ai_summary,
        alert_payload={
            "incident_id": incident.incident_id,
            "service": incident.service,
            "source": "incident_investigation",
            "mcp_investigation": incident.mcp_investigation,
        },
        hec_status=hec_status,
        mcp_tool_used=incident.mcp_investigation,
        mcp_log_event_count=incident.mcp_log_event_count,
    )
    write_investigation_event(investigation_record)


async def _load_or_hydrate_incident(
    incident_id: str,
) -> tuple[Incident, Evidence | None]:
    incident = load_incidents().get(incident_id)
    if incident:
        return incident, None

    evidence = await SplunkMCPClient().query_incident_evidence(incident_id)
    incident = Incident(
        incident_id=incident_id,
        service=evidence.service if evidence else "checkout-api",
        source="mcp_hydrated" if evidence else "mcp_unavailable",
    )
    upsert_incident(incident)
    write_incident_event(
        {
            "timestamp": _timestamp(),
            "incident_id": incident.incident_id,
            "service": incident.service,
            "status": incident.status,
            "severity": incident.severity,
            "incident_status": incident.status,
            "action": "incident_hydrated",
            "sourcetype": "aiops-incidents",
        }
    )
    _write_timeline(incident, "incident_hydrated")
    return incident, evidence


async def _start_investigation_state(incident_id: str) -> Incident:
    incident, hydrated_evidence = await _load_or_hydrate_incident(incident_id)

    incident.status = "INVESTIGATED"
    incident.updated_at = utc_now()
    upsert_incident(incident)
    write_incident_event(
        {
            "timestamp": _timestamp(),
            "incident_id": incident.incident_id,
            "service": incident.service,
            "status": incident.status,
            "severity": incident.severity,
            "incident_status": incident.status,
            "investigation_status": "STARTED",
            "action": "investigation_started",
            "sourcetype": "aiops-incidents",
        }
    )
    _write_timeline(incident, "investigation_started")

    _write_preliminary_investigation_event(incident)
    return incident


async def _investigate_incident_state(incident_id: str) -> Incident:
    incident = await _start_investigation_state(incident_id)

    await _finalize_investigation_state(incident.incident_id)
    return load_incidents().get(incident_id) or incident


@app.get("/health")
async def health() -> dict[str, Any]:
    startup_verification = await _verify_startup_with_splunk_mcp()
    return {"status": "ok", "time": _timestamp(), **startup_verification}


@app.post("/incidents/create", response_model=Incident)
def create_incident(request: CreateIncidentRequest) -> Incident:
    incident_id = (
        inject_incident(request.incident_type) if request.inject_burst else None
    )
    service = INCIDENT_SERVICE_MAP.get(request.incident_type or "", request.service)
    incident = Incident(
        incident_id=incident_id or Incident(service=request.service).incident_id,
        service=service,
        severity=request.severity,
        source="telemetry_injection" if request.inject_burst else "manual_or_api",
    )
    upsert_incident(incident)
    write_incident_event(
        {
            "timestamp": _timestamp(),
            "incident_id": incident.incident_id,
            "service": incident.service,
            "status": incident.status,
            "severity": incident.severity,
            "approved_by": incident.approved_by,
            "incident_status": incident.status,
            "action": "incident_created",
            "sourcetype": "aiops-incidents",
        }
    )
    write_remediation_event(
        {
            "timestamp": _timestamp(),
            "incident_id": incident.incident_id,
            "service": incident.service,
            "status": incident.status,
            "remediation_status": "OPEN",
            "action": "incident_created",
            "mode": "simulate",
            "result": "pending_investigation",
        }
    )
    _write_timeline(incident, "incident_created")
    return incident


@app.post("/logs/generate")
def generate_logs(request: GenerateLogsRequest) -> dict[str, object]:
    for _ in range(request.count):
        write_event(normal_event())

    incident_id = (
        inject_incident(request.incident_type) if request.include_incident else None
    )
    return {
        "status": "ok",
        "generated_normal_events": request.count,
        "incident_id": incident_id,
        "log_path": "data/app.log",
    }


@app.post("/webhook/splunk-alert")
async def handle_splunk_alert(alert: SplunkAlertRequest) -> dict[str, object]:
    alert_payload = alert.model_dump(mode="json", exclude_none=True)
    search_name = _alert_field(
        alert_payload, "Splunk Alert", "search_name", "alert_name", "name"
    )
    failing_host = _alert_field(alert_payload, "unknown-host", "host")
    service = _alert_field(alert_payload, "checkout-api", "service")
    incident_id = _alert_incident_id(alert_payload)

    incident = Incident(
        incident_id=incident_id or Incident(service=service).incident_id,
        service=service,
        source="splunk_webhook",
    )
    incident.status = "INVESTIGATED"
    incident.updated_at = utc_now()
    upsert_incident(incident)
    write_incident_event(
        {
            "timestamp": _timestamp(),
            "incident_id": incident.incident_id,
            "service": incident.service,
            "status": incident.status,
            "severity": incident.severity,
            "incident_status": incident.status,
            "action": "splunk_webhook_received",
            "alert_name": search_name,
            "host": failing_host,
            "trigger_time": _alert_field(
                alert_payload, "unknown", "trigger_time", "triggered_time", "time"
            ),
            "sourcetype": "aiops-incidents",
        }
    )

    mcp_client = SplunkMCPClient()
    mcp_evidence: Evidence | None = None
    raw_events: list[dict[str, Any]] = []
    fallback_reason: str | None = None
    try:
        mcp_evidence = await mcp_client.query_incident_evidence(
            incident.incident_id, incident.service
        )
    except Exception as exc:
        fallback_reason = f"splunk_mcp_query_failed: {exc}"

    try:
        raw_events = await mcp_client.query_alert_logs(
            host=None if failing_host == "unknown-host" else failing_host,
            service=incident.service,
            incident_id=incident_id,
            earliest_time="-10m",
            latest_time="now",
            row_limit=10,
        )
    except Exception:
        raw_events = []

    evidence = mcp_evidence or _evidence_from_alert_context(
        incident, alert_payload, raw_events
    )
    mcp_evidence_summary = _mcp_summary(mcp_evidence)
    if mcp_evidence:
        result = build_fallback_rca_from_mcp_evidence(
            mcp_evidence,
            source="rules_fallback_after_ai_unavailable",
        )
        evidence_source = "python_mcp_client_rules_fallback"
    else:
        result = decide_investigation(evidence, source="rules_fallback_mcp_unavailable")
        evidence_source = "splunk_webhook_payload"

    _apply_investigation_result(
        incident,
        result,
        mcp_evidence=mcp_evidence,
        mcp_evidence_summary=mcp_evidence_summary,
    )
    if raw_events and not incident.mcp_investigation:
        incident.mcp_investigation = True
        incident.mcp_log_event_count = len(raw_events)
        if "splunk_run_query" not in incident.mcp_tools_used:
            incident.mcp_tools_used.insert(0, "splunk_run_query")
        if not incident.mcp_evidence_summary:
            incident.mcp_evidence_summary = _format_mcp_evidence_summary(evidence)
    upsert_incident(incident)
    write_investigation_event(
        _investigation_record(
            incident,
            result,
            mcp_evidence=mcp_evidence,
            mcp_evidence_summary=incident.mcp_evidence_summary,
            evidence_source=evidence_source,
            extra={
                "alert_name": search_name,
                "host": failing_host,
                "fallback_reason": fallback_reason,
            },
        )
    )
    _write_correlation_from_evidence(
        incident,
        evidence,
        incident_class=result.root_cause,
        source=evidence_source,
    )
    await _record_splunk_ai_assistant_activity(mcp_client, incident, evidence)

    enhanced_result = await asyncio.to_thread(
        _maybe_codex_enhancement,
        alert_name=search_name,
        incident=incident,
        evidence=evidence,
        raw_events=raw_events,
        alert_payload=alert_payload,
    )
    if enhanced_result:
        result = enhanced_result
        _apply_investigation_result(
            incident,
            result,
            mcp_evidence=mcp_evidence,
            mcp_evidence_summary=incident.mcp_evidence_summary,
        )
        if raw_events:
            incident.mcp_investigation = True
            incident.mcp_log_event_count = max(
                incident.mcp_log_event_count, len(raw_events)
            )
            if "splunk_run_query" not in incident.mcp_tools_used:
                incident.mcp_tools_used.insert(0, "splunk_run_query")
    upsert_incident(incident)

    ai_summary = incident.ai_summary or _format_ai_summary(search_name, incident)
    hec_status = await save_ai_summary_to_splunk(
        summary_text=ai_summary,
        host=failing_host,
        alert_name=search_name,
        incident=incident,
        alert_payload=alert_payload,
    )

    common_record = {
        "timestamp": _timestamp(),
        "incident_id": incident.incident_id,
        "service": incident.service,
        "status": incident.status,
        "severity": incident.severity,
        "root_cause": incident.root_cause,
        "confidence_score": incident.confidence_score,
        "evidence_summary": incident.evidence_summary,
        "ai_summary": incident.ai_summary,
        "llm_provider": incident.llm_provider,
        "mcp_evidence_summary": incident.mcp_evidence_summary,
        "alert_name": search_name,
        "host": failing_host,
        "mcp_investigation": incident.mcp_investigation,
        "mcp_tools_used": incident.mcp_tools_used,
        "spl_queries_used": incident.spl_queries_used,
        "mcp_log_event_count": incident.mcp_log_event_count,
        "llm_raw_response": (result.raw_response or "")[:2000] or None,
    }
    write_incident_event(
        {
            **common_record,
            "incident_status": incident.status,
            "investigation_status": "COMPLETED",
            "action": "splunk_webhook_triaged",
            "sourcetype": "aiops-incidents",
        }
    )
    write_investigation_event(
        {
            **common_record,
            "investigation_status": "COMPLETED",
            "evidence_source": evidence_source,
            "mcp_evidence_source": "splunk_mcp_client_call" if mcp_evidence else None,
            "source": incident.llm_provider,
            "fallback_reason": fallback_reason,
            "sourcetype": "aiops-investigations",
        }
    )
    _write_timeline(
        incident,
        "splunk_webhook_triaged",
        details={"alert_name": search_name, "host": failing_host},
    )
    await _persist_ai_triage_record(
        incident=incident,
        alert_name=search_name,
        host=failing_host,
        summary_text=ai_summary,
        alert_payload=alert_payload,
        hec_status=hec_status,
        mcp_tool_used=incident.mcp_investigation,
        mcp_log_event_count=incident.mcp_log_event_count,
    )

    return {
        "status": "incident_triaged",
        "incident_id": incident.incident_id,
        "diagnosis": ai_summary,
        "llm_provider": incident.llm_provider,
        "mcp_tool_used": incident.mcp_investigation,
        "mcp_tools_used": incident.mcp_tools_used,
        "spl_queries_used": incident.spl_queries_used,
        "mcp_log_event_count": incident.mcp_log_event_count,
        "hec_status": hec_status,
    }


@app.get("/incidents", response_model=list[Incident])
def list_incidents() -> list[Incident]:
    return sorted(
        load_incidents().values(), key=lambda item: item.created_at, reverse=True
    )


@app.get("/incidents/{incident_id}", response_model=Incident)
def get_incident(incident_id: str) -> Incident:
    incident = load_incidents().get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@app.post("/incidents/{incident_id}/investigate", response_model=Incident)
async def investigate_incident(
    incident_id: str, request: Request, background_tasks: BackgroundTasks
) -> Incident | RedirectResponse:
    if _wants_html(request):
        incident = await _start_investigation_state(incident_id)
        background_tasks.add_task(_finalize_investigation_state, incident.incident_id)
        return RedirectResponse(url="/dashboard", status_code=303)
    incident = await _investigate_incident_state(incident_id)
    return incident


@app.get("/incidents/{incident_id}/investigate", response_model=None)
async def investigate_incident_link(
    incident_id: str, request: Request, background_tasks: BackgroundTasks
) -> Incident | HTMLResponse:
    incident = await _investigate_incident_state(incident_id)
    if _wants_html(request):
        return _render_action_result("Investigation", incident)
    return incident


@app.post("/incidents/{incident_id}/approve", response_model=Incident)
def approve_incident(
    incident_id: str,
    http_request: Request,
    approval: ApprovalRequest | None = None,
) -> Incident | RedirectResponse:
    incident = load_incidents().get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    if not _has_approval_ready_rca(incident):
        raise HTTPException(
            status_code=409,
            detail="Incident must be investigated and have MCP evidence or fallback RCA before approval.",
        )

    operator = (approval or ApprovalRequest()).approved_by
    _apply_remediation_outcome(
        incident,
        status="APPROVED",
        remediation_status="APPROVED",
        action="remediation_approved",
        result="Remediation approved by operator; execution pending.",
        approved_by=operator,
    )
    if _wants_html(http_request):
        return RedirectResponse(url="/dashboard", status_code=303)
    return incident


@app.get("/incidents/{incident_id}/approve", response_model=None)
def approve_incident_link(
    incident_id: str, request: Request
) -> Incident | HTMLResponse:
    incident = approve_incident(incident_id, request)
    if isinstance(incident, RedirectResponse):
        incident = load_incidents()[incident_id]
    if _wants_html(request):
        return _render_action_result("Approval", incident)
    return incident


@app.post("/incidents/{incident_id}/reject", response_model=Incident)
def reject_remediation(
    incident_id: str,
    request: Request,
    rejection: ApprovalRequest | None = None,
) -> Incident | RedirectResponse:
    incident = load_incidents().get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    operator = (rejection or ApprovalRequest()).approved_by
    _apply_remediation_outcome(
        incident,
        status="REJECTED",
        remediation_status="REJECTED remediation",
        action="remediation_rejected",
        result="Remediation rejected by operator",
        approved_by=operator,
    )
    if _wants_html(request):
        return RedirectResponse(url="/dashboard", status_code=303)
    return incident


@app.get("/incidents/{incident_id}/reject", response_model=None)
def reject_remediation_link(
    incident_id: str, request: Request
) -> Incident | HTMLResponse:
    incident = reject_remediation(incident_id, request)
    if isinstance(incident, RedirectResponse):
        incident = load_incidents()[incident_id]
    if _wants_html(request):
        return _render_action_result("Rejection", incident)
    return incident


@app.post("/incidents/{incident_id}/execute", response_model=Incident)
def execute_remediation(
    incident_id: str, request: Request
) -> Incident | RedirectResponse:
    incident = load_incidents().get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    if incident.status != "APPROVED":
        raise HTTPException(
            status_code=409, detail="Incident must be approved before execution"
        )

    action = (
        incident.safe_remediation_actions[0]
        if incident.safe_remediation_actions
        else "SIMULATE: open escalation"
    )
    _apply_remediation_outcome(
        incident,
        status="EXECUTED",
        remediation_status="Remediation Executed",
        action="remediation_executed",
        result=f"Executed simulation action: {action}",
        approved_by=incident.approved_by,
    )
    if _wants_html(request):
        return RedirectResponse(url="/dashboard", status_code=303)
    return incident


@app.get("/incidents/{incident_id}/execute", response_model=None)
def execute_remediation_link(
    incident_id: str, request: Request
) -> Incident | HTMLResponse:
    incident = execute_remediation(incident_id, request)
    if isinstance(incident, RedirectResponse):
        incident = load_incidents()[incident_id]
    if _wants_html(request):
        return _render_action_result("Execution", incident)
    return incident


@app.post("/incidents/{incident_id}/close", response_model=Incident)
def close_incident(incident_id: str, request: Request) -> Incident | RedirectResponse:
    incident = load_incidents().get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    if incident.status not in {"EXECUTED", "CLOSED"}:
        raise HTTPException(
            status_code=409, detail="Incident must be executed before closure"
        )

    _apply_remediation_outcome(
        incident,
        status="CLOSED",
        remediation_status="TICKET CLOSED",
        action="ticket_closed",
        result=incident.remediation_result or "Ticket closed by operator",
        approved_by=incident.approved_by,
    )
    if _wants_html(request):
        return RedirectResponse(url="/dashboard", status_code=303)
    return incident


@app.get("/incidents/{incident_id}/close", response_model=None)
def close_incident_link(incident_id: str, request: Request) -> Incident | HTMLResponse:
    incident = close_incident(incident_id, request)
    if isinstance(incident, RedirectResponse):
        incident = load_incidents()[incident_id]
    if _wants_html(request):
        return _render_action_result("Close", incident)
    return incident


@app.get("/dashboard", response_model=None)
def dashboard(request: Request) -> dict[str, object] | HTMLResponse:
    payload = _dashboard_payload(request)
    if _wants_html(request):
        return HTMLResponse(_render_dashboard(payload))
    return payload
