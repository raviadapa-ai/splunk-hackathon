from html import escape
import os
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
import httpx
from pydantic import BaseModel, ConfigDict, Field

from app.config import AI_TRIAGE_SOURCETYPE
from app.decision_engine import decide_investigation
from app.llm_agent import CodexRcaAgent
from app.models import Evidence, Incident, log_timestamp, utc_now
from app.splunk_mcp_client import SplunkMCPClient
from app.storage import (
    load_incidents,
    upsert_incident,
    write_ai_triage_event,
    write_incident_event,
    write_investigation_event,
    write_remediation_event,
)
from app.telemetry import inject_incident, normal_event, write_event


app = FastAPI(title="Agentic Ops Observability", version="1.0.0")

INCIDENT_SERVICE_MAP = {
    "database_timeout": "checkout-api",
    "upstream_api_failure": "payment-api",
    "auth_failure": "auth-api",
    "deployment_regression": "checkout-api",
    "cpu_saturation": "catalog-api",
    "latency_regression": "checkout-api",
}


class CreateIncidentRequest(BaseModel):
    service: str = "checkout-api"
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


def _evidence_from_alert_context(
    incident: Incident,
    payload: dict[str, Any],
    raw_events: list[dict[str, Any]],
) -> Evidence:
    result = payload.get("result") if isinstance(payload.get("result"), dict) else {}
    rows = raw_events or ([result] if result else [])
    service = incident.service
    error_types = [str(row.get("error_type")) for row in rows if row.get("error_type") not in {None, "", "null"}]
    hosts = [str(row.get("host")) for row in rows if row.get("host")]
    endpoints = [str(row.get("endpoint")) for row in rows if row.get("endpoint")]
    dependencies = [str(row.get("dependency")) for row in rows if row.get("dependency")]
    regions = [str(row.get("user_region")) for row in rows if row.get("user_region")]
    versions = [str(row.get("deployment_version")) for row in rows if row.get("deployment_version")]

    if not error_types:
        alert_name = _alert_field(payload, "", "search_name", "alert_name", "name").lower()
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
    actions = "; ".join(incident.recommended_actions) if incident.recommended_actions else "Continue monitoring"
    return (
        f"Alert '{alert_name}' was triaged for {incident.service}. "
        f"Root cause: {incident.root_cause or 'undetermined service anomaly'}. "
        f"Severity: {incident.severity}. Confidence: {incident.confidence_score or 0:.2f}. "
        f"Evidence: {incident.evidence_summary or 'No evidence summary available.'} "
        f"Recommended actions: {actions}."
    )


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

    verify_tls = os.getenv("SPLUNK_HEC_VERIFY_TLS", "true").lower() not in {"0", "false", "no"}
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
            "ai_summary": summary_text,
            "ai_root_cause_summary": summary_text,
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


def _fallback_evidence(incident: Incident, incident_type: str | None = None) -> Evidence:
    error_type = incident_type or "latency_regression"
    return Evidence(
        service=incident.service,
        incident_id=incident.incident_id,
        event_count=12,
        error_types=[error_type],
        hosts=[f"{incident.service.split('-')[0]}-01", f"{incident.service.split('-')[0]}-02"],
        endpoints=["/checkout" if incident.service == "checkout-api" else "/health"],
        dependencies=["postgres" if error_type in {"database_timeout", "deployment_regression"} else "none"],
        regions=["us-east"],
        avg_latency_ms=2200,
        max_latency_ms=3400,
        max_cpu_pct=92 if error_type == "cpu_saturation" else 76,
        max_memory_pct=88,
        max_db_pool_pct=96 if error_type in {"database_timeout", "deployment_regression"} else 55,
        deployment_versions=["2026.06.3"],
    )


def _format_mcp_evidence_summary(evidence: Evidence) -> str:
    hosts = ", ".join(sorted(set(evidence.hosts))[:4]) or "unknown hosts"
    endpoints = ", ".join(sorted(set(evidence.endpoints))[:4]) or "unknown endpoints"
    errors = ", ".join(sorted(set(evidence.error_types))[:4]) or "unknown errors"
    dependencies = ", ".join(sorted(set(evidence.dependencies))[:4]) or "unknown dependencies"
    return (
        f"MCP evidence for {evidence.service}: {evidence.event_count} events; "
        f"errors={errors}; hosts={hosts}; endpoints={endpoints}; dependencies={dependencies}; "
        f"avg_latency_ms={evidence.avg_latency_ms:.0f}; max_latency_ms={evidence.max_latency_ms:.0f}; "
        f"max_cpu_pct={evidence.max_cpu_pct:.0f}; max_db_pool_pct={evidence.max_db_pool_pct:.0f}."
    )


def _fallback_mcp_summary(incident_id: str) -> str:
    return f"MCP evidence unavailable for incident {incident_id}."


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
            "ai_summary": summary_text,
            "llm_provider": incident.llm_provider,
            "mcp_evidence_summary": incident.mcp_evidence_summary,
            "original_alert": alert_name,
            "target_host": host,
            "mcp_investigation": mcp_tool_used,
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
            "mcp_investigation": incident.mcp_evidence_summary is not None,
            "action": action,
            "mode": "simulate",
            "result": incident.remediation_result,
            "sourcetype": "aiops-remediation",
        }
    )
    return incident


def _wants_html(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    return "text/html" in accept and "application/json" not in accept


def _incident_action_urls(request: Request, incident_id: str) -> dict[str, str]:
    return {
        "investigate": str(request.url_for("investigate_incident", incident_id=incident_id)),
        "approve": str(request.url_for("approve_incident", incident_id=incident_id)),
        "reject": str(request.url_for("reject_remediation", incident_id=incident_id)),
        "close": str(request.url_for("close_incident", incident_id=incident_id)),
    }


def _dashboard_payload(request: Request) -> dict[str, object]:
    incidents = list(load_incidents().values())
    by_status: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for incident in incidents:
        by_status[incident.status] = by_status.get(incident.status, 0) + 1
        by_severity[incident.severity] = by_severity.get(incident.severity, 0) + 1

    recent_incidents = []
    for incident in sorted(incidents, key=lambda item: item.updated_at, reverse=True)[:10]:
        item = incident.model_dump(mode="json")
        item["action_urls"] = _incident_action_urls(request, incident.incident_id)
        recent_incidents.append(item)

    return {
        "total_incidents": len(incidents),
        "by_status": by_status,
        "by_severity": by_severity,
        "recent_incidents": recent_incidents,
        "last_updated": _timestamp(),
    }


def _status_counts(counts: dict[str, int]) -> str:
    if not counts:
        return "None"
    return ", ".join(f"{escape(status)}: {count}" for status, count in sorted(counts.items()))


def _action_button(label: str, url: str, disabled: bool = False) -> str:
    disabled_attr = " disabled" if disabled else ""
    return (
        f'<form method="post" action="{escape(url)}" target="_blank">'
        f'<button type="submit"{disabled_attr}>{escape(label)}</button>'
        "</form>"
    )


def _render_dashboard(payload: dict[str, object]) -> str:
    incidents = payload["recent_incidents"]
    rows = []
    for incident in incidents if isinstance(incidents, list) else []:
        if not isinstance(incident, dict):
            continue
        incident_id = str(incident.get("incident_id", ""))
        status = str(incident.get("status", ""))
        remediation_status = str(incident.get("remediation_status") or "")
        can_approve = status in {"INVESTIGATED", "COMPLETED"}
        can_reject = status not in {"CLOSED", "REJECTED"}
        can_close = status != "CLOSED" or remediation_status != "TICKET CLOSED"
        action_urls = incident.get("action_urls", {})
        if not isinstance(action_urls, dict):
            action_urls = {}
        rows.append(
            "<tr>"
            f"<td>{escape(incident_id)}</td>"
            f"<td>{escape(str(incident.get('service', '')))}</td>"
            f"<td>{escape(status)}</td>"
            f"<td>{escape(str(incident.get('severity', '')))}</td>"
            f"<td>{escape(str(incident.get('remediation_status') or ''))}</td>"
            f"<td>{escape(str(incident.get('root_cause') or 'Pending investigation'))}</td>"
            f"<td class=\"actions\">"
            f"{_action_button('Investigate', str(action_urls.get('investigate', '')), status == 'CLOSED')}"
            f"{_action_button('Approve', str(action_urls.get('approve', '')), not can_approve)}"
            f"{_action_button('Reject', str(action_urls.get('reject', '')), not can_reject)}"
            f"{_action_button('Close', str(action_urls.get('close', '')), not can_close)}"
            "</td>"
            "</tr>"
        )

    table_body = "\n".join(rows) or '<tr><td colspan="7">No incidents yet.</td></tr>'
    by_status = payload.get("by_status", {})
    by_severity = payload.get("by_severity", {})
    status_text = _status_counts(by_status if isinstance(by_status, dict) else {})
    severity_text = _status_counts(by_severity if isinstance(by_severity, dict) else {})
    last_updated = escape(str(payload.get("last_updated", "")))

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
    .page-head {{ display: flex; justify-content: space-between; align-items: baseline; gap: 12px; flex-wrap: wrap; }}
    .updated {{ color: #5f6b7a; font-size: 13px; }}
    .summary {{ display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; margin-bottom: 22px; }}
    .metric {{ background: #fff; border: 1px solid #d9dee5; border-radius: 8px; padding: 14px; }}
    .metric strong {{ display: block; font-size: 24px; margin-bottom: 6px; }}
    table {{ width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #d9dee5; }}
    th, td {{ padding: 10px 12px; border-bottom: 1px solid #e5e8ed; text-align: left; vertical-align: middle; }}
    th {{ background: #eef1f5; font-size: 13px; text-transform: uppercase; }}
    .actions {{ display: flex; flex-wrap: wrap; gap: 8px; min-width: 260px; }}
    form {{ margin: 0; }}
    button {{ border: 1px solid #1f6feb; background: #1f6feb; color: #fff; border-radius: 6px; padding: 7px 11px; cursor: pointer; }}
    button:disabled {{ border-color: #c2c8d0; background: #e1e5ea; color: #6b7280; cursor: not-allowed; }}
    @media (max-width: 760px) {{
      .summary {{ grid-template-columns: 1fr; }}
      table {{ display: block; overflow-x: auto; }}
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
    <table>
      <thead>
        <tr><th>Incident</th><th>Service</th><th>Status</th><th>Severity</th><th>Remediation</th><th>Root Cause</th><th>Actions</th></tr>
      </thead>
      <tbody>
        {table_body}
      </tbody>
    </table>
  </main>
</body>
</html>"""


def _render_action_result(action: str, incident: Incident) -> HTMLResponse:
    root_cause = incident.root_cause or "Pending"
    evidence_summary = incident.evidence_summary or _fallback_mcp_summary(incident.incident_id)
    ai_summary = incident.ai_summary or "No AI summary available."
    mcp_evidence_summary = incident.mcp_evidence_summary or "No MCP evidence summary available."
    recommended_actions = "".join(f"<li>{escape(item)}</li>" for item in incident.recommended_actions) or "<li>None</li>"
    safe_actions = "".join(f"<li>{escape(item)}</li>" for item in incident.safe_remediation_actions) or "<li>None</li>"
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
    mcp_evidence = await mcp_client.query_incident_evidence(incident.incident_id, incident.service)
    evidence = mcp_evidence or _fallback_evidence(incident)
    result = decide_investigation(evidence, source="mcp_query" if mcp_evidence else "rules_fallback")

    incident.status = "COMPLETED"
    incident.severity = result.severity
    incident.root_cause = result.root_cause
    incident.confidence_score = result.confidence_score
    incident.evidence_summary = result.evidence_summary
    incident.ai_summary = result.ai_summary
    incident.llm_provider = result.source
    incident.mcp_evidence_summary = (
        f"MCP client call: {_format_mcp_evidence_summary(mcp_evidence)}" if mcp_evidence else None
    )
    incident.recommended_actions = result.recommended_actions
    incident.safe_remediation_actions = result.safe_remediation_actions
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
            "confidence_score": incident.confidence_score,
            "approved_by": incident.approved_by,
            "remediation_result": incident.remediation_result,
            "evidence_summary": incident.evidence_summary,
            "mcp_evidence_summary": incident.mcp_evidence_summary,
            "incident_status": incident.status,
            "investigation_status": "COMPLETED",
            "action": "investigation_completed",
            "sourcetype": "aiops-incidents",
        }
    )

    investigation_record = result.model_dump(mode="json")
    investigation_record["evidence_summary"] = incident.evidence_summary
    investigation_record.update(
        {
            "timestamp": _timestamp(),
            "status": "COMPLETED",
            "incident_status": incident.status,
            "investigation_status": "COMPLETED",
            "mcp_investigation": mcp_evidence is not None,
            "mcp_evidence_summary": incident.mcp_evidence_summary,
            "evidence_source": "correlated_observed_events",
            "mcp_evidence_source": "splunk_mcp_client_call" if mcp_evidence else None,
            "sourcetype": "aiops-investigations",
        }
    )

    ai_summary = incident.ai_summary or _format_ai_summary(incident.incident_id, incident)
    hec_status = await save_ai_summary_to_splunk(
        summary_text=ai_summary,
        host=incident.service,
        alert_name=f"incident:{incident.incident_id}",
        incident=incident,
        alert_payload={
            "incident_id": incident.incident_id,
            "service": incident.service,
            "source": "incident_investigation",
            "mcp_investigation": mcp_evidence is not None,
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
            "mcp_investigation": mcp_evidence is not None,
        },
        hec_status=hec_status,
        mcp_tool_used=mcp_evidence is not None,
        mcp_log_event_count=evidence.event_count,
    )
    write_investigation_event(investigation_record)


async def _load_or_hydrate_incident(incident_id: str) -> tuple[Incident, Evidence | None]:
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
    return incident, evidence


async def _investigate_incident_state(incident_id: str) -> Incident:
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

    _write_preliminary_investigation_event(incident)

    await _finalize_investigation_state(incident.incident_id)
    return load_incidents().get(incident_id) or incident


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "time": _timestamp()}


@app.post("/incidents/create", response_model=Incident)
def create_incident(request: CreateIncidentRequest) -> Incident:
    incident_id = inject_incident(request.incident_type) if request.inject_burst else None
    service = INCIDENT_SERVICE_MAP.get(request.incident_type or "", request.service)
    incident = Incident(
        incident_id=incident_id or Incident(service=request.service).incident_id,
        service=service,
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
    return incident


@app.post("/logs/generate")
def generate_logs(request: GenerateLogsRequest) -> dict[str, object]:
    for _ in range(request.count):
        write_event(normal_event())

    incident_id = inject_incident(request.incident_type) if request.include_incident else None
    return {
        "status": "ok",
        "generated_normal_events": request.count,
        "incident_id": incident_id,
        "log_path": "data/app.log",
    }


@app.post("/webhook/splunk-alert")
async def handle_splunk_alert(alert: SplunkAlertRequest) -> dict[str, object]:
    alert_payload = alert.model_dump(mode="json", exclude_none=True)
    search_name = _alert_field(alert_payload, "Splunk Alert", "search_name", "alert_name", "name")
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
            "trigger_time": _alert_field(alert_payload, "unknown", "trigger_time", "triggered_time", "time"),
            "sourcetype": "aiops-incidents",
        }
    )

    mcp_client = SplunkMCPClient()
    mcp_evidence: Evidence | None = None
    raw_events: list[dict[str, Any]] = []
    if incident_id:
        try:
            mcp_evidence = await mcp_client.query_incident_evidence(incident.incident_id, incident.service)
        except Exception:
            mcp_evidence = None

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

    evidence = mcp_evidence or _evidence_from_alert_context(incident, alert_payload, raw_events)
    result_source = "splunk_mcp_webhook" if mcp_evidence or raw_events else "splunk_webhook_payload"
    result = CodexRcaAgent().analyze(
        alert_name=search_name,
        incident=incident,
        evidence=evidence,
        raw_events=raw_events,
    )

    incident.status = "COMPLETED"
    incident.severity = result.severity
    incident.root_cause = result.root_cause
    incident.confidence_score = result.confidence_score
    incident.evidence_summary = result.evidence_summary
    incident.ai_summary = result.ai_summary
    incident.llm_provider = result.source
    incident.mcp_evidence_summary = _format_mcp_evidence_summary(evidence) if mcp_evidence or raw_events else None
    incident.recommended_actions = result.recommended_actions
    incident.safe_remediation_actions = result.safe_remediation_actions
    incident.updated_at = utc_now()
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
        "mcp_investigation": mcp_evidence is not None or bool(raw_events),
        "mcp_log_event_count": len(raw_events),
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
            "evidence_source": result_source,
            "mcp_evidence_source": "splunk_mcp_client_call" if mcp_evidence or raw_events else None,
            "source": result.source,
            "sourcetype": "aiops-investigations",
        }
    )
    await _persist_ai_triage_record(
        incident=incident,
        alert_name=search_name,
        host=failing_host,
        summary_text=ai_summary,
        alert_payload=alert_payload,
        hec_status=hec_status,
        mcp_tool_used=mcp_evidence is not None or bool(raw_events),
        mcp_log_event_count=len(raw_events),
    )

    return {
        "status": "incident_triaged",
        "incident_id": incident.incident_id,
        "diagnosis": ai_summary,
        "llm_provider": incident.llm_provider,
        "mcp_tool_used": mcp_evidence is not None or bool(raw_events),
        "mcp_log_event_count": len(raw_events),
        "hec_status": hec_status,
    }


@app.get("/incidents", response_model=list[Incident])
def list_incidents() -> list[Incident]:
    return sorted(load_incidents().values(), key=lambda item: item.created_at, reverse=True)


@app.get("/incidents/{incident_id}", response_model=Incident)
def get_incident(incident_id: str) -> Incident:
    incident = load_incidents().get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@app.post("/incidents/{incident_id}/investigate", response_model=Incident)
async def investigate_incident(incident_id: str, request: Request) -> Incident | RedirectResponse:
    incident = await _investigate_incident_state(incident_id)
    if _wants_html(request):
        return RedirectResponse(url="/dashboard", status_code=303)
    return incident


@app.get("/incidents/{incident_id}/investigate", response_model=None)
async def investigate_incident_link(incident_id: str, request: Request) -> Incident | HTMLResponse:
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
    if incident.status not in {"INVESTIGATED", "COMPLETED"}:
        raise HTTPException(status_code=409, detail="Incident must be investigated before approval")

    operator = (approval or ApprovalRequest()).approved_by
    remediation_summary = incident.ai_summary or incident.evidence_summary or incident.root_cause or "No AI summary available."
    _apply_remediation_outcome(
        incident,
        status="CLOSED",
        remediation_status="Remediation Executed",
        action="remediation_executed",
        result=f"Remediation Executed from AI summary: {remediation_summary}",
        approved_by=operator,
    )
    if _wants_html(http_request):
        return RedirectResponse(url="/dashboard", status_code=303)
    return incident


@app.get("/incidents/{incident_id}/approve", response_model=None)
def approve_incident_link(incident_id: str, request: Request) -> Incident | HTMLResponse:
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
def reject_remediation_link(incident_id: str, request: Request) -> Incident | HTMLResponse:
    incident = reject_remediation(incident_id, request)
    if isinstance(incident, RedirectResponse):
        incident = load_incidents()[incident_id]
    if _wants_html(request):
        return _render_action_result("Rejection", incident)
    return incident


@app.post("/incidents/{incident_id}/execute", response_model=Incident)
def execute_remediation(incident_id: str, request: Request) -> Incident | RedirectResponse:
    incident = load_incidents().get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    if incident.status == "CLOSED" and incident.remediation_status == "Remediation Executed":
        if _wants_html(request):
            return RedirectResponse(url="/dashboard", status_code=303)
        return incident
    if incident.status not in {"APPROVED", "INVESTIGATED", "COMPLETED"}:
        raise HTTPException(status_code=409, detail="Incident must be approved before execution")

    action = incident.safe_remediation_actions[0] if incident.safe_remediation_actions else "SIMULATE: open escalation"
    _apply_remediation_outcome(
        incident,
        status="CLOSED",
        remediation_status="Remediation Executed",
        action="remediation_executed",
        result=f"Executed simulation action: {action}",
        approved_by=incident.approved_by,
    )
    if _wants_html(request):
        return RedirectResponse(url="/dashboard", status_code=303)
    return incident


@app.get("/incidents/{incident_id}/execute", response_model=None)
def execute_remediation_link(incident_id: str, request: Request) -> Incident | HTMLResponse:
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
