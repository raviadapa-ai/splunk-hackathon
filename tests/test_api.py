import json
from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient

from app import config
from app.models import Evidence, InvestigationResult


def _fake_codex_enhancement(**kwargs) -> InvestigationResult:
    incident = kwargs["incident"]
    evidence = kwargs["evidence"]
    return InvestigationResult(
        incident_id=incident.incident_id,
        service=incident.service,
        severity=incident.severity,
        root_cause="database connection pool exhaustion",
        confidence_score=0.95,
        evidence_summary=(
            f"Fresh evidence confirms {incident.service} is blocked by saturated database connections."
        ),
        ai_summary=(
            f"Codex fresh summary: {incident.service} is blocked by saturated database connections."
        ),
        recommended_actions=["Recycle saturated DB connections"],
        safe_remediation_actions=["SIMULATE: Recycle saturated DB connections"],
        source="codex_mcp_agent",
        mcp_investigation=True,
        mcp_tools_used=["splunk_run_query"],
        spl_queries_used=["index=main sourcetype=agentic-ops"],
        mcp_log_event_count=evidence.event_count,
    )


def test_generate_logs_endpoint_writes_app_log(monkeypatch) -> None:
    tmp_path = Path(".testdata") / f"test_logs_{uuid4().hex}"
    tmp_path.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "APP_LOG_PATH", tmp_path / "app.log")

    import app.main as main
    import app.telemetry as telemetry

    monkeypatch.setattr(telemetry, "DATA_DIR", tmp_path)
    monkeypatch.setattr(telemetry, "APP_LOG_PATH", tmp_path / "app.log")

    client = TestClient(main.app)
    response = client.post(
        "/logs/generate",
        json={
            "count": 3,
            "include_incident": True,
            "incident_type": "database_timeout",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["generated_normal_events"] == 3
    assert payload["incident_id"].startswith("inc-")

    lines = (tmp_path / "app.log").read_text(encoding="utf-8").splitlines()
    assert len(lines) >= 13


def test_optional_api_bearer_auth(monkeypatch) -> None:
    monkeypatch.setenv("AGENTIC_OPS_API_TOKEN", "secret-token")

    import app.main as main

    client = TestClient(main.app)

    health = client.get("/health")
    assert health.status_code == 200

    blocked = client.get("/incidents")
    assert blocked.status_code == 401

    allowed = client.get("/incidents", headers={"authorization": "Bearer secret-token"})
    assert allowed.status_code == 200


def test_create_incident_preserves_requested_severity(monkeypatch) -> None:
    tmp_path = Path(".testdata") / f"test_create_severity_{uuid4().hex}"
    tmp_path.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "INCIDENT_STORE_PATH", tmp_path / "incidents.json")
    monkeypatch.setattr(config, "INCIDENT_LOG_PATH", tmp_path / "incidents.log")
    monkeypatch.setattr(
        config, "REMEDIATION_LOG_PATH", tmp_path / "aiops_remediation.log"
    )
    monkeypatch.setattr(config, "FORECAST_LOG_PATH", tmp_path / "forecast.log")

    import app.main as main
    import app.storage as storage

    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)
    monkeypatch.setattr(storage, "INCIDENT_STORE_PATH", tmp_path / "incidents.json")
    monkeypatch.setattr(storage, "INCIDENT_LOG_PATH", tmp_path / "incidents.log")
    monkeypatch.setattr(
        storage, "REMEDIATION_LOG_PATH", tmp_path / "aiops_remediation.log"
    )

    client = TestClient(main.app)
    response = client.post(
        "/incidents/create",
        json={
            "service": "checkout-api",
            "severity": "HIGH",
            "inject_burst": False,
        },
    )

    assert response.status_code == 200
    assert response.json()["severity"] == "HIGH"


def test_incident_lifecycle_uses_human_approval(monkeypatch) -> None:
    tmp_path = Path(".testdata") / f"test_api_{uuid4().hex}"
    tmp_path.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "APP_LOG_PATH", tmp_path / "app.log")
    monkeypatch.setattr(config, "INCIDENT_STORE_PATH", tmp_path / "incidents.json")
    monkeypatch.setattr(config, "INCIDENT_LOG_PATH", tmp_path / "incidents.log")
    monkeypatch.setattr(config, "FORECAST_LOG_PATH", tmp_path / "forecast.log")
    monkeypatch.setattr(
        config, "INVESTIGATION_LOG_PATH", tmp_path / "aiops_investigations.log"
    )
    monkeypatch.setattr(
        config, "REMEDIATION_LOG_PATH", tmp_path / "aiops_remediation.log"
    )

    import app.main as main
    import app.storage as storage
    import app.telemetry as telemetry

    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)
    monkeypatch.setattr(storage, "INCIDENT_STORE_PATH", tmp_path / "incidents.json")
    monkeypatch.setattr(storage, "INCIDENT_LOG_PATH", tmp_path / "incidents.log")
    monkeypatch.setattr(storage, "FORECAST_LOG_PATH", tmp_path / "forecast.log")
    monkeypatch.setattr(
        storage, "INVESTIGATION_LOG_PATH", tmp_path / "aiops_investigations.log"
    )
    monkeypatch.setattr(
        storage, "REMEDIATION_LOG_PATH", tmp_path / "aiops_remediation.log"
    )
    monkeypatch.setattr(storage, "FORECAST_LOG_PATH", tmp_path / "forecast.log")
    monkeypatch.setattr(telemetry, "DATA_DIR", tmp_path)
    monkeypatch.setattr(telemetry, "APP_LOG_PATH", tmp_path / "app.log")

    async def fake_query_incident_evidence(
        self, incident_id: str, service: str | None = None
    ) -> Evidence | None:
        return Evidence(
            service=service or "checkout-api",
            incident_id=incident_id,
            event_count=14,
            error_types=["database_timeout"],
            hosts=["checkout-01", "checkout-02"],
            endpoints=["/checkout"],
            dependencies=["postgres"],
            regions=["us-east"],
            avg_latency_ms=2400,
            max_latency_ms=3900,
            max_cpu_pct=74,
            max_memory_pct=81,
            max_db_pool_pct=97,
            deployment_versions=["2026.06.3"],
        )

    monkeypatch.setattr(
        main.SplunkMCPClient, "query_incident_evidence", fake_query_incident_evidence
    )
    monkeypatch.setattr(main, "_maybe_codex_enhancement", _fake_codex_enhancement)

    storage.write_forecast_event(
        {
            "timestamp": "2026-06-13T17:20:00+05:30",
            "incident_id": "inc-checkout-forecast",
            "service": "checkout",
            "status": "READY",
            "forecast_horizon": "15m",
            "predicted_latency_ms": 3600,
            "confidence_score": 0.92,
            "sourcetype": "aiops-forecast",
        }
    )
    storage.write_forecast_event(
        {
            "timestamp": "2026-06-13T17:21:00+05:30",
            "incident_id": "inc-payment-forecast",
            "service": "payment",
            "status": "READY",
            "forecast_horizon": "45m",
            "predicted_latency_ms": 2100,
            "confidence_score": 0.81,
            "sourcetype": "aiops-forecast",
        }
    )
    storage.write_forecast_event(
        {
            "timestamp": "2026-06-13T17:22:00+05:30",
            "incident_id": "inc-auth-forecast",
            "service": "auth",
            "status": "READY",
            "forecast_horizon": "15m",
            "predicted_latency_ms": 1200,
            "confidence_score": 0.95,
            "sourcetype": "aiops-forecast",
        }
    )

    client = TestClient(main.app)
    created = client.post(
        "/incidents/create",
        json={"incident_type": "database_timeout", "inject_burst": True},
    )
    assert created.status_code == 200
    incident_id = created.json()["incident_id"]

    premature_approval = client.post(
        f"/incidents/{incident_id}/approve", json={"approved_by": "tester"}
    )
    assert premature_approval.status_code == 409

    blocked = client.post(f"/incidents/{incident_id}/execute")
    assert blocked.status_code == 409

    investigated = client.post(f"/incidents/{incident_id}/investigate")
    assert investigated.status_code == 200
    assert investigated.json()["status"] == "COMPLETED"
    assert investigated.json()["llm_provider"] in {
        "codex_mcp_agent",
        "fallback_alternative_after_codex_unavailable",
        "fallback_alternative_after_codex_failure",
    }
    assert investigated.json()["ai_summary"]
    assert investigated.json()["mcp_investigation"] is True
    assert investigated.json()["mcp_evidence_summary"].startswith("MCP client call:")
    assert "database" in investigated.json()["root_cause"].lower()
    assert investigated.json()["confidence_score"] >= 0.8
    assert investigated.json()["recommended_actions"]

    approved = client.post(
        f"/incidents/{incident_id}/approve", json={"approved_by": "tester"}
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "APPROVED"
    assert approved.json()["remediation_status"] == "APPROVED"

    executed = client.post(f"/incidents/{incident_id}/execute")
    assert executed.status_code == 200
    assert executed.json()["status"] == "EXECUTED"

    closed = client.post(f"/incidents/{incident_id}/close")
    assert closed.status_code == 200
    assert closed.json()["status"] == "CLOSED"

    assert Path(tmp_path / "aiops_investigations.log").exists()
    assert Path(tmp_path / "aiops_remediation.log").exists()

    investigation_events = [
        json.loads(line)
        for line in (tmp_path / "aiops_investigations.log")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    completed_events = [
        event
        for event in investigation_events
        if event.get("investigation_status") == "COMPLETED"
    ]
    assert completed_events
    assert completed_events[-1]["mcp_investigation"] is True
    assert completed_events[-1]["source"] in {
        "codex_mcp_agent",
        "fallback_alternative_after_codex_unavailable",
        "fallback_alternative_after_codex_failure",
    }


def test_ai_assistant_preparation_writes_forecast_and_prompt(monkeypatch) -> None:
    tmp_path = Path(".testdata") / f"test_ai_assistant_{uuid4().hex}"
    tmp_path.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "APP_LOG_PATH", tmp_path / "app.log")
    monkeypatch.setattr(config, "INCIDENT_STORE_PATH", tmp_path / "incidents.json")
    monkeypatch.setattr(config, "INCIDENT_LOG_PATH", tmp_path / "incidents.log")
    monkeypatch.setattr(
        config, "AI_TRIAGE_LOG_PATH", tmp_path / "ai_triages.log"
    )
    monkeypatch.setattr(
        config, "AI_ASSISTANT_LOG_PATH", tmp_path / "ai_assistant.log"
    )
    monkeypatch.setattr(config, "FORECAST_LOG_PATH", tmp_path / "forecast.log")
    monkeypatch.setattr(
        config, "SPLUNK_AI_ACTIVITY_LOG_PATH", tmp_path / "splunk_ai_activity.log"
    )

    import app.main as main
    import app.storage as storage
    import app.telemetry as telemetry

    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)
    monkeypatch.setattr(storage, "INCIDENT_STORE_PATH", tmp_path / "incidents.json")
    monkeypatch.setattr(storage, "INCIDENT_LOG_PATH", tmp_path / "incidents.log")
    monkeypatch.setattr(storage, "AI_TRIAGE_LOG_PATH", tmp_path / "ai_triages.log")
    monkeypatch.setattr(storage, "AI_ASSISTANT_LOG_PATH", tmp_path / "ai_assistant.log")
    monkeypatch.setattr(storage, "FORECAST_LOG_PATH", tmp_path / "forecast.log")
    monkeypatch.setattr(
        storage, "SPLUNK_AI_ACTIVITY_LOG_PATH", tmp_path / "splunk_ai_activity.log"
    )
    monkeypatch.setattr(telemetry, "DATA_DIR", tmp_path)
    monkeypatch.setattr(telemetry, "APP_LOG_PATH", tmp_path / "app.log")

    async def fake_query_incident_evidence(
        self, incident_id: str, service: str | None = None
    ) -> Evidence | None:
        return Evidence(
            service=service or "checkout-api",
            incident_id=incident_id,
            event_count=12,
            error_types=["latency_regression"],
            hosts=["checkout-01", "checkout-02"],
            endpoints=["/checkout"],
            dependencies=["redis"],
            regions=["us-east"],
            avg_latency_ms=1800,
            max_latency_ms=2600,
            max_cpu_pct=71,
            max_memory_pct=64,
            max_db_pool_pct=55,
            deployment_versions=["2026.06.3"],
        )

    monkeypatch.setattr(
        main.SplunkMCPClient, "query_incident_evidence", fake_query_incident_evidence
    )
    monkeypatch.setattr(main, "_maybe_codex_enhancement", _fake_codex_enhancement)
    monkeypatch.setattr(main, "_maybe_codex_enhancement", _fake_codex_enhancement)

    storage.write_forecast_event(
        {
            "timestamp": "2026-06-13T17:20:00+05:30",
            "incident_id": "inc-checkout-forecast",
            "service": "checkout",
            "status": "READY",
            "forecast_horizon": "15m",
            "predicted_latency_ms": 3600,
            "confidence_score": 0.92,
            "sourcetype": "aiops-forecast",
        }
    )
    storage.write_forecast_event(
        {
            "timestamp": "2026-06-13T17:21:00+05:30",
            "incident_id": "inc-payment-forecast",
            "service": "payment",
            "status": "READY",
            "forecast_horizon": "45m",
            "predicted_latency_ms": 2100,
            "confidence_score": 0.81,
            "sourcetype": "aiops-forecast",
        }
    )
    storage.write_forecast_event(
        {
            "timestamp": "2026-06-13T17:22:00+05:30",
            "incident_id": "inc-auth-forecast",
            "service": "auth",
            "status": "READY",
            "forecast_horizon": "15m",
            "predicted_latency_ms": 1200,
            "confidence_score": 0.95,
            "sourcetype": "aiops-forecast",
        }
    )

    client = TestClient(main.app)
    created = client.post(
        "/incidents/create",
        json={"incident_type": "latency_regression", "inject_burst": False},
    )
    assert created.status_code == 200
    incident_id = created.json()["incident_id"]

    response = client.post(f"/incidents/{incident_id}/assistant")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "assistant_prepared"
    assert payload["suggested_spl"]
    assert payload["forecast_model"] == "hosted_time_series_ready"
    assert payload["forecast_latency_ms"] > 0

    assert Path(tmp_path / "ai_assistant.log").exists()
    assert Path(tmp_path / "forecast.log").exists()

    assistant_events = [
        json.loads(line)
        for line in (tmp_path / "ai_assistant.log")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    forecast_events = [
        json.loads(line)
        for line in (tmp_path / "forecast.log").read_text(encoding="utf-8").splitlines()
    ]
    assert assistant_events[-1]["sourcetype"] == "aiops-ai-assistant"
    assert "signal_count" in assistant_events[-1]["suggested_spl"]
    assert forecast_events[-1]["sourcetype"] == "aiops-forecast"
    assert forecast_events[-1]["model_name"] == "hosted_time_series_ready"
    assert "timechart" in forecast_events[-1]["hosted_model_query"]


def test_dashboard_exposes_remediation_actions(monkeypatch) -> None:
    tmp_path = Path(".testdata") / f"test_dashboard_{uuid4().hex}"
    tmp_path.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "APP_LOG_PATH", tmp_path / "app.log")
    monkeypatch.setattr(config, "INCIDENT_STORE_PATH", tmp_path / "incidents.json")
    monkeypatch.setattr(config, "INCIDENT_LOG_PATH", tmp_path / "incidents.log")
    monkeypatch.setattr(
        config, "INVESTIGATION_LOG_PATH", tmp_path / "aiops_investigations.log"
    )
    monkeypatch.setattr(
        config, "REMEDIATION_LOG_PATH", tmp_path / "aiops_remediation.log"
    )

    import app.main as main
    import app.storage as storage
    import app.telemetry as telemetry

    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)
    monkeypatch.setattr(storage, "INCIDENT_STORE_PATH", tmp_path / "incidents.json")
    monkeypatch.setattr(storage, "INCIDENT_LOG_PATH", tmp_path / "incidents.log")
    monkeypatch.setattr(
        storage, "INVESTIGATION_LOG_PATH", tmp_path / "aiops_investigations.log"
    )
    monkeypatch.setattr(
        storage, "REMEDIATION_LOG_PATH", tmp_path / "aiops_remediation.log"
    )
    monkeypatch.setattr(telemetry, "DATA_DIR", tmp_path)
    monkeypatch.setattr(telemetry, "APP_LOG_PATH", tmp_path / "app.log")

    async def fake_query_incident_evidence(
        self, incident_id: str, service: str | None = None
    ) -> Evidence | None:
        return Evidence(
            service=service or "checkout-api",
            incident_id=incident_id,
            event_count=14,
            error_types=["database_timeout"],
            hosts=["checkout-01", "checkout-02"],
            endpoints=["/checkout"],
            dependencies=["postgres"],
            regions=["us-east"],
            avg_latency_ms=2400,
            max_latency_ms=3900,
            max_cpu_pct=74,
            max_memory_pct=81,
            max_db_pool_pct=97,
            deployment_versions=["2026.06.3"],
        )

    monkeypatch.setattr(
        main.SplunkMCPClient, "query_incident_evidence", fake_query_incident_evidence
    )
    monkeypatch.setattr(main, "_maybe_codex_enhancement", _fake_codex_enhancement)

    client = TestClient(main.app)
    created = client.post(
        "/incidents/create",
        json={"incident_type": "database_timeout", "inject_burst": False},
    )
    incident_id = created.json()["incident_id"]
    client.post(f"/incidents/{incident_id}/investigate")

    json_dashboard = client.get("/dashboard")
    assert json_dashboard.status_code == 200
    action_urls = json_dashboard.json()["recent_incidents"][0]["action_urls"]
    assert (
        action_urls["investigate"]
        == f"http://testserver/incidents/{incident_id}/investigate?refresh=1"
    )
    assert (
        action_urls["approve"] == f"http://testserver/incidents/{incident_id}/approve"
    )
    assert (
        action_urls["execute"] == f"http://testserver/incidents/{incident_id}/execute"
    )
    assert action_urls["reject"] == f"http://testserver/incidents/{incident_id}/reject"
    assert action_urls["close"] == f"http://testserver/incidents/{incident_id}/close"

    html_dashboard = client.get("/dashboard", headers={"accept": "text/html"})
    assert html_dashboard.status_code == 200
    assert '<meta http-equiv="refresh" content="15">' in html_dashboard.text
    assert "Last updated" in html_dashboard.text
    assert "Predicted Critical Incidents" in html_dashboard.text
    assert "Services At Risk" in html_dashboard.text
    assert "Avg Forecast Confidence" in html_dashboard.text
    assert "checkout" in html_dashboard.text
    assert "payment" in html_dashboard.text
    assert "auth" in html_dashboard.text
    assert "Investigate" in html_dashboard.text
    assert "Approve" in html_dashboard.text
    assert "noopener,noreferrer" not in html_dashboard.text
    assert "window.open(this.href, '_blank');" in html_dashboard.text
    assert "Select row for more" not in html_dashboard.text
    assert f"/incidents/{incident_id}/reject" in html_dashboard.text

    reinvestigated = client.post(
        f"/incidents/{incident_id}/investigate",
        headers={"accept": "text/html"},
        follow_redirects=False,
    )
    assert reinvestigated.status_code == 303
    assert reinvestigated.headers["location"] == "/dashboard"

    approved = client.post(
        f"/incidents/{incident_id}/approve",
        headers={"accept": "text/html"},
        follow_redirects=False,
    )
    assert approved.status_code == 303
    assert approved.headers["location"] == "/dashboard"

    rejected = client.post(f"/incidents/{incident_id}/reject")
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "REJECTED"
    assert rejected.json()["remediation_status"] == "REJECTED remediation"

    closed = client.post(f"/incidents/{incident_id}/close")
    assert closed.status_code == 409


def test_incident_table_ai_summary_prefers_ai_summary_and_falls_back_to_rca() -> None:
    import app.main as main

    assert (
        main._incident_table_ai_summary(
            {
                "ai_summary": "LLM summary for the incident",
                "root_cause": "database connection pool exhaustion",
            }
        )
        == "LLM summary for the incident"
    )

    fallback = main._incident_table_ai_summary(
        {
            "root_cause": "database connection pool exhaustion",
            "confidence_score": 0.94,
            "evidence_summary": "MCP evidence points to saturated DB connections.",
            "recommended_actions": [
                "Recycle saturated DB connections",
                "Escalate to database owner",
            ],
        }
    )
    assert fallback.startswith("AI summary unavailable. RCA fallback:")
    assert "Confidence 0.94." in fallback
    assert "MCP evidence points to saturated DB connections." in fallback
    assert "Recycle saturated DB connections" in fallback


def test_dashboard_prefers_ai_triage_summary_for_incident_table(monkeypatch) -> None:
    tmp_path = Path(".testdata") / f"test_ai_triage_summary_{uuid4().hex}"
    tmp_path.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "APP_LOG_PATH", tmp_path / "app.log")
    monkeypatch.setattr(config, "INCIDENT_STORE_PATH", tmp_path / "incidents.json")
    monkeypatch.setattr(config, "INCIDENT_LOG_PATH", tmp_path / "incidents.log")
    monkeypatch.setattr(
        config, "INVESTIGATION_LOG_PATH", tmp_path / "aiops_investigations.log"
    )
    monkeypatch.setattr(
        config, "REMEDIATION_LOG_PATH", tmp_path / "aiops_remediation.log"
    )
    monkeypatch.setattr(config, "AI_TRIAGE_LOG_PATH", tmp_path / "ai_triages.log")

    import app.main as main
    import app.storage as storage
    import app.telemetry as telemetry

    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)
    monkeypatch.setattr(storage, "INCIDENT_STORE_PATH", tmp_path / "incidents.json")
    monkeypatch.setattr(storage, "INCIDENT_LOG_PATH", tmp_path / "incidents.log")
    monkeypatch.setattr(
        storage, "INVESTIGATION_LOG_PATH", tmp_path / "aiops_investigations.log"
    )
    monkeypatch.setattr(
        storage, "REMEDIATION_LOG_PATH", tmp_path / "aiops_remediation.log"
    )
    monkeypatch.setattr(storage, "AI_TRIAGE_LOG_PATH", tmp_path / "ai_triages.log")
    monkeypatch.setattr(telemetry, "DATA_DIR", tmp_path)
    monkeypatch.setattr(telemetry, "APP_LOG_PATH", tmp_path / "app.log")

    client = TestClient(main.app)
    created = client.post(
        "/incidents/create",
        json={"incident_type": "database_timeout", "inject_burst": False},
    )
    incident_id = created.json()["incident_id"]

    storage.write_ai_triage_event(
        {
            "timestamp": "2026-06-14T12:00:00+00:00",
            "incident_id": incident_id,
            "service": "checkout-api",
            "ai_summary": "Codex MCP summary: checkout-api has saturated DB connections.",
        }
    )

    dashboard = client.get("/dashboard")
    assert dashboard.status_code == 200
    row = dashboard.json()["recent_incidents"][0]
    assert row["incident_id"] == incident_id
    assert row["ai_summary"].startswith("Codex MCP summary:")


def test_execute_and_close_pages_show_action_details(monkeypatch) -> None:
    tmp_path = Path(".testdata") / f"test_execute_close_{uuid4().hex}"
    tmp_path.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "APP_LOG_PATH", tmp_path / "app.log")
    monkeypatch.setattr(config, "INCIDENT_STORE_PATH", tmp_path / "incidents.json")
    monkeypatch.setattr(config, "INCIDENT_LOG_PATH", tmp_path / "incidents.log")
    monkeypatch.setattr(
        config, "INVESTIGATION_LOG_PATH", tmp_path / "aiops_investigations.log"
    )
    monkeypatch.setattr(
        config, "REMEDIATION_LOG_PATH", tmp_path / "aiops_remediation.log"
    )

    import app.main as main
    import app.storage as storage
    import app.telemetry as telemetry

    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)
    monkeypatch.setattr(storage, "INCIDENT_STORE_PATH", tmp_path / "incidents.json")
    monkeypatch.setattr(storage, "INCIDENT_LOG_PATH", tmp_path / "incidents.log")
    monkeypatch.setattr(
        storage, "INVESTIGATION_LOG_PATH", tmp_path / "aiops_investigations.log"
    )
    monkeypatch.setattr(
        storage, "REMEDIATION_LOG_PATH", tmp_path / "aiops_remediation.log"
    )
    monkeypatch.setattr(telemetry, "DATA_DIR", tmp_path)
    monkeypatch.setattr(telemetry, "APP_LOG_PATH", tmp_path / "app.log")

    async def fake_query_incident_evidence(
        self, incident_id: str, service: str | None = None
    ) -> Evidence | None:
        return Evidence(
            service=service or "checkout-api",
            incident_id=incident_id,
            event_count=14,
            error_types=["database_timeout"],
            hosts=["checkout-01", "checkout-02"],
            endpoints=["/checkout"],
            dependencies=["postgres"],
            regions=["us-east"],
            avg_latency_ms=2400,
            max_latency_ms=3900,
            max_cpu_pct=74,
            max_memory_pct=81,
            max_db_pool_pct=97,
            deployment_versions=["2026.06.3"],
        )

    monkeypatch.setattr(
        main.SplunkMCPClient, "query_incident_evidence", fake_query_incident_evidence
    )
    monkeypatch.setattr(main, "_maybe_codex_enhancement", _fake_codex_enhancement)

    client = TestClient(main.app)
    created = client.post(
        "/incidents/create",
        json={"incident_type": "database_timeout", "inject_burst": False},
    )
    incident_id = created.json()["incident_id"]

    client.post(f"/incidents/{incident_id}/investigate")
    client.post(f"/incidents/{incident_id}/approve", json={"approved_by": "tester"})

    executed = client.get(
        f"/incidents/{incident_id}/execute", headers={"accept": "text/html"}
    )
    assert executed.status_code == 200
    assert "Actions executed" in executed.text
    assert "Execution summary" in executed.text
    assert "SIMULATE:" in executed.text

    closed = client.get(f"/incidents/{incident_id}/close", headers={"accept": "text/html"})
    assert closed.status_code == 200
    assert "Ticket closed" in closed.text
    assert "Remediation executed" in closed.text
    assert "Yes" in closed.text


def test_investigation_source_labels_are_normalized() -> None:
    import app.main as main

    counts = main._investigation_source_counts(
        [
            {"investigation_source": "codex_mcp_agent"},
            {"llm_provider": "rules_fallback_after_ai_unavailable"},
            {"investigation_source": "https://127.0.0.1:8089/services/mcp"},
        ]
    )

    assert counts == {
        "Codex MCP agent": 1,
        "Deterministic fallback": 1,
        "Webhook triage": 1,
    }


def test_splunk_dashboard_action_links(monkeypatch) -> None:
    tmp_path = Path(".testdata") / f"test_splunk_links_{uuid4().hex}"
    tmp_path.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "APP_LOG_PATH", tmp_path / "app.log")
    monkeypatch.setattr(config, "INCIDENT_STORE_PATH", tmp_path / "incidents.json")
    monkeypatch.setattr(config, "INCIDENT_LOG_PATH", tmp_path / "incidents.log")
    monkeypatch.setattr(
        config, "INVESTIGATION_LOG_PATH", tmp_path / "aiops_investigations.log"
    )
    monkeypatch.setattr(
        config, "REMEDIATION_LOG_PATH", tmp_path / "aiops_remediation.log"
    )

    import app.main as main
    import app.storage as storage
    import app.telemetry as telemetry

    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)
    monkeypatch.setattr(storage, "INCIDENT_STORE_PATH", tmp_path / "incidents.json")
    monkeypatch.setattr(storage, "INCIDENT_LOG_PATH", tmp_path / "incidents.log")
    monkeypatch.setattr(
        storage, "INVESTIGATION_LOG_PATH", tmp_path / "aiops_investigations.log"
    )
    monkeypatch.setattr(
        storage, "REMEDIATION_LOG_PATH", tmp_path / "aiops_remediation.log"
    )
    monkeypatch.setattr(telemetry, "DATA_DIR", tmp_path)
    monkeypatch.setattr(telemetry, "APP_LOG_PATH", tmp_path / "app.log")

    async def fake_query_incident_evidence(
        self, incident_id: str, service: str | None = None
    ) -> Evidence | None:
        return Evidence(
            service=service or "checkout-api",
            incident_id=incident_id,
            event_count=14,
            error_types=["database_timeout"],
            hosts=["checkout-01", "checkout-02"],
            endpoints=["/checkout"],
            dependencies=["postgres"],
            regions=["us-east"],
            avg_latency_ms=2400,
            max_latency_ms=3900,
            max_cpu_pct=74,
            max_memory_pct=81,
            max_db_pool_pct=97,
            deployment_versions=["2026.06.3"],
        )

    monkeypatch.setattr(
        main.SplunkMCPClient, "query_incident_evidence", fake_query_incident_evidence
    )
    monkeypatch.setattr(main, "_maybe_codex_enhancement", _fake_codex_enhancement)

    client = TestClient(main.app)
    created = client.post(
        "/incidents/create",
        json={"incident_type": "database_timeout", "inject_burst": False},
    )
    incident_id = created.json()["incident_id"]

    investigated = client.get(f"/incidents/{incident_id}/investigate")
    assert investigated.status_code == 200
    assert investigated.json()["status"] == "COMPLETED"

    approved = client.get(f"/incidents/{incident_id}/approve")
    assert approved.status_code == 200
    assert approved.json()["status"] == "APPROVED"

    executed = client.get(f"/incidents/{incident_id}/execute")
    assert executed.status_code == 200
    assert executed.json()["status"] == "EXECUTED"


def test_missing_incident_can_be_hydrated_from_mcp(monkeypatch) -> None:
    tmp_path = Path(".testdata") / f"test_mcp_hydration_{uuid4().hex}"
    tmp_path.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "APP_LOG_PATH", tmp_path / "app.log")
    monkeypatch.setattr(config, "INCIDENT_STORE_PATH", tmp_path / "incidents.json")
    monkeypatch.setattr(config, "INCIDENT_LOG_PATH", tmp_path / "incidents.log")
    monkeypatch.setattr(
        config, "INVESTIGATION_LOG_PATH", tmp_path / "aiops_investigations.log"
    )
    monkeypatch.setattr(
        config, "REMEDIATION_LOG_PATH", tmp_path / "aiops_remediation.log"
    )

    import app.main as main
    import app.storage as storage
    import app.telemetry as telemetry

    async def fake_query_incident_evidence(
        self, incident_id: str, service: str | None = None
    ) -> Evidence | None:
        return Evidence(
            service=service or "checkout-api",
            incident_id=incident_id,
            event_count=14,
            error_types=["database_timeout"],
            hosts=["checkout-01", "checkout-02"],
            endpoints=["/checkout"],
            dependencies=["postgres"],
            regions=["us-east"],
            avg_latency_ms=2400,
            max_latency_ms=3900,
            max_cpu_pct=74,
            max_memory_pct=81,
            max_db_pool_pct=97,
            deployment_versions=["2026.06.3"],
        )

    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)
    monkeypatch.setattr(storage, "INCIDENT_STORE_PATH", tmp_path / "incidents.json")
    monkeypatch.setattr(storage, "INCIDENT_LOG_PATH", tmp_path / "incidents.log")
    monkeypatch.setattr(
        storage, "INVESTIGATION_LOG_PATH", tmp_path / "aiops_investigations.log"
    )
    monkeypatch.setattr(
        storage, "REMEDIATION_LOG_PATH", tmp_path / "aiops_remediation.log"
    )
    monkeypatch.setattr(telemetry, "DATA_DIR", tmp_path)
    monkeypatch.setattr(telemetry, "APP_LOG_PATH", tmp_path / "app.log")
    monkeypatch.setattr(
        main.SplunkMCPClient, "query_incident_evidence", fake_query_incident_evidence
    )
    monkeypatch.setattr(main, "_maybe_codex_enhancement", _fake_codex_enhancement)

    client = TestClient(main.app)
    response = client.get(
        "/incidents/inc-59cca2f038/investigate", headers={"accept": "application/json"}
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "COMPLETED"
    assert payload["evidence_summary"]
    assert payload["mcp_evidence_summary"].startswith("MCP client call:")
    assert payload["evidence_summary"] != payload["mcp_evidence_summary"]
    assert "database connection pool exhaustion" not in payload["mcp_evidence_summary"]
    assert payload["incident_id"] == "inc-59cca2f038"


def test_investigation_result_refreshes_opener_dashboard(monkeypatch) -> None:
    tmp_path = Path(".testdata") / f"test_opener_refresh_{uuid4().hex}"
    tmp_path.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "APP_LOG_PATH", tmp_path / "app.log")
    monkeypatch.setattr(config, "INCIDENT_STORE_PATH", tmp_path / "incidents.json")
    monkeypatch.setattr(config, "INCIDENT_LOG_PATH", tmp_path / "incidents.log")
    monkeypatch.setattr(
        config, "INVESTIGATION_LOG_PATH", tmp_path / "aiops_investigations.log"
    )
    monkeypatch.setattr(
        config, "REMEDIATION_LOG_PATH", tmp_path / "aiops_remediation.log"
    )

    import app.main as main
    import app.storage as storage
    import app.telemetry as telemetry

    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)
    monkeypatch.setattr(storage, "INCIDENT_STORE_PATH", tmp_path / "incidents.json")
    monkeypatch.setattr(storage, "INCIDENT_LOG_PATH", tmp_path / "incidents.log")
    monkeypatch.setattr(
        storage, "INVESTIGATION_LOG_PATH", tmp_path / "aiops_investigations.log"
    )
    monkeypatch.setattr(
        storage, "REMEDIATION_LOG_PATH", tmp_path / "aiops_remediation.log"
    )
    monkeypatch.setattr(telemetry, "DATA_DIR", tmp_path)
    monkeypatch.setattr(telemetry, "APP_LOG_PATH", tmp_path / "app.log")

    async def fake_query_incident_evidence(
        self, incident_id: str, service: str | None = None
    ) -> Evidence | None:
        return Evidence(
            service=service or "checkout-api",
            incident_id=incident_id,
            event_count=14,
            error_types=["database_timeout"],
            hosts=["checkout-01", "checkout-02"],
            endpoints=["/checkout"],
            dependencies=["postgres"],
            regions=["us-east"],
            avg_latency_ms=2400,
            max_latency_ms=3900,
            max_cpu_pct=74,
            max_memory_pct=81,
            max_db_pool_pct=97,
            deployment_versions=["2026.06.3"],
        )

    monkeypatch.setattr(
        main.SplunkMCPClient, "query_incident_evidence", fake_query_incident_evidence
    )
    monkeypatch.setattr(main, "_maybe_codex_enhancement", _fake_codex_enhancement)

    client = TestClient(main.app)
    created = client.post(
        "/incidents/create",
        json={"incident_type": "database_timeout", "inject_burst": False},
    )
    incident_id = created.json()["incident_id"]

    response = client.get(
        f"/incidents/{incident_id}/investigate", headers={"accept": "text/html"}
    )

    assert response.status_code == 200
    assert "Investigation completed" in response.text
    assert "MCP evidence" in response.text
    assert "window.opener.location.reload" in response.text


def test_investigation_refreshes_stale_fallback_summary(monkeypatch) -> None:
    tmp_path = Path(".testdata") / f"test_refresh_stale_summary_{uuid4().hex}"
    tmp_path.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "APP_LOG_PATH", tmp_path / "app.log")
    monkeypatch.setattr(config, "INCIDENT_STORE_PATH", tmp_path / "incidents.json")
    monkeypatch.setattr(config, "INCIDENT_LOG_PATH", tmp_path / "incidents.log")
    monkeypatch.setattr(
        config, "INVESTIGATION_LOG_PATH", tmp_path / "aiops_investigations.log"
    )
    monkeypatch.setattr(
        config, "REMEDIATION_LOG_PATH", tmp_path / "aiops_remediation.log"
    )

    import app.main as main
    import app.storage as storage
    import app.telemetry as telemetry

    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)
    monkeypatch.setattr(storage, "INCIDENT_STORE_PATH", tmp_path / "incidents.json")
    monkeypatch.setattr(storage, "INCIDENT_LOG_PATH", tmp_path / "incidents.log")
    monkeypatch.setattr(
        storage, "INVESTIGATION_LOG_PATH", tmp_path / "aiops_investigations.log"
    )
    monkeypatch.setattr(
        storage, "REMEDIATION_LOG_PATH", tmp_path / "aiops_remediation.log"
    )
    monkeypatch.setattr(telemetry, "DATA_DIR", tmp_path)
    monkeypatch.setattr(telemetry, "APP_LOG_PATH", tmp_path / "app.log")

    async def fake_query_incident_evidence(
        self, incident_id: str, service: str | None = None
    ) -> Evidence | None:
        return Evidence(
            service=service or "checkout-api",
            incident_id=incident_id,
            event_count=12,
            error_types=["database_timeout"],
            hosts=["checkout-01"],
            endpoints=["/checkout"],
            dependencies=["postgres"],
            regions=["us-east"],
            avg_latency_ms=2600,
            max_latency_ms=4100,
            max_cpu_pct=82,
            max_memory_pct=79,
            max_db_pool_pct=98,
            deployment_versions=["2026.06.3"],
        )

    monkeypatch.setattr(
        main.SplunkMCPClient, "query_incident_evidence", fake_query_incident_evidence
    )
    monkeypatch.setattr(main, "_maybe_codex_enhancement", _fake_codex_enhancement)

    def fake_codex_refresh(**kwargs):
        incident = kwargs["incident"]
        return InvestigationResult(
            incident_id=incident.incident_id,
            service=incident.service,
            severity="HIGH",
            root_cause="database connection pool exhaustion",
            confidence_score=0.96,
            evidence_summary="Fresh MCP evidence confirms saturated database connections.",
            ai_summary="Codex fresh summary: checkout-api is blocked by saturated database connections.",
            recommended_actions=["Recycle saturated DB connections"],
            safe_remediation_actions=["SIMULATE: Recycle saturated DB connections"],
            source="codex_mcp_agent",
            mcp_investigation=True,
            mcp_tools_used=["splunk_run_query"],
            spl_queries_used=["index=main sourcetype=agentic-ops"],
            mcp_log_event_count=12,
        )

    monkeypatch.setattr(main, "_maybe_codex_enhancement", fake_codex_refresh)

    client = TestClient(main.app)
    created = client.post(
        "/incidents/create",
        json={"incident_type": "database_timeout", "inject_burst": False},
    )
    incident_id = created.json()["incident_id"]

    stale_incident = storage.load_incidents()[incident_id]
    stale_incident.ai_summary = "Old RCA fallback summary"
    stale_incident.fallback_rca_summary = "Old fallback RCA summary"
    storage.upsert_incident(stale_incident)

    response = client.get(
        f"/incidents/{incident_id}/investigate", headers={"accept": "text/html"}
    )

    assert response.status_code == 200
    assert "Codex fresh summary:" in response.text
    assert "Old RCA fallback summary" not in response.text
    refreshed = storage.load_incidents()[incident_id]
    assert refreshed.ai_summary == (
        "Codex fresh summary: checkout-api is blocked by saturated database connections."
    )
    assert refreshed.fallback_rca_summary is None
    assert refreshed.mcp_evidence_summary is not None
    assert "MCP evidence" in refreshed.mcp_evidence_summary


def test_investigation_report_prefers_latest_triage_summary(monkeypatch) -> None:
    tmp_path = Path(".testdata") / f"test_report_triage_summary_{uuid4().hex}"
    tmp_path.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "APP_LOG_PATH", tmp_path / "app.log")
    monkeypatch.setattr(config, "INCIDENT_STORE_PATH", tmp_path / "incidents.json")
    monkeypatch.setattr(config, "INCIDENT_LOG_PATH", tmp_path / "incidents.log")
    monkeypatch.setattr(
        config, "INVESTIGATION_LOG_PATH", tmp_path / "aiops_investigations.log"
    )
    monkeypatch.setattr(
        config, "REMEDIATION_LOG_PATH", tmp_path / "aiops_remediation.log"
    )
    monkeypatch.setattr(config, "AI_TRIAGE_LOG_PATH", tmp_path / "ai_triages.log")

    import app.main as main
    import app.storage as storage
    import app.telemetry as telemetry

    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)
    monkeypatch.setattr(storage, "INCIDENT_STORE_PATH", tmp_path / "incidents.json")
    monkeypatch.setattr(storage, "INCIDENT_LOG_PATH", tmp_path / "incidents.log")
    monkeypatch.setattr(
        storage, "INVESTIGATION_LOG_PATH", tmp_path / "aiops_investigations.log"
    )
    monkeypatch.setattr(
        storage, "REMEDIATION_LOG_PATH", tmp_path / "aiops_remediation.log"
    )
    monkeypatch.setattr(storage, "AI_TRIAGE_LOG_PATH", tmp_path / "ai_triages.log")
    monkeypatch.setattr(telemetry, "DATA_DIR", tmp_path)
    monkeypatch.setattr(telemetry, "APP_LOG_PATH", tmp_path / "app.log")

    client = TestClient(main.app)
    created = client.post(
        "/incidents/create",
        json={"incident_type": "database_timeout", "inject_burst": False},
    )
    assert created.status_code == 200
    incident_id = created.json()["incident_id"]

    incident = storage.load_incidents()[incident_id]
    incident.root_cause = "database connection pool exhaustion"
    incident.confidence_score = 0.95
    incident.evidence_summary = "Fresh evidence from Splunk."
    incident.ai_summary = "Stale fallback summary"
    incident.fallback_rca_summary = "Stale fallback RCA"
    storage.upsert_incident(incident)

    storage.write_ai_triage_event(
        {
            "timestamp": "2026-06-14T12:00:00+05:30",
            "incident_id": incident_id,
            "service": incident.service,
            "ai_summary": "Codex fresh summary: checkout-api is blocked by saturated database connections.",
            "llm_provider": "codex_mcp_agent",
            "sourcetype": "ai-mcp-triage-agent",
        }
    )

    response = client.get(
        f"/incidents/{incident_id}/investigate/report", headers={"accept": "text/html"}
    )

    assert response.status_code == 200
    assert "Codex fresh summary:" in response.text
    assert "Stale fallback summary" not in response.text


def test_investigation_report_prefers_latest_mcp_evidence_summary(monkeypatch) -> None:
    tmp_path = Path(".testdata") / f"test_report_mcp_summary_{uuid4().hex}"
    tmp_path.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "APP_LOG_PATH", tmp_path / "app.log")
    monkeypatch.setattr(config, "INCIDENT_STORE_PATH", tmp_path / "incidents.json")
    monkeypatch.setattr(config, "INCIDENT_LOG_PATH", tmp_path / "incidents.log")
    monkeypatch.setattr(
        config, "INVESTIGATION_LOG_PATH", tmp_path / "aiops_investigations.log"
    )
    monkeypatch.setattr(
        config, "REMEDIATION_LOG_PATH", tmp_path / "aiops_remediation.log"
    )
    monkeypatch.setattr(config, "AI_TRIAGE_LOG_PATH", tmp_path / "ai_triages.log")

    import app.main as main
    import app.storage as storage
    import app.telemetry as telemetry

    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)
    monkeypatch.setattr(storage, "INCIDENT_STORE_PATH", tmp_path / "incidents.json")
    monkeypatch.setattr(storage, "INCIDENT_LOG_PATH", tmp_path / "incidents.log")
    monkeypatch.setattr(
        storage, "INVESTIGATION_LOG_PATH", tmp_path / "aiops_investigations.log"
    )
    monkeypatch.setattr(
        storage, "REMEDIATION_LOG_PATH", tmp_path / "aiops_remediation.log"
    )
    monkeypatch.setattr(storage, "AI_TRIAGE_LOG_PATH", tmp_path / "ai_triages.log")
    monkeypatch.setattr(telemetry, "DATA_DIR", tmp_path)
    monkeypatch.setattr(telemetry, "APP_LOG_PATH", tmp_path / "app.log")

    client = TestClient(main.app)
    created = client.post(
        "/incidents/create",
        json={"incident_type": "database_timeout", "inject_burst": False},
    )
    assert created.status_code == 200
    incident_id = created.json()["incident_id"]

    incident = storage.load_incidents()[incident_id]
    incident.mcp_evidence_summary = None
    incident.root_cause = "database connection pool exhaustion"
    incident.confidence_score = 0.95
    incident.evidence_summary = "Fresh evidence from Splunk."
    storage.upsert_incident(incident)

    storage.write_investigation_event(
        {
            "timestamp": "2026-06-14T12:00:00+05:30",
            "incident_id": incident_id,
            "service": incident.service,
            "mcp_evidence_summary": "MCP client call: MCP evidence for checkout-api: 14 events; errors=database_timeout; hosts=checkout-01; endpoints=/checkout; dependencies=postgres; avg_latency_ms=2400; max_latency_ms=3900; max_cpu_pct=74; max_db_pool_pct=97.",
            "sourcetype": "aiops-investigations",
        }
    )

    response = client.get(
        f"/incidents/{incident_id}/investigate/report", headers={"accept": "text/html"}
    )

    assert response.status_code == 200
    assert "MCP client call:" in response.text
    assert "Pending investigation / no MCP evidence yet." not in response.text


def test_remediation_log_includes_investigation_context(monkeypatch) -> None:
    tmp_path = Path(".testdata") / f"test_remediation_context_{uuid4().hex}"
    tmp_path.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "APP_LOG_PATH", tmp_path / "app.log")
    monkeypatch.setattr(config, "INCIDENT_STORE_PATH", tmp_path / "incidents.json")
    monkeypatch.setattr(config, "INCIDENT_LOG_PATH", tmp_path / "incidents.log")
    monkeypatch.setattr(
        config, "INVESTIGATION_LOG_PATH", tmp_path / "aiops_investigations.log"
    )
    monkeypatch.setattr(
        config, "REMEDIATION_LOG_PATH", tmp_path / "aiops_remediation.log"
    )

    import app.main as main
    import app.storage as storage
    import app.telemetry as telemetry

    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)
    monkeypatch.setattr(storage, "INCIDENT_STORE_PATH", tmp_path / "incidents.json")
    monkeypatch.setattr(storage, "INCIDENT_LOG_PATH", tmp_path / "incidents.log")
    monkeypatch.setattr(
        storage, "INVESTIGATION_LOG_PATH", tmp_path / "aiops_investigations.log"
    )
    monkeypatch.setattr(
        storage, "REMEDIATION_LOG_PATH", tmp_path / "aiops_remediation.log"
    )
    monkeypatch.setattr(telemetry, "DATA_DIR", tmp_path)
    monkeypatch.setattr(telemetry, "APP_LOG_PATH", tmp_path / "app.log")

    async def fake_query_incident_evidence(
        self, incident_id: str, service: str | None = None
    ) -> Evidence | None:
        return Evidence(
            service=service or "checkout-api",
            incident_id=incident_id,
            event_count=14,
            error_types=["database_timeout"],
            hosts=["checkout-01", "checkout-02"],
            endpoints=["/checkout"],
            dependencies=["postgres"],
            regions=["us-east"],
            avg_latency_ms=2400,
            max_latency_ms=3900,
            max_cpu_pct=74,
            max_memory_pct=81,
            max_db_pool_pct=97,
            deployment_versions=["2026.06.3"],
        )

    monkeypatch.setattr(
        main.SplunkMCPClient, "query_incident_evidence", fake_query_incident_evidence
    )

    client = TestClient(main.app)
    created = client.post(
        "/incidents/create",
        json={"incident_type": "database_timeout", "inject_burst": False},
    )
    incident_id = created.json()["incident_id"]

    investigated = client.post(f"/incidents/{incident_id}/investigate")
    assert investigated.status_code == 200

    approved = client.post(
        f"/incidents/{incident_id}/approve", json={"approved_by": "tester"}
    )
    assert approved.status_code == 200

    executed = client.post(f"/incidents/{incident_id}/execute")
    assert executed.status_code == 200

    remediation_lines = (
        (tmp_path / "aiops_remediation.log").read_text(encoding="utf-8").splitlines()
    )
    assert remediation_lines
    last_event = json.loads(remediation_lines[-1])
    assert last_event["mcp_evidence_summary"].startswith("MCP client call:")
    assert last_event["evidence_summary"]
    assert last_event["mcp_investigation"] is True


def test_investigation_log_exposes_workflow_status(monkeypatch) -> None:
    tmp_path = Path(".testdata") / f"test_investigation_status_{uuid4().hex}"
    tmp_path.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "APP_LOG_PATH", tmp_path / "app.log")
    monkeypatch.setattr(config, "INCIDENT_STORE_PATH", tmp_path / "incidents.json")
    monkeypatch.setattr(
        config, "INVESTIGATION_LOG_PATH", tmp_path / "aiops_investigations.log"
    )
    monkeypatch.setattr(
        config, "REMEDIATION_LOG_PATH", tmp_path / "aiops_remediation.log"
    )
    monkeypatch.setattr(config, "AI_TRIAGE_LOG_PATH", tmp_path / "ai_triages.log")

    import app.main as main
    import app.storage as storage
    import app.telemetry as telemetry

    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)
    monkeypatch.setattr(storage, "INCIDENT_STORE_PATH", tmp_path / "incidents.json")
    monkeypatch.setattr(
        storage, "INVESTIGATION_LOG_PATH", tmp_path / "aiops_investigations.log"
    )
    monkeypatch.setattr(
        storage, "REMEDIATION_LOG_PATH", tmp_path / "aiops_remediation.log"
    )
    monkeypatch.setattr(storage, "AI_TRIAGE_LOG_PATH", tmp_path / "ai_triages.log")
    monkeypatch.setattr(telemetry, "DATA_DIR", tmp_path)
    monkeypatch.setattr(telemetry, "APP_LOG_PATH", tmp_path / "app.log")

    async def fake_query_incident_evidence(
        self, incident_id: str, service: str | None = None
    ) -> Evidence | None:
        return Evidence(
            service=service or "checkout-api",
            incident_id=incident_id,
            event_count=14,
            error_types=["database_timeout"],
            hosts=["checkout-01", "checkout-02"],
            endpoints=["/checkout"],
            dependencies=["postgres"],
            regions=["us-east"],
            avg_latency_ms=2400,
            max_latency_ms=3900,
            max_cpu_pct=74,
            max_memory_pct=81,
            max_db_pool_pct=97,
            deployment_versions=["2026.06.3"],
        )

    monkeypatch.setattr(
        main.SplunkMCPClient, "query_incident_evidence", fake_query_incident_evidence
    )

    client = TestClient(main.app)
    created = client.post(
        "/incidents/create",
        json={"incident_type": "database_timeout", "inject_burst": False},
    )
    incident_id = created.json()["incident_id"]

    client.post(f"/incidents/{incident_id}/investigate")

    investigation_lines = (
        (tmp_path / "aiops_investigations.log").read_text(encoding="utf-8").splitlines()
    )
    assert investigation_lines
    events = [json.loads(line) for line in investigation_lines]
    assert {event["status"] for event in events} == {"STARTED", "COMPLETED"}
    assert all(event["incident_status"] == "COMPLETED" for event in events[1:])

    triage_lines = (
        (tmp_path / "ai_triages.log").read_text(encoding="utf-8").splitlines()
    )
    assert triage_lines
    triage_event = json.loads(triage_lines[-1])
    assert triage_event["incident_id"] == incident_id
    assert triage_event["ai_summary"]
    assert triage_event["mcp_evidence_summary"].startswith("MCP client call:")


def test_splunk_webhook_triages_alert_with_mcp_context(monkeypatch) -> None:
    tmp_path = Path(".testdata") / f"test_webhook_triage_{uuid4().hex}"
    tmp_path.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "INCIDENT_STORE_PATH", tmp_path / "incidents.json")
    monkeypatch.setattr(config, "INCIDENT_LOG_PATH", tmp_path / "incidents.log")
    monkeypatch.setattr(
        config, "INVESTIGATION_LOG_PATH", tmp_path / "aiops_investigations.log"
    )
    monkeypatch.setattr(
        config, "REMEDIATION_LOG_PATH", tmp_path / "aiops_remediation.log"
    )
    monkeypatch.setattr(config, "AI_TRIAGE_LOG_PATH", tmp_path / "ai_triages.log")

    import app.main as main
    import app.storage as storage

    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)
    monkeypatch.setattr(storage, "INCIDENT_STORE_PATH", tmp_path / "incidents.json")
    monkeypatch.setattr(storage, "INCIDENT_LOG_PATH", tmp_path / "incidents.log")
    monkeypatch.setattr(
        storage, "INVESTIGATION_LOG_PATH", tmp_path / "aiops_investigations.log"
    )
    monkeypatch.setattr(
        storage, "REMEDIATION_LOG_PATH", tmp_path / "aiops_remediation.log"
    )
    monkeypatch.setattr(storage, "AI_TRIAGE_LOG_PATH", tmp_path / "ai_triages.log")

    async def fake_query_incident_evidence(
        self, incident_id: str, service: str | None = None
    ) -> Evidence | None:
        return None

    async def fake_query_alert_logs(self, **kwargs) -> list[dict[str, object]]:
        return [
            {
                "service": "checkout-api",
                "host": "checkout-01",
                "endpoint": "/checkout",
                "error_type": "database_timeout",
                "dependency": "postgres",
                "latency_ms": 3100,
                "db_connection_pool_pct": 98,
            },
            {
                "service": "checkout-api",
                "host": "checkout-02",
                "endpoint": "/checkout",
                "error_type": "database_timeout",
                "dependency": "postgres",
                "latency_ms": 3400,
                "db_connection_pool_pct": 96,
            },
        ]

    async def fake_save_ai_summary_to_splunk(**kwargs) -> dict[str, str]:
        return {"status": "saved", "index": "ai_triages"}

    def fake_analyze(self, **kwargs) -> InvestigationResult:
        return InvestigationResult(
            incident_id=kwargs["incident"].incident_id,
            service=kwargs["incident"].service,
            severity="HIGH",
            root_cause="database connection pool exhaustion",
            confidence_score=0.92,
            evidence_summary="Codex correlated 2 timeout events around the alert window.",
            ai_summary="Codex RCA: checkout-api is failing due to database pool exhaustion; scale workers and recycle connections.",
            recommended_actions=[
                "Recycle saturated DB connections",
                "Scale checkout-api workers",
                "Escalate to database owner",
            ],
            safe_remediation_actions=[
                "SIMULATE: Recycle saturated DB connections",
                "SIMULATE: Scale checkout-api workers",
                "SIMULATE: Escalate to database owner",
            ],
            source="codex",
            raw_response='{"root_cause":"database connection pool exhaustion"}',
        )

    monkeypatch.setattr(
        main.SplunkMCPClient, "query_incident_evidence", fake_query_incident_evidence
    )
    monkeypatch.setattr(main.SplunkMCPClient, "query_alert_logs", fake_query_alert_logs)
    monkeypatch.setattr(main.CodexRcaAgent, "analyze", fake_analyze)
    monkeypatch.setattr(
        main, "save_ai_summary_to_splunk", fake_save_ai_summary_to_splunk
    )

    client = TestClient(main.app)
    response = client.post(
        "/webhook/splunk-alert",
        json={
            "search_name": "High database timeout rate",
            "host": "checkout-01",
            "service": "checkout-api",
            "trigger_time": "2026-06-09T10:00:00Z",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "incident_triaged"
    assert payload["mcp_tool_used"] is True
    assert payload["mcp_log_event_count"] == 2
    assert payload["llm_provider"] == "codex"
    assert "pool exhaustion" in payload["diagnosis"]

    triage_lines = (
        (tmp_path / "ai_triages.log").read_text(encoding="utf-8").splitlines()
    )
    assert triage_lines
    triage_event = json.loads(triage_lines[-1])
    assert triage_event["sourcetype"] == "ai-mcp-triage-agent"
    assert triage_event["llm_provider"] == "codex"
    assert triage_event["ai_summary"].startswith("Codex RCA:")
    assert triage_event["hec_status"]["status"] == "saved"


def test_splunk_webhook_skips_hec_when_not_configured(monkeypatch) -> None:
    tmp_path = Path(".testdata") / f"test_webhook_no_hec_{uuid4().hex}"
    tmp_path.mkdir(parents=True, exist_ok=True)

    monkeypatch.delenv("SPLUNK_HEC_URL", raising=False)
    monkeypatch.delenv("SPLUNK_HEC_TOKEN", raising=False)
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "INCIDENT_STORE_PATH", tmp_path / "incidents.json")
    monkeypatch.setattr(config, "INCIDENT_LOG_PATH", tmp_path / "incidents.log")
    monkeypatch.setattr(
        config, "INVESTIGATION_LOG_PATH", tmp_path / "aiops_investigations.log"
    )
    monkeypatch.setattr(
        config, "REMEDIATION_LOG_PATH", tmp_path / "aiops_remediation.log"
    )
    monkeypatch.setattr(config, "AI_TRIAGE_LOG_PATH", tmp_path / "ai_triages.log")

    import app.main as main
    import app.storage as storage

    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)
    monkeypatch.setattr(storage, "INCIDENT_STORE_PATH", tmp_path / "incidents.json")
    monkeypatch.setattr(storage, "INCIDENT_LOG_PATH", tmp_path / "incidents.log")
    monkeypatch.setattr(
        storage, "INVESTIGATION_LOG_PATH", tmp_path / "aiops_investigations.log"
    )
    monkeypatch.setattr(
        storage, "REMEDIATION_LOG_PATH", tmp_path / "aiops_remediation.log"
    )
    monkeypatch.setattr(storage, "AI_TRIAGE_LOG_PATH", tmp_path / "ai_triages.log")

    async def fake_query_incident_evidence(
        self, incident_id: str, service: str | None = None
    ) -> Evidence | None:
        return None

    async def fake_query_alert_logs(self, **kwargs) -> list[dict[str, object]]:
        return []

    def fake_analyze(self, **kwargs) -> InvestigationResult:
        return InvestigationResult(
            incident_id=kwargs["incident"].incident_id,
            service=kwargs["incident"].service,
            severity="MEDIUM",
            root_cause="latency regression under load",
            confidence_score=0.71,
            evidence_summary="Codex found no direct MCP rows and used the alert context.",
            ai_summary="Codex RCA: latency regression under load; keep monitoring and inspect the slow endpoint.",
            recommended_actions=[
                "Scale service instances",
                "Warm cache",
                "Inspect slow endpoint",
            ],
            safe_remediation_actions=[
                "SIMULATE: Scale service instances",
                "SIMULATE: Warm cache",
                "SIMULATE: Inspect slow endpoint",
            ],
            source="codex",
            raw_response='{"root_cause":"latency regression under load"}',
        )

    monkeypatch.setattr(
        main.SplunkMCPClient, "query_incident_evidence", fake_query_incident_evidence
    )
    monkeypatch.setattr(main.SplunkMCPClient, "query_alert_logs", fake_query_alert_logs)
    monkeypatch.setattr(main.CodexRcaAgent, "analyze", fake_analyze)

    client = TestClient(main.app)
    response = client.post(
        "/webhook/splunk-alert",
        json={
            "search_name": "Latency regression alert",
            "result": {"host": "checkout-03", "service": "checkout-api"},
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["hec_status"] == {
        "status": "skipped",
        "reason": "hec_not_configured",
    }
    assert payload["mcp_tool_used"] is False
    assert payload["llm_provider"] == "codex"

    triage_event = json.loads(
        (tmp_path / "ai_triages.log").read_text(encoding="utf-8").splitlines()[-1]
    )
    assert triage_event["hec_status"]["status"] == "skipped"
    assert triage_event["llm_provider"] == "codex"
