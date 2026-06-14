from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field

IncidentStatus = Literal[
    "OPEN", "INVESTIGATED", "COMPLETED", "APPROVED", "REJECTED", "EXECUTED", "CLOSED"
]
Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def local_now() -> datetime:
    return datetime.now().astimezone()


def log_timestamp() -> str:
    return local_now().isoformat(timespec="milliseconds")


class TelemetryEvent(BaseModel):
    timestamp: datetime = Field(default_factory=utc_now)
    service: str
    host: str
    endpoint: str
    status_code: int
    latency_ms: int
    error_type: str = "null"
    severity: str = "INFO"
    trace_id: str = Field(default_factory=lambda: uuid4().hex)
    user_region: str
    cpu_pct: float
    memory_pct: float
    db_connection_pool_pct: float
    dependency: str = "none"
    deployment_version: str
    incident_id: str = "none"
    timeline_stage: str = "normal"
    demo_minute: int | None = None


class Evidence(BaseModel):
    service: str
    incident_id: str
    event_count: int = 0
    error_types: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    endpoints: list[str] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)
    regions: list[str] = Field(default_factory=list)
    avg_latency_ms: float = 0
    max_latency_ms: float = 0
    max_cpu_pct: float = 0
    max_memory_pct: float = 0
    max_db_pool_pct: float = 0
    deployment_versions: list[str] = Field(default_factory=list)
    raw_events: list[dict[str, Any]] = Field(default_factory=list)


class InvestigationResult(BaseModel):
    incident_id: str
    service: str
    severity: Severity
    status: IncidentStatus = "INVESTIGATED"
    root_cause: str
    confidence_score: float
    evidence_summary: str
    ai_summary: str | None = None
    fallback_rca_summary: str | None = None
    recommended_actions: list[str]
    safe_remediation_actions: list[str]
    source: str
    mcp_investigation: bool = False
    mcp_tools_used: list[str] = Field(default_factory=list)
    spl_queries_used: list[str] = Field(default_factory=list)
    mcp_log_event_count: int = 0
    raw_response: str | None = None
    created_at: datetime = Field(default_factory=utc_now)


class Incident(BaseModel):
    incident_id: str = Field(default_factory=lambda: f"inc-{uuid4().hex[:10]}")
    service: str
    status: IncidentStatus = "OPEN"
    severity: Severity = "MEDIUM"
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    root_cause: str | None = None
    confidence_score: float | None = None
    evidence_summary: str | None = None
    ai_summary: str | None = None
    fallback_rca_summary: str | None = None
    mcp_evidence_summary: str | None = None
    llm_provider: str | None = None
    mcp_investigation: bool = False
    mcp_tools_used: list[str] = Field(default_factory=list)
    spl_queries_used: list[str] = Field(default_factory=list)
    mcp_log_event_count: int = 0
    recommended_actions: list[str] = Field(default_factory=list)
    safe_remediation_actions: list[str] = Field(default_factory=list)
    approved_by: str | None = None
    remediation_status: str | None = None
    remediation_result: str | None = None
    source: str = "manual_or_api"


class AssistantSuggestion(BaseModel):
    incident_id: str
    service: str
    status: str = "READY"
    intent: str = "generate_spl"
    prompt: str
    suggested_spl: str
    explanation: str
    source: str = "splunk_ai_assistant_ready"
    created_at: datetime = Field(default_factory=utc_now)


class ForecastSignal(BaseModel):
    service: str
    incident_id: str
    status: str = "READY"
    forecast_horizon: str = "15m"
    predicted_latency_ms: float
    lower_bound_latency_ms: float
    upper_bound_latency_ms: float
    predicted_error_rate_pct: float
    confidence_score: float
    model_name: str = "hosted_time_series_ready"
    model_source: str = "fallback_ewma"
    hosted_model_query: str | None = None
    supporting_events: int = 0
    source: str = "splunk_hosted_timeseries_ready"
    created_at: datetime = Field(default_factory=utc_now)
