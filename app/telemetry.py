import json
import random
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from app.config import APP_LOG_PATH, DATA_DIR
from app.models import TelemetryEvent, utc_now


SERVICES = ["checkout-api", "payment-api", "auth-api", "catalog-api", "orders-worker"]
REGIONS = ["us-east", "us-west", "eu-central", "ap-south"]
HOSTS = {
    "checkout-api": ["checkout-01", "checkout-02", "checkout-03"],
    "payment-api": ["payment-01", "payment-02"],
    "auth-api": ["auth-01", "auth-02"],
    "catalog-api": ["catalog-01", "catalog-02"],
    "orders-worker": ["orders-01", "orders-02"],
}
ENDPOINTS = {
    "checkout-api": ["/checkout", "/cart/submit", "/orders"],
    "payment-api": ["/payments/authorize", "/payments/capture"],
    "auth-api": ["/login", "/token/refresh", "/session"],
    "catalog-api": ["/products", "/search", "/inventory"],
    "orders-worker": ["/jobs/order-confirmation", "/jobs/invoice"],
}
DEPENDENCIES = ["none", "postgres", "redis", "payment_gateway", "identity_provider"]
VERSIONS = ["2026.06.1", "2026.06.2", "2026.06.3"]
INCIDENT_TYPES = [
    "database_timeout",
    "upstream_api_failure",
    "auth_failure",
    "deployment_regression",
    "cpu_saturation",
    "latency_regression",
]
INCIDENT_SERVICE = {
    "database_timeout": "checkout-api",
    "upstream_api_failure": "payment-api",
    "auth_failure": "auth-api",
    "deployment_regression": "checkout-api",
    "cpu_saturation": "catalog-api",
    "latency_regression": "checkout-api",
}
INCIDENT_DEPENDENCY = {
    "database_timeout": "postgres",
    "upstream_api_failure": "payment_gateway",
    "auth_failure": "identity_provider",
    "deployment_regression": "postgres",
    "cpu_saturation": "none",
    "latency_regression": "redis",
}


@dataclass(frozen=True)
class TimelineIncident:
    minute: int
    incident_type: str
    duration_seconds: int
    burst_size: int
    stage: str


def event_to_json_line(event: TelemetryEvent) -> str:
    payload = event.model_dump(mode="json")
    payload["timestamp"] = event.timestamp.astimezone().isoformat(timespec="milliseconds")
    return json.dumps(payload, separators=(",", ":"))


def write_event(event: TelemetryEvent, path: Path | None = None) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    path = path or APP_LOG_PATH
    with path.open("a", encoding="utf-8") as handle:
        handle.write(event_to_json_line(event) + "\n")


DEMO_TIMELINE = [
    TimelineIncident(10, "database_timeout", 75, 18, "database_incident"),
    TimelineIncident(20, "upstream_api_failure", 60, 16, "payment_gateway_incident"),
    TimelineIncident(30, "deployment_regression", 90, 20, "deployment_regression_incident"),
]


def normal_event(timestamp: datetime | None = None, timeline_stage: str = "normal", demo_minute: int | None = None) -> TelemetryEvent:
    service = random.choice(SERVICES)
    roll = random.random()
    error_type = "null"
    status_code = 200
    severity = "INFO"
    latency_ms = random.randint(60, 450)
    dependency = random.choice(DEPENDENCIES)

    if roll < 0.08:
        error_type = "latency_regression"
        latency_ms = random.randint(900, 1600)
        severity = "WARN"
    elif roll < 0.12:
        service = "auth-api"
        error_type = "auth_failure"
        status_code = random.choice([401, 403])
        severity = "WARN"
        dependency = "identity_provider"
    elif roll < 0.14:
        service = "payment-api"
        error_type = "upstream_api_failure"
        status_code = random.choice([502, 503, 504])
        latency_ms = random.randint(700, 1800)
        severity = "ERROR"
        dependency = "payment_gateway"
    elif roll < 0.15:
        error_type = random.choice(["cpu_saturation", "database_timeout"])
        status_code = random.choice([500, 502, 503])
        latency_ms = random.randint(1300, 2600)
        severity = "ERROR"
        dependency = "postgres"

    return TelemetryEvent(
        timestamp=timestamp or utc_now(),
        service=service,
        host=random.choice(HOSTS[service]),
        endpoint=random.choice(ENDPOINTS[service]),
        status_code=status_code,
        latency_ms=latency_ms,
        error_type=error_type,
        severity=severity,
        user_region=random.choice(REGIONS),
        cpu_pct=round(random.uniform(25, 72), 2),
        memory_pct=round(random.uniform(35, 78), 2),
        db_connection_pool_pct=round(random.uniform(20, 70), 2),
        dependency=dependency,
        deployment_version=random.choice(VERSIONS),
        timeline_stage=timeline_stage,
        demo_minute=demo_minute,
    )


def incident_event(
    incident_type: str,
    incident_id: str,
    sequence: int,
    timestamp: datetime | None = None,
    endpoint: str | None = None,
    region: str = "us-east",
    timeline_stage: str | None = None,
    demo_minute: int | None = None,
) -> TelemetryEvent:
    service = INCIDENT_SERVICE[incident_type]
    dependency = INCIDENT_DEPENDENCY[incident_type]
    status_code = {
        "auth_failure": random.choice([401, 403]),
        "latency_regression": 200,
    }.get(incident_type, random.choice([500, 502, 503, 504]))

    return TelemetryEvent(
        timestamp=timestamp or utc_now(),
        service=service,
        host=random.choice(HOSTS[service]),
        endpoint=endpoint or ENDPOINTS[service][0],
        status_code=status_code,
        latency_ms=random.randint(1600, 4200),
        error_type=incident_type,
        severity="CRITICAL" if status_code >= 500 else "ERROR",
        trace_id=f"{incident_id}-{sequence:03d}",
        user_region=region,
        cpu_pct=round(random.uniform(88, 99), 2) if incident_type == "cpu_saturation" else round(random.uniform(45, 82), 2),
        memory_pct=round(random.uniform(86, 96), 2) if incident_type == "cpu_saturation" else round(random.uniform(50, 85), 2),
        db_connection_pool_pct=round(random.uniform(91, 99), 2) if incident_type in {"database_timeout", "deployment_regression"} else round(random.uniform(30, 75), 2),
        dependency=dependency,
        deployment_version="2026.06.3" if incident_type == "deployment_regression" else random.choice(VERSIONS),
        incident_id=incident_id,
        timeline_stage=timeline_stage or incident_type,
        demo_minute=demo_minute,
    )


def inject_incident(incident_type: str | None = None, burst_size: int | None = None, path: Path | None = None) -> str:
    selected_type = incident_type or random.choice(INCIDENT_TYPES)
    if selected_type not in INCIDENT_TYPES:
        raise ValueError(f"Unsupported incident type: {selected_type}")

    incident_id = f"inc-{utc_now().strftime('%Y%m%d%H%M%S')}-{uuid4().hex[:6]}"
    size = burst_size or random.randint(10, 20)
    for index in range(size):
        write_event(incident_event(selected_type, incident_id, index), path)
    return incident_id


def _timeline_stage_for_minute(minute: int) -> str:
    if minute < 5:
        return "baseline"
    if minute < 10:
        return "early_warning"
    if minute < 20:
        return "post_database_recovery"
    if minute < 30:
        return "post_payment_recovery"
    return "post_deployment_recovery"


def _timeline_normal_event(timestamp: datetime, minute: int) -> TelemetryEvent:
    event = normal_event(timestamp=timestamp, timeline_stage=_timeline_stage_for_minute(minute), demo_minute=minute)
    if 5 <= minute < 10:
        event.service = "checkout-api"
        event.endpoint = "/checkout"
        event.error_type = "latency_regression"
        event.status_code = 200
        event.severity = "WARN"
        event.latency_ms = random.randint(900, 1500)
        event.dependency = "redis"
    return event


def generate_demo_timeline(
    path: Path | None = None,
    start_time: datetime | None = None,
    duration_minutes: int = 35,
    normal_interval_seconds: int = 5,
    seed: int = 42,
    overwrite: bool = False,
) -> list[str]:
    """Generate a complete deterministic demo timeline for Splunk ingestion."""
    if duration_minutes < 31:
        raise ValueError("duration_minutes must be at least 31 to include all planned incidents")

    random.seed(seed)
    output_path = path or APP_LOG_PATH
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if overwrite:
        output_path.write_text("", encoding="utf-8")

    start = (start_time or utc_now()).astimezone(timezone.utc).replace(second=0, microsecond=0)
    incident_ids: list[str] = []
    incident_by_minute = {incident.minute: incident for incident in DEMO_TIMELINE}

    for offset_seconds in range(0, duration_minutes * 60, normal_interval_seconds):
        current_time = start + timedelta(seconds=offset_seconds)
        minute = offset_seconds // 60
        write_event(_timeline_normal_event(current_time, minute), output_path)

        incident = incident_by_minute.get(minute)
        if incident and offset_seconds % 60 == 0:
            incident_id = f"inc-demo-{incident.minute:02d}-{incident.incident_type}"
            incident_ids.append(incident_id)
            service = INCIDENT_SERVICE[incident.incident_type]
            endpoint = ENDPOINTS[service][0]
            spacing = max(1, incident.duration_seconds // incident.burst_size)
            for index in range(incident.burst_size):
                event_time = current_time + timedelta(seconds=index * spacing)
                write_event(
                    incident_event(
                        incident.incident_type,
                        incident_id,
                        index,
                        timestamp=event_time,
                        endpoint=endpoint,
                        region="us-east",
                        timeline_stage=incident.stage,
                        demo_minute=minute,
                    ),
                    output_path,
                )

    return incident_ids


def run_generator(interval_seconds: float = 5.0, incident_interval_seconds: float = 600.0) -> None:
    next_incident_at = time.monotonic() + incident_interval_seconds
    while True:
        write_event(normal_event())
        if time.monotonic() >= next_incident_at:
            inject_incident()
            next_incident_at = time.monotonic() + incident_interval_seconds
        time.sleep(interval_seconds)
