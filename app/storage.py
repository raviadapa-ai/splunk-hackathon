import json
from pathlib import Path
from typing import Any

from app.config import (
    AI_ASSISTANT_LOG_PATH,
    AI_TRIAGE_LOG_PATH,
    CORRELATION_LOG_PATH,
    FORECAST_LOG_PATH,
    DATA_DIR,
    INDEX_HEALTH_LOG_PATH,
    INCIDENT_LOG_PATH,
    INCIDENT_STORE_PATH,
    INVESTIGATION_LOG_PATH,
    MCP_METRICS_LOG_PATH,
    METADATA_SNAPSHOT_LOG_PATH,
    REMEDIATION_LOG_PATH,
    SPLUNK_AI_ACTIVITY_LOG_PATH,
    SYSTEM_HEALTH_LOG_PATH,
    TIMELINE_LOG_PATH,
)
from app.models import Incident


def ensure_data_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def load_incidents(path: Path | None = None) -> dict[str, Incident]:
    ensure_data_dir()
    path = path or INCIDENT_STORE_PATH
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        raw = json.load(handle)
    return {item["incident_id"]: Incident.model_validate(item) for item in raw}


def save_incidents(incidents: dict[str, Incident], path: Path | None = None) -> None:
    ensure_data_dir()
    path = path or INCIDENT_STORE_PATH
    payload = [incident.model_dump(mode="json") for incident in incidents.values()]
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


def upsert_incident(incident: Incident) -> Incident:
    incidents = load_incidents()
    incidents[incident.incident_id] = incident
    save_incidents(incidents)
    return incident


def append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    ensure_data_dir()
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, separators=(",", ":"), default=str) + "\n")


def _tail_lines(path: Path, limit: int) -> list[str]:
    if limit <= 0:
        return []

    chunk_size = 8192
    collected = bytearray()
    with path.open("rb") as handle:
        handle.seek(0, 2)
        position = handle.tell()
        while position > 0 and collected.count(b"\n") <= limit:
            read_size = min(chunk_size, position)
            position -= read_size
            handle.seek(position)
            collected[:0] = handle.read(read_size)

    return collected.decode("utf-8", errors="replace").splitlines()[-limit:]


def load_jsonl_events(filename: str, limit: int = 200) -> list[dict[str, Any]]:
    ensure_data_dir()
    path = DATA_DIR / filename
    if not path.exists():
        return []

    events: list[dict[str, Any]] = []
    for line in _tail_lines(path, limit):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events


def write_investigation_event(payload: dict[str, Any]) -> None:
    append_jsonl(INVESTIGATION_LOG_PATH, payload)


def write_incident_event(payload: dict[str, Any]) -> None:
    append_jsonl(INCIDENT_LOG_PATH, payload)


def write_remediation_event(payload: dict[str, Any]) -> None:
    append_jsonl(REMEDIATION_LOG_PATH, payload)


def write_ai_triage_event(payload: dict[str, Any]) -> None:
    append_jsonl(AI_TRIAGE_LOG_PATH, payload)


def write_ai_assistant_event(payload: dict[str, Any]) -> None:
    append_jsonl(AI_ASSISTANT_LOG_PATH, payload)


def write_forecast_event(payload: dict[str, Any]) -> None:
    append_jsonl(FORECAST_LOG_PATH, payload)


def write_system_health_event(payload: dict[str, Any]) -> None:
    append_jsonl(SYSTEM_HEALTH_LOG_PATH, payload)


def write_index_health_event(payload: dict[str, Any]) -> None:
    append_jsonl(INDEX_HEALTH_LOG_PATH, payload)


def write_metadata_snapshot_event(payload: dict[str, Any]) -> None:
    append_jsonl(METADATA_SNAPSHOT_LOG_PATH, payload)


def write_timeline_event(payload: dict[str, Any]) -> None:
    append_jsonl(TIMELINE_LOG_PATH, payload)


def write_correlation_event(payload: dict[str, Any]) -> None:
    append_jsonl(CORRELATION_LOG_PATH, payload)


def write_mcp_metric_event(payload: dict[str, Any]) -> None:
    append_jsonl(MCP_METRICS_LOG_PATH, payload)


def write_splunk_ai_activity_event(payload: dict[str, Any]) -> None:
    append_jsonl(SPLUNK_AI_ACTIVITY_LOG_PATH, payload)
