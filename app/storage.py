import json
from pathlib import Path
from typing import Any

from app.config import (
    AI_TRIAGE_LOG_PATH,
    DATA_DIR,
    INCIDENT_LOG_PATH,
    INCIDENT_STORE_PATH,
    INVESTIGATION_LOG_PATH,
    REMEDIATION_LOG_PATH,
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


def write_investigation_event(payload: dict[str, Any]) -> None:
    append_jsonl(INVESTIGATION_LOG_PATH, payload)


def write_incident_event(payload: dict[str, Any]) -> None:
    append_jsonl(INCIDENT_LOG_PATH, payload)


def write_remediation_event(payload: dict[str, Any]) -> None:
    append_jsonl(REMEDIATION_LOG_PATH, payload)


def write_ai_triage_event(payload: dict[str, Any]) -> None:
    append_jsonl(AI_TRIAGE_LOG_PATH, payload)
