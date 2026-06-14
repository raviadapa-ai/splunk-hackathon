import json
from datetime import datetime
from pathlib import Path

from app.telemetry import (
    INCIDENT_TYPES,
    event_to_json_line,
    generate_demo_timeline,
    incident_event,
    normal_event,
)


def test_normal_event_serializes_to_json_line() -> None:
    event = normal_event()
    payload = json.loads(event_to_json_line(event))

    assert payload["service"]
    assert datetime.fromisoformat(payload["timestamp"]).tzinfo is not None
    assert payload["sourcetype"] is None if "sourcetype" in payload else True
    assert payload["status_code"] >= 200
    assert payload["incident_id"] == "none"


def test_incident_events_share_correlation_fields() -> None:
    incident_id = "inc-test"
    events = [
        incident_event("database_timeout", incident_id, index) for index in range(3)
    ]

    assert {event.incident_id for event in events} == {incident_id}
    assert {event.service for event in events} == {"checkout-api"}
    assert all(event.error_type in INCIDENT_TYPES for event in events)
    assert all(event.db_connection_pool_pct > 90 for event in events)


def test_demo_timeline_generates_all_planned_incidents() -> None:
    path = Path(".testdata/test_demo_timeline.log")
    path.parent.mkdir(parents=True, exist_ok=True)
    incident_ids = generate_demo_timeline(
        path=path, duration_minutes=35, overwrite=True
    )
    lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]

    assert incident_ids == [
        "inc-demo-10-database_timeout",
        "inc-demo-20-upstream_api_failure",
        "inc-demo-30-deployment_regression",
    ]
    assert len(lines) >= 35 * 12
    assert {
        line["incident_id"] for line in lines if line["incident_id"] != "none"
    } == set(incident_ids)
    assert {
        line["timeline_stage"] for line in lines if line["incident_id"] != "none"
    } == {
        "database_incident",
        "payment_gateway_incident",
        "deployment_regression_incident",
    }
