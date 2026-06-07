import json
import os
import random
import threading
import time
from pathlib import Path
from uuid import uuid4
from datetime import datetime, timezone

from fastapi import FastAPI

app = FastAPI()

APP_LOG_PATH = Path(os.getenv("APP_LOG_PATH", "data/app.log"))
TELEMETRY_ENABLED = os.getenv("TELEMETRY_ENABLED", "true").lower() in ("1", "true", "yes", "on")
TELEMETRY_INTERVAL_SECONDS = int(os.getenv("TELEMETRY_INTERVAL_SECONDS", "10"))
INCIDENT_INJECTION_INTERVAL_SECONDS = int(os.getenv("INCIDENT_INJECTION_INTERVAL_SECONDS", "300"))
INCIDENT_BURST_SIZE = int(os.getenv("INCIDENT_BURST_SIZE", "8"))

SERVICES = ["checkout-api", "payments-api", "auth-api", "inventory-api"]
HOSTS = ["ip-10-0-1-12", "ip-10-0-1-18", "ip-10-0-2-21"]
REGIONS = ["us-east", "us-west", "eu-central", "ap-south"]
ENDPOINTS = ["/checkout", "/cart", "/login", "/inventory", "/payment"]
_telemetry_stop = threading.Event()
_telemetry_thread = None


def write_event(event):
    line = json.dumps(event, separators=(",", ":"))
    APP_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with APP_LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def build_log(
    service=None,
    endpoint=None,
    status_code=None,
    latency_ms=None,
    error_type=None,
    message=None,
    host=None,
    user_region=None,
):
    service = service or random.choice(SERVICES)
    endpoint = endpoint or random.choice(ENDPOINTS)
    status_code = status_code if status_code is not None else random.choice([200, 200, 200, 201, 204])
    latency_ms = latency_ms if latency_ms is not None else random.randint(80, 420)
    message = message or "Request completed successfully"
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": service,
        "host": host or random.choice(HOSTS),
        "endpoint": endpoint,
        "status_code": status_code,
        "latency_ms": latency_ms,
        "error_type": error_type,
        "message": message,
        "trace_id": uuid4().hex[:16],
        "user_region": user_region or random.choice(REGIONS),
    }
    write_event(event)
    return event


def latency(base, jitter):
    return base + random.randint(0, jitter)


@app.get("/")
def home():
    event = build_log(
        status_code=random.choice([200, 200, 201, 204]),
        latency_ms=latency(80, 340),
        error_type=None,
    )
    return {"status": "ok", "trace_id": event["trace_id"]}


@app.get("/error")
def error():
    event = build_log(
        service="checkout-api",
        host=random.choice(["ip-10-0-1-12", "ip-10-0-1-18"]),
        endpoint="/checkout",
        status_code=random.choice([500, 502, 503]),
        latency_ms=latency(1600, 2600),
        error_type="database_timeout",
        message="Database timeout while reserving cart inventory",
    )
    return {"status": "error", "trace_id": event["trace_id"]}


@app.get("/latency")
def latency_spike():
    event = build_log(
        service=random.choice(["checkout-api", "inventory-api"]),
        endpoint=random.choice(["/checkout", "/inventory"]),
        status_code=200,
        latency_ms=latency(1300, 1700),
        error_type="latency_regression",
        message="Request latency exceeded service objective",
    )
    return {"status": "slow", "trace_id": event["trace_id"]}


@app.get("/api-failure")
def api_failure():
    event = build_log(
        service="payments-api",
        endpoint="/payment",
        status_code=502,
        latency_ms=latency(900, 450),
        error_type="upstream_api_failure",
        message="API failure from upstream payment gateway",
    )
    return {"status": "error", "trace_id": event["trace_id"]}


@app.get("/auth-failure")
def auth_failure():
    event = build_log(
        service="auth-api",
        endpoint="/login",
        status_code=random.choice([401, 403]),
        latency_ms=latency(700, 600),
        error_type="auth_failure",
        message="Authentication token validation failed",
    )
    return {"status": "error", "trace_id": event["trace_id"]}


@app.get("/test")
def test():
    roll = random.randint(1, 10)
    if roll >= 8:
        return error()
    if roll >= 6:
        return latency_spike()
    if roll >= 5:
        return auth_failure()
    return home()


def build_random_telemetry_event():
    roll = random.random()
    if roll < 0.25:
        return build_log(
            service="checkout-api",
            host=random.choice(["ip-10-0-1-12", "ip-10-0-1-18"]),
            endpoint="/checkout",
            status_code=random.choice([500, 502, 503]),
            latency_ms=latency(1600, 2600),
            error_type="database_timeout",
            message="Database timeout while reserving cart inventory",
        )
    if roll < 0.4:
        return build_log(
            service="payments-api",
            endpoint="/payment",
            status_code=502,
            latency_ms=latency(900, 450),
            error_type="upstream_api_failure",
            message="API failure from upstream payment gateway",
        )
    if roll < 0.55:
        return build_log(
            service="auth-api",
            endpoint="/login",
            status_code=random.choice([401, 403]),
            latency_ms=latency(700, 600),
            error_type="auth_failure",
            message="Authentication token validation failed",
        )
    if roll < 0.7:
        return build_log(
            service=random.choice(["checkout-api", "inventory-api"]),
            endpoint=random.choice(["/checkout", "/inventory"]),
            status_code=200,
            latency_ms=latency(1300, 1700),
            error_type="latency_regression",
            message="Request latency exceeded service objective",
        )
    return build_log()


def build_incident_event(incident_type):
    if incident_type == "database_timeout":
        return build_log(
            service="checkout-api",
            host=random.choice(["ip-10-0-1-12", "ip-10-0-1-18"]),
            endpoint="/checkout",
            status_code=random.choice([500, 502, 503]),
            latency_ms=latency(1800, 2800),
            error_type="database_timeout",
            message="Injected incident: database timeout while reserving cart inventory",
            user_region=random.choice(["us-east", "ap-south"]),
        )
    if incident_type == "upstream_api_failure":
        return build_log(
            service="payments-api",
            host="ip-10-0-2-21",
            endpoint="/payment",
            status_code=random.choice([502, 503, 504]),
            latency_ms=latency(950, 650),
            error_type="upstream_api_failure",
            message="Injected incident: upstream payment gateway failure",
            user_region=random.choice(["us-west", "eu-central"]),
        )
    if incident_type == "auth_failure":
        return build_log(
            service="auth-api",
            endpoint="/login",
            status_code=random.choice([401, 403]),
            latency_ms=latency(700, 700),
            error_type="auth_failure",
            message="Injected incident: authentication validation failures",
        )
    return build_log(
        service=random.choice(["checkout-api", "inventory-api"]),
        endpoint=random.choice(["/checkout", "/inventory"]),
        status_code=200,
        latency_ms=latency(1400, 1900),
        error_type="latency_regression",
        message="Injected incident: latency regression exceeded service objective",
    )


def inject_incident_burst():
    incident_type = random.choice(
        ["database_timeout", "upstream_api_failure", "auth_failure", "latency_regression"]
    )
    events = [build_incident_event(incident_type) for _ in range(INCIDENT_BURST_SIZE)]
    return {"incident_type": incident_type, "event_count": len(events), "events": events}


def telemetry_loop():
    next_incident_at = time.monotonic() + INCIDENT_INJECTION_INTERVAL_SECONDS
    while not _telemetry_stop.is_set():
        build_random_telemetry_event()
        if time.monotonic() >= next_incident_at:
            inject_incident_burst()
            next_incident_at = time.monotonic() + INCIDENT_INJECTION_INTERVAL_SECONDS
        _telemetry_stop.wait(TELEMETRY_INTERVAL_SECONDS)


@app.on_event("startup")
def start_continuous_telemetry():
    global _telemetry_thread
    if not TELEMETRY_ENABLED:
        return
    if _telemetry_thread and _telemetry_thread.is_alive():
        return
    _telemetry_stop.clear()
    _telemetry_thread = threading.Thread(
        target=telemetry_loop,
        name="continuous-telemetry-generator",
        daemon=True,
    )
    _telemetry_thread.start()


@app.on_event("shutdown")
def stop_continuous_telemetry():
    _telemetry_stop.set()
    if _telemetry_thread and _telemetry_thread.is_alive():
        _telemetry_thread.join(timeout=5)


@app.get("/telemetry/live/status")
def live_telemetry_status():
    return {
        "enabled": TELEMETRY_ENABLED,
        "running": bool(_telemetry_thread and _telemetry_thread.is_alive()),
        "log_path": str(APP_LOG_PATH),
        "telemetry_interval_seconds": TELEMETRY_INTERVAL_SECONDS,
        "incident_injection_interval_seconds": INCIDENT_INJECTION_INTERVAL_SECONDS,
        "incident_burst_size": INCIDENT_BURST_SIZE,
        "schema": [
            "timestamp",
            "service",
            "host",
            "endpoint",
            "status_code",
            "latency_ms",
            "error_type",
            "message",
            "trace_id",
            "user_region",
        ],
    }


@app.post("/telemetry/live/emit")
def emit_live_telemetry():
    event = build_random_telemetry_event()
    return {"log_path": str(APP_LOG_PATH), "event": event}


@app.post("/telemetry/live/inject-incident")
def inject_live_incident():
    return {"log_path": str(APP_LOG_PATH), **inject_incident_burst()}
