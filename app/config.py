import os
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]


def _is_placeholder_env_value(value: str) -> bool:
    lowered = value.strip().lower()
    return (
        not lowered
        or "<" in lowered
        or "your-" in lowered
        or lowered in {"changeme", "change-me", "example"}
    )


def _load_env_file(path: Path) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ and not _is_placeholder_env_value(value):
            os.environ[key] = value


_load_env_file(ROOT_DIR / ".env")
_load_env_file(ROOT_DIR / ".env.example")

DATA_DIR = ROOT_DIR / "data"
APP_LOG_PATH = DATA_DIR / "app.log"
INCIDENT_LOG_PATH = DATA_DIR / "incidents.log"
INVESTIGATION_LOG_PATH = DATA_DIR / "aiops_investigations.log"
REMEDIATION_LOG_PATH = DATA_DIR / "aiops_remediation.log"
AI_TRIAGE_LOG_PATH = DATA_DIR / "ai_triages.log"
AI_ASSISTANT_LOG_PATH = DATA_DIR / "ai_assistant.log"
FORECAST_LOG_PATH = DATA_DIR / "forecast.log"
INCIDENT_STORE_PATH = DATA_DIR / "incidents.json"
SYSTEM_HEALTH_LOG_PATH = DATA_DIR / "system_health.log"
INDEX_HEALTH_LOG_PATH = DATA_DIR / "index_health.log"
METADATA_SNAPSHOT_LOG_PATH = DATA_DIR / "metadata_snapshot.log"
TIMELINE_LOG_PATH = DATA_DIR / "timeline.log"
CORRELATION_LOG_PATH = DATA_DIR / "correlation.log"
MCP_METRICS_LOG_PATH = DATA_DIR / "mcp_metrics.log"
SPLUNK_AI_ACTIVITY_LOG_PATH = DATA_DIR / "splunk_ai_activity.log"

DEFAULT_INDEX = "main"
AGENTIC_OPS_SOURCETYPE = "agentic-ops"
INCIDENT_SOURCETYPE = "aiops-incidents"
INVESTIGATION_SOURCETYPE = "aiops-investigations"
REMEDIATION_SOURCETYPE = "aiops-remediation"
AI_TRIAGE_SOURCETYPE = "ai-mcp-triage-agent"
AI_ASSISTANT_SOURCETYPE = "aiops-ai-assistant"
FORECAST_SOURCETYPE = "aiops-forecast"
