from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT_DIR / "data"
APP_LOG_PATH = DATA_DIR / "app.log"
INCIDENT_LOG_PATH = DATA_DIR / "incidents.log"
INVESTIGATION_LOG_PATH = DATA_DIR / "aiops_investigations.log"
REMEDIATION_LOG_PATH = DATA_DIR / "aiops_remediation.log"
AI_TRIAGE_LOG_PATH = DATA_DIR / "ai_triages.log"
INCIDENT_STORE_PATH = DATA_DIR / "incidents.json"

DEFAULT_INDEX = "main"
AGENTIC_OPS_SOURCETYPE = "agentic-ops"
INCIDENT_SOURCETYPE = "aiops-incidents"
INVESTIGATION_SOURCETYPE = "aiops-investigations"
REMEDIATION_SOURCETYPE = "aiops-remediation"
AI_TRIAGE_SOURCETYPE = "ai-mcp-triage-agent"
