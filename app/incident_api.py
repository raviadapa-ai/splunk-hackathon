import os
from dotenv import load_dotenv
import json
import uuid
import requests
import urllib3
from fastapi import FastAPI
from requests.auth import HTTPBasicAuth

load_dotenv()
urllib3.disable_warnings()

app = FastAPI(title="Splunk Incident Copilot")

SPLUNK_URL = os.getenv("SPLUNK_URL")
SPLUNK_USERNAME = os.getenv("SPLUNK_USERNAME")
SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD")

OLLAMA_URL = os.getenv("OLLAMA_URL")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL")

print("Splunk Username:", SPLUNK_USERNAME)
print("Model:", OLLAMA_MODEL)


def analyze_patterns(logs):
    db_timeout_count = sum("Database timeout" in log for log in logs)
    api_failure_count = sum("API failure" in log for log in logs)

    severity = "LOW"

    if db_timeout_count >= 5:
        severity = "HIGH"
    elif db_timeout_count >= 2:
        severity = "MEDIUM"

    probable_root_cause = "Unknown"

    if db_timeout_count >= 2:
        probable_root_cause = "Possible database connectivity or connection pool issue"

    return {
        "db_timeout_count": db_timeout_count,
        "api_failure_count": api_failure_count,
        "severity": severity,
        "probable_root_cause": probable_root_cause
    }

def generate_remediation_plan(analysis):
    severity = analysis["severity"]
    root_cause = analysis["probable_root_cause"]

    if "database" in root_cause.lower():
        actions = [
            "Check PostgreSQL service status",
            "Verify database connectivity from application",
            "Check active DB connections",
            "Review connection pool configuration",
            "Restart application only after approval"
        ]
    else:
        actions = [
            "Review recent ERROR logs",
            "Check application health",
            "Verify dependent services"
        ]

    return {
        "requires_human_approval": True,
        "severity": severity,
        "recommended_actions": actions
    }

def fetch_error_logs():
    query = 'search sourcetype="aiops_logs" ERROR | head 20'

    response = requests.post(
        SPLUNK_URL,
        auth=HTTPBasicAuth(SPLUNK_USERNAME, SPLUNK_PASSWORD),
        data={
            "search": query,
            "output_mode": "json"
        },
        verify=False,
        timeout=30
    )

    logs = []

    for line in response.text.splitlines():
        if not line.strip():
            continue

        data = json.loads(line)

        if "result" in data:
            logs.append(data["result"]["_raw"])

    return logs


def generate_incident_summary(logs, analysis, remediation):
    if not logs:
        return "No ERROR logs found in Splunk."

    prompt = f"""
You are an AIOps incident assistant.

Use ONLY the facts below.
Do not add generic recommendations.
Do not mention data loss unless it is stated.
Do not mention Splunk as a recommendation.
Do not invent extra tools, teams, or assumptions.

Facts:
- Log count: {len(logs)}
- DB timeout count: {analysis["db_timeout_count"]}
- API failure count: {analysis["api_failure_count"]}
- Severity: {analysis["severity"]}
- Probable root cause: {analysis["probable_root_cause"]}
- Human approval required: {remediation["requires_human_approval"]}

Recommended actions:
{chr(10).join(remediation["recommended_actions"])}

Return exactly this format:

Incident Summary:
Repeated database timeout errors were detected in the application logs.

Possible Impact:
Application requests may fail or experience increased latency.

Probable Root Cause:
{analysis["probable_root_cause"]}

Recommended Action:
1. {remediation["recommended_actions"][0]}
2. {remediation["recommended_actions"][1]}
3. {remediation["recommended_actions"][2]}
4. {remediation["recommended_actions"][3]}
5. {remediation["recommended_actions"][4]}
"""

    response = requests.post(
        OLLAMA_URL,
        json={
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False
        },
        timeout=120
    )

    return response.json()["response"]

def create_incident(logs, analysis, remediation, summary):

    incident = {
        "incident_id": f"INC-{str(uuid.uuid4())[:8]}",
        "severity": analysis["severity"],
        "status": "OPEN",
        "root_cause": analysis["probable_root_cause"],
        "requires_human_approval": remediation["requires_human_approval"],
        "summary": summary
    }

    incidents = []

    if os.path.exists("incidents.json") and os.path.getsize("incidents.json") > 0:
        with open("incidents.json", "r") as f:
            incidents = json.load(f)

    incidents.append(incident)

    with open("incidents.json", "w") as f:
        json.dump(incidents, f, indent=2)

    return incident

def update_incident_status(incident_id, new_status):

    with open("incidents.json", "r") as f:
        incidents = json.load(f)

    updated = False

    for incident in incidents:
        if incident["incident_id"] == incident_id:
            incident["status"] = new_status
            updated = True
            break

    with open("incidents.json", "w") as f:
        json.dump(incidents, f, indent=2)

    return updated

@app.get("/")
def home():
    return {
        "message": "Splunk Incident Copilot API is running"
    }

@app.get("/incident-summary")
def incident_summary():
    logs = fetch_error_logs()
    analysis = analyze_patterns(logs)
    remediation = generate_remediation_plan(analysis)
    summary = generate_incident_summary(logs, analysis, remediation)

    return {
        "log_count": len(logs),
        "analysis": analysis,
        "remediation": remediation,
        "logs": logs,
        "ai_summary": summary
    }

@app.get("/create-incident")
def create_new_incident():

    logs = fetch_error_logs()

    analysis = analyze_patterns(logs)

    remediation = generate_remediation_plan(analysis)

    summary = generate_incident_summary(
        logs,
        analysis,
        remediation
    )

    incident = create_incident(
        logs,
        analysis,
        remediation,
        summary
    )

    return incident

@app.get("/incidents")
def get_incidents():

    try:
        with open("incidents.json", "r") as f:
            incidents = json.load(f)
    except:
        incidents = []

    return incidents

@app.post("/remediation/approve/{incident_id}")
def approve_remediation(incident_id: str):

    success = update_incident_status(incident_id,"APPROVED")

    if not success:
        return {
            "success": False,
            "message": "Incident not found"
        }

    return {
        "success": True,
        "incident_id": incident_id,
        "status": "APPROVED",
        "message": "Human approval granted"
    }