import os
import json
import requests
import urllib3
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth

load_dotenv()
urllib3.disable_warnings()

SPLUNK_URL = os.getenv("SPLUNK_URL")
SPLUNK_USERNAME = os.getenv("SPLUNK_USERNAME")
SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD")

if not SPLUNK_URL or not SPLUNK_USERNAME or not SPLUNK_PASSWORD:
    raise RuntimeError(
        "Missing Splunk configuration: set SPLUNK_URL, SPLUNK_USERNAME, and SPLUNK_PASSWORD in your environment or .env file."
    )

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.2:1b"

def fetch_error_logs():
    query = 'search sourcetype="aiops_logs" ERROR | head 10'
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
    response.raise_for_status()

    logs = []

    for line in response.text.splitlines():
        if not line.strip():
            continue

        data = json.loads(line)

        if "result" in data:
            logs.append(f'{data["result"]["_raw"]} | count={data["result"]["count"]}')

    return logs


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
    if "database" in analysis["probable_root_cause"].lower():
        actions = [
            "Check database service status",
            "Verify database connectivity from the application",
            "Inspect active DB connections and connection pool settings",
            "Review recent deployment or configuration changes",
            "Restart application only if approved"
        ]
    else:
        actions = [
            "Review recent ERROR logs",
            "Check application health and dependent services",
            "Validate network connectivity",
            "Verify third-party service availability",
            "Escalate to on-call if issues persist"
        ]

    return {
        "requires_human_approval": True,
        "severity": analysis["severity"],
        "recommended_actions": actions
    }

def generate_incident_summary(logs, analysis, remediation):
    prompt = f"""
You are an AIOps incident assistant.

Use ONLY the given analysis, remediation plan, and logs.
Do not invent tools, teams, or extra steps.
Do not say you cannot analyze logs.

Return only this format:

Incident Summary:
<one short paragraph>

Possible Impact:
<one short paragraph>

Probable Root Cause:
<use the probable root cause from analysis>

Recommended Action:
<use the recommended actions from remediation>

Analysis:
{analysis}

Remediation:
{remediation}

Logs:
{chr(10).join(logs[:10])}
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
    response.raise_for_status()

    result = response.json()
    if "response" not in result:
        raise RuntimeError(f"Unexpected Ollama response: {result}")

    return result["response"]


if __name__ == "__main__":
    print("Starting incident summary...")

    logs = fetch_error_logs()
    analysis = analyze_patterns(logs)
    remediation = generate_remediation_plan(analysis)

    print(f"Retrieved {len(logs)} logs")

    for log in logs:
        print(log)

    print("\nCalling Ollama...")

    summary = generate_incident_summary(logs, analysis, remediation)

    print("\nAI Incident Summary:")
    print(summary)