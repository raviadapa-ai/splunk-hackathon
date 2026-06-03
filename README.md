# Splunk Incident Copilot

An AIOps hackathon project that connects FastAPI, Splunk, and Ollama to detect repeated application errors, estimate incident severity, and generate a concise remediation-focused incident summary.

## What It Does

- Generates sample application logs with INFO and ERROR events.
- Queries Splunk for recent ERROR logs from the `aiops_logs` sourcetype.
- Detects common incident patterns such as repeated `Database timeout` errors.
- Assigns a simple severity level: `LOW`, `MEDIUM`, or `HIGH`.
- Builds a human-approved remediation plan.
- Uses a local Ollama model to generate an incident summary.

## Project Structure

```text
splunk-hackathon/
+-- app/
|   +-- main.py              # Sample FastAPI app that writes logs to app.log
|   +-- incident_api.py      # Main API for Splunk incident analysis
|   +-- incident_summary.py  # CLI workflow for incident summary generation
|   +-- splunk_query.py      # Simple Splunk query test script
+-- requirements.txt
+-- .env                     # Local secrets and service URLs, not committed
+-- .gitignore
```

## Requirements

- Python 3.10+
- Splunk instance with indexed application logs
- Ollama running locally or on a reachable host
- An Ollama model such as `llama3.2:1b`

## Setup

Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
pip install -r requirements.txt
```

Create a `.env` file in the project root:

```env
SPLUNK_URL=https://localhost:8089/services/search/jobs/export
SPLUNK_USERNAME=your_splunk_username
SPLUNK_PASSWORD=your_splunk_password
OLLAMA_URL=http://localhost:11434/api/generate
OLLAMA_MODEL=llama3.2:1b
```

Pull the Ollama model if needed:

```powershell
ollama pull llama3.2:1b
```

## Run The Sample Log App

Start the log-producing FastAPI app:

```powershell
uvicorn app.main:app --reload --port 8000
```

Available endpoints:

- `GET /` writes a successful request log.
- `GET /error` writes a database timeout error log.
- `GET /test` randomly writes a success or error log.

Example:

```powershell
curl http://127.0.0.1:8000/error
```

The app writes logs to `app.log`. Configure Splunk to monitor this file and assign it the sourcetype `aiops_logs`.

## Run The Incident Copilot API

Start the incident analysis API:

```powershell
uvicorn app.incident_api:app --reload --port 8001
```

Available endpoints:

- `GET /` checks whether the API is running.
- `GET /incident-summary` fetches Splunk error logs, analyzes them, generates remediation actions, and returns an AI-written incident summary.

Example:

```powershell
curl http://127.0.0.1:8001/incident-summary
```

Example response shape:

```json
{
  "log_count": 10,
  "analysis": {
    "db_timeout_count": 5,
    "api_failure_count": 0,
    "severity": "HIGH",
    "probable_root_cause": "Possible database connectivity or connection pool issue"
  },
  "remediation": {
    "requires_human_approval": true,
    "severity": "HIGH",
    "recommended_actions": [
      "Check PostgreSQL service status",
      "Verify database connectivity from application",
      "Check active DB connections",
      "Review connection pool configuration",
      "Restart application only after approval"
    ]
  },
  "logs": [],
  "ai_summary": "Incident Summary: ..."
}
```

## Run The CLI Summary Script

You can also run the incident workflow directly from the terminal:

```powershell
python -m app.incident_summary
```

This script fetches recent Splunk ERROR logs, analyzes patterns, calls Ollama, and prints the generated incident summary.

## Splunk Notes

The project currently queries Splunk with:

```spl
search sourcetype="aiops_logs" ERROR | head 20
```

For best results:

- Make sure `app.log` is being monitored by Splunk.
- Set the sourcetype to `aiops_logs`.
- Generate several `/error` or `/test` requests before calling `/incident-summary`.
- Confirm that Splunk search export is reachable at the `SPLUNK_URL` configured in `.env`.

## Troubleshooting

If Splunk returns no logs:

- Check that the sample app has generated ERROR logs.
- Confirm `app.log` is indexed in Splunk.
- Verify the configured sourcetype is `aiops_logs`.
- Test the Splunk connection with `python app\splunk_query.py`.

If Ollama fails:

- Start Ollama.
- Pull the configured model.
- Confirm `OLLAMA_URL` points to `/api/generate`.

If FastAPI does not start:

- Confirm the virtual environment is activated.
- Reinstall dependencies with `pip install -r requirements.txt`.
- Make sure each API is using a different port.

## Safety

The remediation plan intentionally sets `requires_human_approval` to `true`. Suggested actions are advisory and should be reviewed before restarting services or changing production systems.
