# Splunk Agentic Ops Control Center

This repo is a Splunk hackathon project for GenAI and agentic observability. It generates realistic multi-source logs, injects one correlated incident inside mostly successful traffic, indexes those logs into Splunk, and lets an agent investigate across proxy, application, database, infrastructure, Ollama, and agent metric evidence.

The demo is designed to prove multi-log reasoning, not basic chatbot behavior.

## What The Demo Shows

- Normal checkout traffic with HTTP 200s, app INFO events, DB commits, and healthy metrics.
- One injected incident per 15-minute window.
- Proxy-to-app correlation by `trace_id`.
- App-to-database correlation by timestamp, `tx_id`, `pid`, `blocking_pid`, and `item_id`.
- Infrastructure metrics showing pressure and recovery.
- Agent activity metrics showing tool calls and confidence.
- Safe ticket-only remediation that requires human approval.
- Severity router with `P1` autonomous simulated remediation, `P2` human-approved remediation, and `P3` observation-only feedback.
- Splunk alert webhook and Splunk-ingestable agent feedback loop.

## Architecture

```text
Streamlit Dashboard
    |
    +--> Telemetry API (app.main)
    |       +--> Multi-log Generator
    |               +--> data/logs/*.log
    |                       +--> Splunk file monitors
    |
    +--> Incident API (app.incident_api)
            +--> Splunk MCP Client
                    +--> Splunk MCP Server
                            +--> Splunk Enterprise
```

Detailed architecture: [docs/ARCHITECTURE_AND_FLOW.md](docs/ARCHITECTURE_AND_FLOW.md)

Splunk setup guide: [docs/SPLUNK_GUIDE.md](docs/SPLUNK_GUIDE.md)

Execution plan: [MULTI_LOG_OBSERVABILITY_PLAN_2026-06-07_22-53-18.md](MULTI_LOG_OBSERVABILITY_PLAN_2026-06-07_22-53-18.md)

## Project Files

| File | What it does |
| --- | --- |
| [app/main.py](app/main.py) | FastAPI telemetry service. Writes live and generated events to the dedicated multi-log files under `data/logs/`. |
| [app/multi_log_generator.py](app/multi_log_generator.py) | Generates the Splunk-friendly proxy, app, DB, infra, Ollama, and agent metric logs. Supports required and optional incident types. |
| [app/incident_api.py](app/incident_api.py) | FastAPI incident service. Queries Splunk through MCP, synthesizes evidence, creates incidents, and creates safe remediation tickets. |
| [app/splunk_mcp_client.py](app/splunk_mcp_client.py) | Splunk MCP adapter. Reads MCP endpoint/token config from environment and runs SPL queries. |
| [app/dashboard.py](app/dashboard.py) | Streamlit dashboard/control center for generating logs, running investigations, creating incidents, and creating remediation tickets. |
| [app/incident_summary.py](app/incident_summary.py) | CLI path for generating an incident summary without the dashboard. |
| [app/splunk_query.py](app/splunk_query.py) | Small manual smoke-test helper for Splunk query connectivity. |
| [requirements.txt](requirements.txt) | Python runtime dependencies. |
| [.gitignore](.gitignore) | Ignores local environments, runtime logs, cache files, `.env`, and generated state. |
| [incidents.json](incidents.json) | Local incident store used by the API. Runtime/demo state, not production storage. |
| [docs/SPLUNK_GUIDE.md](docs/SPLUNK_GUIDE.md) | Step-by-step Splunk ingestion, monitoring, dashboard, and MCP guide. |
| [docs/ARCHITECTURE_AND_FLOW.md](docs/ARCHITECTURE_AND_FLOW.md) | Architecture, flow, safety model, and verification status. |

Generated runtime files:

| Path | Meaning |
| --- | --- |
| `data/logs/proxy_nginx.log` | Proxy/API gateway logs, sourcetype `agentic:proxy:nginx`. |
| `data/logs/application_spring.log` | Checkout app logs, sourcetype `agentic:app:spring`. |
| `data/logs/database_postgres.log` | Postgres logs, sourcetype `agentic:db:postgres`. |
| `data/logs/system_metrics.log` | Infra metrics, sourcetype `agentic:infra:metrics`. |
| `data/logs/ollama_runtime.log` | Ollama runtime metrics, sourcetype `agentic:ai:ollama`. |
| `data/logs/agent_metrics.log` | Agent tool metrics, sourcetype `splunk:agent:metrics`. |
| `data/logs/agent_feedback.log` | Agent lifecycle feedback, sourcetype `splunk:agent:feedback`. |

## Setup

Use Python 3.12 for this project.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If `py -3.12 -m venv .venv` creates the environment but fails during `ensurepip`, install through the global pip launcher:

```powershell
py -3.12 -m pip --python .\.venv\Scripts\python.exe install -r requirements.txt
```

Create `.env` in the repo root:

```env
SPLUNK_MCP_URL=https://127.0.0.1:8089/services/mcp
SPLUNK_MCP_AUTH_HEADER=
SPLUNK_MCP_VERIFY_SSL=false
SPLUNK_MCP_TIMEOUT_SECONDS=60
OLLAMA_URL=http://localhost:11434/api/generate
OLLAMA_MODEL=llama3.2:1b
INCIDENT_DATABASE_URL=sqlite:///data/incident_tickets.db
TELEMETRY_ENABLED=true
TELEMETRY_INTERVAL_SECONDS=10
INCIDENT_INJECTION_INTERVAL_SECONDS=900
INCIDENT_ROTATION_TYPES=database_timeout,upstream_api_failure,auth_failure,deployment_regression,cpu_saturation,cache_miss_storm,disk_io_saturation,pod_crash_loop
```

Use `ai_provider=rules` during setup if Ollama is not running.

Incident tickets are stored in `INCIDENT_DATABASE_URL`. The default uses SQLite so the demo runs immediately. For Postgres, set a URL such as:

```env
INCIDENT_DATABASE_URL=postgresql://postgres:postgres@127.0.0.1:5432/agentic_ops
```

## Run The App

Start all local services from the repo root:

```powershell
.\run_all.ps1
```

If Windows blocks PowerShell scripts, use:

```cmd
run_all.bat
```

If dependencies are not installed yet, run:

```powershell
.\run_all.ps1 -Install
```

Or:

```cmd
run_all.bat -Install
```

The script starts Ollama, the telemetry API, and the incident API in the background. It does not open extra PowerShell windows; check the VS Code Ports tab for the printed ports.

Ports can be changed without editing the file:

```powershell
.\run_all.ps1 -TelemetryPort 8010 -IncidentPort 8002 -OllamaPort 11434
```

Manual fallback: open separate terminals from the repo root.

Terminal 1: Ollama server.

```powershell
ollama serve
```

Terminal 2: telemetry and log generation API.

```powershell
.\.venv\Scripts\Activate.ps1
uvicorn app.main:app --host 127.0.0.1 --port 8010
```

Terminal 3: incident investigation API.

```powershell
.\.venv\Scripts\Activate.ps1
uvicorn app.incident_api:app --host 127.0.0.1 --port 8002
```

Optional dashboard:

```powershell
.\.venv\Scripts\Activate.ps1
streamlit run app/dashboard.py
```

Default service URLs:

```text
Telemetry API: http://127.0.0.1:8010
Incident API:  http://127.0.0.1:8002
```

## Continuous Live Logs

When the telemetry API is running, it continuously appends normal checkout traffic to `data/logs/proxy_nginx.log`, `data/logs/application_spring.log`, and `data/logs/database_postgres.log`.

The background stream injects one scheduled incident every 15 minutes by default. Scheduled incidents rotate through `INCIDENT_ROTATION_TYPES`, so each interval gets one distinct incident type before the list repeats. Incident injections write correlated evidence to all six log files, including infrastructure metrics, Ollama runtime metrics, and agent activity metrics.

Useful settings:

```env
TELEMETRY_ENABLED=true
TELEMETRY_INTERVAL_SECONDS=10
INCIDENT_INJECTION_INTERVAL_SECONDS=900
INCIDENT_ROTATION_TYPES=database_timeout,upstream_api_failure,auth_failure,deployment_regression,cpu_saturation,cache_miss_storm,disk_io_saturation,pod_crash_loop
```

Check the live stream:

```powershell
Invoke-RestMethod "http://127.0.0.1:8010/telemetry/live/status"
```

## Generate Multi-Log Demo Traffic

Use the dashboard or call the API directly:

```powershell
Invoke-RestMethod -Method Post "http://127.0.0.1:8010/telemetry/multilog/generate-demo-traffic?incident_type=database_timeout&request_count=100&window_minutes=15"
```

Supported incident types:

- `database_timeout`
- `upstream_api_failure`
- `auth_failure`
- `deployment_regression`
- `cpu_saturation`
- `cache_miss_storm`
- `disk_io_saturation`
- `pod_crash_loop`
- `random`

The five required hackathon incident classes are the first five. Each generated 15-minute window contains one injected incident and otherwise successful traffic.

## Run The Agent Investigation

After Splunk is monitoring `data/logs/*.log`, run:

```powershell
Invoke-RestMethod "http://127.0.0.1:8002/multilog/incident-summary?ai_provider=rules&remediation_mode=ticket_only"
```

Automatically detect the latest Splunk anomaly, deduplicate it, create a confirmed incident, and create a safe remediation ticket:

```powershell
Invoke-RestMethod -Method Post "http://127.0.0.1:8002/automation/detect-ticket?ai_provider=rules&remediation_mode=ticket_only"
```

Create an incident:

```powershell
Invoke-RestMethod "http://127.0.0.1:8002/multilog/create-incident?ai_provider=rules&remediation_mode=ticket_only"
```

Create a safe remediation ticket:

```powershell
Invoke-RestMethod -Method Post "http://127.0.0.1:8002/agent/action/create-ticket/<incident_id>"
```

Splunk alert webhook with severity policy:

```powershell
Invoke-RestMethod -Method Post "http://127.0.0.1:8002/webhook/splunk-alert?ai_provider=rules" `
  -ContentType "application/json" `
  -Body '{"service":"checkout-service","endpoint":"/api/v2/checkout","status":504,"error_type":"database_timeout","trace_id":"tr-demo","request_id":"req-demo","db_pool_waiting":28}'
```

Policy behavior:

| Priority | Behavior |
| --- | --- |
| `P1` | RCA, incident creation, autonomous simulated remediation, and recovery feedback event. |
| `P2` | RCA, incident creation, safe remediation ticket, and human approval required. |
| `P3` | Observation-only feedback event; no incident and no remediation. |

The ticket payload includes evidence and validation searches. It does not terminate processes, restart containers, or run destructive actions.

MCP server-created tickets can be stored in the same incident database. The external MCP ticket ID is preserved as `external_ticket_id`, and the source is marked as `mcp_server`:

```powershell
Invoke-RestMethod -Method Post "http://127.0.0.1:8002/mcp/tickets" `
  -ContentType "application/json" `
  -Body '{"ticket_id":"MCP-12345","severity":"HIGH","affected_service":"checkout-service","root_cause":"MCP server reported checkout anomaly","ai_summary":"MCP generated summary"}'
```

Before human-in-loop remediation is approved, the API checks deduplication and requires `confirmed_anomaly=true`. Duplicate or unconfirmed anomalies cannot create remediation tickets, cannot be approved, and cannot execute remediation.

## Splunk Ingestion Summary

The app queries by `source` file name plus sourcetype fallback because the current local Splunk index has these observed mappings:

| Source file | Observed sourcetype |
| --- | --- |
| `data/logs/agent_metrics.log` | `agentic-ops` |
| `data/logs/application_spring.log` | `agentic-ops` |
| `data/logs/database_postgres.log` | `agentic-ops` |
| `data/logs/ollama_runtime.log` | `agentic-ops` |
| `data/logs/proxy_nginx.log` | `agentic-ops`, with some older rows as `access_combined_wcookie` |
| `data/logs/system_metrics.log` | `agentic-ops` |

Recommended clean Splunk file monitor sourcetypes are still:

```text
data/logs/proxy_nginx.log         -> agentic:proxy:nginx
data/logs/application_spring.log  -> agentic:app:spring
data/logs/database_postgres.log   -> agentic:db:postgres
data/logs/system_metrics.log      -> agentic:infra:metrics
data/logs/ollama_runtime.log      -> agentic:ai:ollama
data/logs/agent_metrics.log       -> splunk:agent:metrics
data/logs/agent_feedback.log      -> splunk:agent:feedback
```

The Incident API supports both the recommended sourcetypes and the verified local `agentic-ops`/`access_combined_wcookie` mappings.

Full instructions are in [docs/SPLUNK_GUIDE.md](docs/SPLUNK_GUIDE.md).

## Quality Checks

Run syntax and import checks:

```powershell
.\.venv\Scripts\python.exe -c "import fastapi, requests, streamlit, pandas; print('dependency imports ok')"
.\.venv\Scripts\python.exe -c "import ast, pathlib; files=['app/main.py','app/incident_api.py','app/multi_log_generator.py','app/dashboard.py','app/splunk_mcp_client.py','app/incident_summary.py','app/splunk_query.py']; [ast.parse(pathlib.Path(f).read_text()) for f in files]; print('syntax ok')"
```

Run generator contract smoke:

```powershell
.\.venv\Scripts\python.exe -c "from app.multi_log_generator import generate_demo_traffic, REQUIRED_INCIDENT_TYPES; import pathlib; failures=[]; 
for incident_type in REQUIRED_INCIDENT_TYPES:
    summary=generate_demo_traffic(request_count=100, incident_type=incident_type, window_minutes=15, clear_existing=True)
    proxy=pathlib.Path('data/logs/proxy_nginx.log').read_text().splitlines()
    app=pathlib.Path('data/logs/application_spring.log').read_text().splitlines()
    success=sum('status=200' in line for line in proxy)
    incident=sum(('status=504' in line or 'status=503' in line or 'status=502' in line or 'status=500' in line or 'status=401' in line) for line in proxy)
    app_errors=sum('level=ERROR' in line or '[ERROR]' in line for line in app)
    print(incident_type, success, incident, app_errors, summary['trace_id'])
    if success != 99 or incident != 1 or app_errors != 1: failures.append(incident_type)
print('failures', failures)"
```

Expected result:

```text
failures []
```

## Demo Flow For Judges

1. Generate `database_timeout` traffic.
2. Show Splunk has six sourcetypes.
3. Show the proxy 504 on `/api/v2/checkout`.
4. Run the agent investigation.
5. Show correlation steps:
   - proxy anomaly detection
   - application trace pivot
   - database time-window pivot
   - metrics pressure and recovery check
   - agent activity metrics check
6. Create the incident.
7. Create the remediation ticket.
8. Show validation SPL searches in the ticket.

## GitHub Push Commands

Review changes:

```powershell
git status --short
git diff -- README.md docs app
```

Stage and commit:

```powershell
git add README.md docs .gitignore app requirements.txt MULTI_LOG_OBSERVABILITY_PLAN_2026-06-07_22-53-18.md
git commit -m "Build Splunk agentic observability demo"
```

Push:

```powershell
git remote -v
git push origin main
```

If your branch is not `main`, replace `main` with the current branch name from:

```powershell
git branch --show-current
```
