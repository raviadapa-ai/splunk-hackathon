# Splunk Agentic Ops Incident Copilot

Splunk-native incident copilot for operational intelligence. This repo implements an end-to-end incident workflow where Python generates telemetry, Splunk ingests and analyzes it, alerts can hand off to FastAPI through a webhook, Splunk MCP provides evidence-backed investigation, Codex can perform a second-pass RCA, and the final investigation and remediation state is written back into Splunk for dashboard visibility and auditability.

## What It Is

This repo is a full incident workflow, not just a log generator.

- Python generates telemetry, incident bursts, correlation records, AI artifacts, and remediation events.
- Splunk ingests the JSONL files, extracts fields, computes latency baselines, reduces noise, and correlates signals into incident candidates.
- FastAPI owns canonical incident state, webhook triage, dashboard actions, and remediation guards.
- Splunk MCP provides the evidence layer by calling the Splunk MCP server tools from Python.
- Codex performs a second-pass RCA when the CLI is available, using the MCP evidence plus raw event context.
- The app writes investigation, timeline, forecast, and remediation decisions back into JSONL logs that Splunk can monitor.

## Current Architecture

```text
app/telemetry.py
  -> writes JSONL telemetry to data/app.log
  -> Splunk file monitor ingests sourcetype="agentic-ops"
  -> SPL baseline / noise reduction / correlation searches
  -> candidate incident or alert threshold
  -> webhook POST to FastAPI /webhook/splunk-alert
  -> incident hydrated in data/incidents.json
  -> SplunkMCPClient calls Splunk MCP server tools
  -> CodexRcaAgent may run a second-pass RCA
  -> Python writes incidents, investigations, timeline, forecast, and remediation logs
  -> optional HEC writeback to Splunk for triage summaries
  -> Splunk dashboard refreshes from the re-ingested events
```

## Main Responsibilities

### Python

- Generates telemetry and controlled incident bursts in `app/telemetry.py`.
- Owns the canonical incident record in `data/incidents.json`.
- Exposes the FastAPI endpoints for incident creation, investigation, approval, execution, closeout, dashboard rendering, and webhook triage.
- Calls Splunk MCP through `SplunkMCPClient` for evidence, metadata, and runtime verification.
- Calls `CodexRcaAgent` when a second-pass AI RCA is available.
- Writes workflow events to JSONL logs so Splunk can re-ingest the results.

### Splunk

- Monitors the JSONL files under `data/` as file inputs.
- Parses JSON fields and event timestamps from each record.
- Performs statistical baseline checks, noise reduction, and correlation.
- Exposes the operational dashboard and the saved-search layer used by the workflow.
- Re-ingests workflow, evidence, and forecast logs for auditability and historical review.

### Splunk MCP Server Integration

- The Python client talks to the Splunk MCP server over the MCP tools endpoint.
- `splunk_get_info` verifies the server at startup.
- `splunk_get_indexes` and `splunk_get_metadata` validate the Splunk data surface.
- `splunk_run_query` is the main evidence query path for incident investigation.
- MCP usage is metered into `data/mcp_metrics.log` so Splunk can visualize tool usage and investigation cost.

### Codex

- Performs a structured RCA pass from the incident, MCP evidence, and raw event context.
- Uses a prompt that instructs the model to return only JSON with root cause, severity, confidence, evidence summary, recommended actions, and safe remediation actions.
- Falls back to deterministic RCA if the Codex CLI is unavailable or returns invalid output.
- Investigation summaries are written to the triage stream so the dashboard can show the latest reasoning even when the AI pass is skipped.

## Data Flow

### 1. Telemetry generation

`app/telemetry.py` writes realistic events to `data/app.log`.

Each event includes:

- service
- host
- endpoint
- status code
- latency
- error type
- severity
- dependency
- deployment version
- incident id
- timeline stage

Normal traffic is mixed with occasional anomalies so Splunk can show both noise and signal. The telemetry generator produces:

- healthy transactions for baseline estimation
- latency regressions for anomaly scoring
- database timeouts for dependency analysis
- authentication failures for identity-path analysis
- CPU and memory pressure for resource correlation
- deployment regressions for release-related RCA

This gives Splunk enough variation to calculate statistical baselines and show how alert storms are reduced into incident candidates.

### 2. Splunk ingestion

`splunk/inputs.conf.example` and `splunk/props.conf.example` define how Splunk monitors and parses the JSONL files.

For a manual Splunk setup in the UI, use:

```text
Settings -> Data inputs -> Files & directories -> New Local File & Directory
```

Configure the file input to write into `index=main` and map the JSON telemetry stream to `sourcetype="agentic-ops"`.

Splunk ingests:

- `data/app.log`
- `data/incidents.log`
- `data/aiops_investigations.log`
- `data/aiops_remediation.log`
- `data/ai_triages.log`
- `data/ai_assistant.log`
- `data/forecast.log`
- `data/system_health.log`
- `data/index_health.log`
- `data/metadata_snapshot.log`
- `data/correlation.log`
- `data/timeline.log`
- `data/mcp_metrics.log`
- `data/splunk_ai_activity.log`

`data/incidents.json` is state storage and is not monitored.

### 2a. Baseline validation and saved searches

Run this validation search to confirm JSON field extraction:

```spl
index=main sourcetype="agentic-ops"
| table _time service host endpoint status_code latency_ms error_type severity incident_id dependency deployment_version
| head 20
```

If the fields appear in separate columns, Splunk is parsing the JSON events correctly.

Recommended saved searches:

- `AIOps - Baseline Latency`
- `AIOps - Noise Reduction`
- `AIOps - Correlated Incident Candidates`

Baseline latency:

```spl
index=main sourcetype="agentic-ops"
| bin _time span=1m
| eval latency_ms=tonumber(latency_ms), status_code=tonumber(status_code), error_type=coalesce(error_type,"null")
| stats avg(latency_ms) as avg_latency stdev(latency_ms) as std_latency p95(latency_ms) as p95_latency by _time service
```

Noise reduction:

```spl
index=main sourcetype="agentic-ops"
| eval latency_ms=tonumber(latency_ms), cpu_pct=tonumber(cpu_pct), memory_pct=tonumber(memory_pct), status_code=tonumber(status_code), error_type=coalesce(error_type,"null"), severity=coalesce(severity,"UNKNOWN")
| eventstats avg(latency_ms) as baseline_latency_avg stdev(latency_ms) as baseline_latency_std avg(cpu_pct) as baseline_cpu_avg stdev(cpu_pct) as baseline_cpu_std avg(memory_pct) as baseline_memory_avg stdev(memory_pct) as baseline_memory_std by service
| eval latency_z=if(baseline_latency_std>0,(latency_ms-baseline_latency_avg)/baseline_latency_std,0)
| eval cpu_z=if(baseline_cpu_std>0,(cpu_pct-baseline_cpu_avg)/baseline_cpu_std,0)
| eval memory_z=if(baseline_memory_std>0,(memory_pct-baseline_memory_avg)/baseline_memory_std,0)
| eval is_signal=case(
    status_code>=500, 1,
    error_type IN ("database_timeout","upstream_api_failure","auth_failure","deployment_regression","cpu_saturation","memory_pressure"), 1,
    error_type="latency_regression" AND latency_z>=2.5, 1,
    cpu_pct>=90 OR cpu_z>=2.5, 1,
    memory_pct>=90 OR memory_z>=2.5, 1,
    latency_z>=3, 1,
    true(), 0
)
| where is_signal=1
| eval signal=case(
    status_code>=500, "server_error",
    error_type="database_timeout", "database_timeout",
    error_type="upstream_api_failure", "dependency_failure",
    error_type="auth_failure", "auth_failure",
    error_type="deployment_regression", "deployment_regression",
    error_type="cpu_saturation", "cpu_saturation",
    error_type="memory_pressure", "memory_pressure",
    error_type="latency_regression" OR latency_z>2.5, "latency_anomaly",
    cpu_pct>=90 OR cpu_z>2.5, "cpu_pressure",
    memory_pct>=90 OR memory_z>2.5, "memory_pressure",
    true(), "noise"
)
| where signal!="noise"
```

Correlation search:

```spl
index=main sourcetype="agentic-ops"
| eval latency_ms=tonumber(latency_ms), cpu_pct=tonumber(cpu_pct), memory_pct=tonumber(memory_pct), status_code=tonumber(status_code), error_type=coalesce(error_type,"null"), severity=coalesce(severity,"UNKNOWN"), incident_id=coalesce(incident_id,"none")
| eventstats avg(latency_ms) as baseline_latency_avg stdev(latency_ms) as baseline_latency_std avg(cpu_pct) as baseline_cpu_avg stdev(cpu_pct) as baseline_cpu_std avg(memory_pct) as baseline_memory_avg stdev(memory_pct) as baseline_memory_std by service
| eval latency_z=if(baseline_latency_std>0,(latency_ms-baseline_latency_avg)/baseline_latency_std,0)
| eval cpu_z=if(baseline_cpu_std>0,(cpu_pct-baseline_cpu_avg)/baseline_cpu_std,0)
| eval memory_z=if(baseline_memory_std>0,(memory_pct-baseline_memory_avg)/baseline_memory_std,0)
| eval signal=case(
    status_code>=500, "server_error",
    error_type="database_timeout", "database_timeout",
    error_type="upstream_api_failure", "dependency_failure",
    error_type="auth_failure", "auth_failure",
    error_type="deployment_regression", "deployment_regression",
    error_type="cpu_saturation", "cpu_saturation",
    error_type="memory_pressure", "memory_pressure",
    error_type="latency_regression" OR latency_z>2.5, "latency_anomaly",
    cpu_pct>=90 OR cpu_z>2.5, "cpu_pressure",
    memory_pct>=90 OR memory_z>2.5, "memory_pressure",
    true(), "noise"
)
| where signal!="noise"
| eval _time_bucket=strftime(_time, "%Y-%m-%dT%H:%M")
| bin _time span=5m
| stats
    count as signal_count
    values(signal) as signals
    values(error_type) as error_types
    values(host) as hosts
    values(endpoint) as endpoints
    values(user_region) as regions
    avg(latency_ms) as avg_latency
    max(latency_ms) as max_latency
    avg(cpu_pct) as avg_cpu_pct
    max(cpu_pct) as max_cpu_pct
    avg(memory_pct) as avg_memory_pct
    max(memory_pct) as max_memory_pct
    dc(trace_id) as affected_traces
    latest(severity) as severity
    latest(status_code) as status_code
    by _time service incident_id _time_bucket
| eval signal_count=tonumber(signal_count)
| eval resource_pressure_score=if(max_cpu_pct>=90 OR max_memory_pct>=90, 4, 0)
| eval correlation_score=signal_count + mvcount(signals)*2 + mvcount(hosts) + mvcount(endpoints) + resource_pressure_score
| eval dedup_key=service . "|" . incident_id . "|" . _time_bucket
| eval severity=case(
    correlation_score>=20, "HIGH",
    correlation_score>=10, "MEDIUM",
    true(), "LOW"
)
| dedup dedup_key
| where correlation_score>=5
| sort - _time
```

### 3. Noise reduction and correlation

Splunk searches the telemetry stream and marks signals versus noise.

The correlation logic groups events into 5-minute windows and computes a score from:

- signal count
- unique signal types
- host diversity
- endpoint diversity
- latency spikes and z-scores
- CPU and memory pressure
- repeated failures on the same incident id

The score produces a candidate incident severity that is shown on the dashboard and can trigger the webhook flow. In the current repo, the correlation search also writes the correlated result back through `write_correlation_event(...)`, which means the dashboard can show correlation history even after the alert has been processed.

### 4. Incident creation

FastAPI creates the canonical incident object and stores it in `data/incidents.json`.

Incident records track:

- incident id
- service
- status
- severity
- root cause
- confidence score
- evidence summary
- AI summary
- MCP evidence summary
- MCP tool usage
- SPL queries used
- remediation state
- approval state
- execution result
- HEC status for the triage writeback

### 5. Evidence collection

When investigation starts, the app queries Splunk MCP for incident evidence and metadata.

If MCP returns evidence:

- Python uses the evidence as the investigation input.
- The deterministic RCA engine produces a baseline result.
- Codex refines that result with a fresh AI summary if the CLI is available.
- The app records the MCP tool names and counts so the investigation can be audited in Splunk.

If MCP is unavailable:

- Python uses the alert context and deterministic rules.
- The app still completes investigation and remediation tracking.
- The dashboard still has a usable incident record and remediation path.

### 5a. How the MCP client works

The current MCP client lives in `app/splunk_mcp_client.py` and uses the MCP tools endpoint directly.

The client flow is:

1. Resolve the MCP URL and auth header from environment variables.
2. Call `splunk_get_info`, `splunk_get_indexes`, or `splunk_get_metadata` for startup and discovery.
3. Call `splunk_run_query` for incident evidence.
4. Convert the raw MCP payload into typed `Evidence` objects.
5. Write a metrics event for every tool call into `data/mcp_metrics.log`.

The client also supports the AI Assistant-oriented method names, but in this repo those methods are intentionally disabled and the app writes deterministic assistant-ready artifacts instead.

### 5b. RCA agent calls

The Codex RCA flow is implemented in `app/llm_agent.py`.

The agent:

- builds a structured JSON prompt from the incident, evidence, and a small slice of raw events
- asks Codex to return only JSON
- normalizes the returned severity, confidence, action list, and summary fields
- falls back to deterministic RCA when the CLI is missing or the output is malformed

This keeps the AI pass evidence-driven instead of turning it into a free-form chat response.

### 6. RCA and remediation planning

`app/decision_engine.py` derives the root cause, severity, confidence, recommended actions, and safe simulation actions from the evidence.

The engine is designed to be stable:

- database timeout maps to connection pool saturation
- upstream API failure maps to dependency failure
- auth failure maps to identity provider failure
- deployment regression maps to release issues
- CPU saturation maps to resource exhaustion
- memory pressure maps to memory exhaustion
- latency regression maps to a latency anomaly or slow service path

The deterministic RCA layer is important because it gives the workflow a stable answer even when Codex or MCP are unavailable.

### 7. AI Assistant and forecast artifacts

After investigation, the app writes two more outputs:

- `data/ai_assistant.log` contains SPL prompt and query tuning guidance.
- `data/forecast.log` contains forecast-ready risk signals and a model-style summary.

These streams are there so Splunk can show what the assistant would suggest and what future risk looks like.

Splunk AI Assistant, when enabled in the target Splunk instance, can be used to:

- generate SPL from a plain-language request
- explain an existing SPL query
- optimize a query for readability or performance
- turn incident context into a different correlation or summary search

This app does not require Splunk AI Assistant to be active. It prepares AI Assistant-ready prompt and suggested SPL records so the dashboard still shows the intended query workflow even when the feature is disabled.

### 8. Alert triggering through webhook

Splunk can trigger the FastAPI triage path through `POST /webhook/splunk-alert`.

That endpoint accepts both top-level fields and nested `result` fields from Splunk alert actions. It can read:

- `search_name`, `alert_name`, or `name`
- `host`
- `service`
- `incident_id` or `sid`
- `severity`
- `trigger_time`, `triggered_time`, or `time`

Webhook triage flow:

1. Splunk alert fires on a saved search or correlation rule.
2. Splunk POSTs the alert payload to FastAPI.
3. FastAPI hydrates or creates the incident record.
4. Python queries MCP for surrounding evidence.
5. The RCA engine and optional Codex pass produce the investigation result.
6. The result is written back to the local event logs and optionally to Splunk via HEC.
7. The dashboard refreshes with the new incident state and summary.

### 9. HEC writeback

HEC is used to write the AI triage summary back into Splunk as a dedicated event stream.

The app posts to:

```text
https://your-splunk-instance:8088/services/collector
```

The event is sent with:

- `Authorization: Splunk <hec-token>`
- `index = ai_triages`
- `source = ai-mcp-triage-agent`
- `sourcetype = _json`

The event body includes:

- timestamp
- status
- original alert metadata
- target host
- incident id
- service
- severity
- confidence score
- llm provider
- ai summary
- ai reasoning
- ai root cause summary
- mcp evidence summary
- alert payload

Behavior:

- If `SPLUNK_HEC_URL` or `SPLUNK_HEC_TOKEN` is missing, HEC is skipped.
- If HEC fails, triage still completes.
- The local triage record always writes `hec_status` so Splunk can show whether writeback succeeded, failed, or was skipped.
- Use `SPLUNK_HEC_VERIFY_TLS=false` only for local self-signed Splunk test instances.

### 10. From Python back to Splunk

After investigation, FastAPI writes updated incident state, investigation output, AI assistant prompt data, forecast output, and remediation events to JSONL logs.

Splunk re-ingests those logs, so the dashboard reflects:

- the final incident state
- the root cause
- the confidence score
- the selected remediation
- the assistant prompt and SPL suggestion
- the forecast view
- the latest webhook triage result

## Dashboard In Splunk

The dashboard is backed by `splunk/dashboard_simple.xml` and the reusable search library in `splunk/dashboard_panels.spl`.

### Core panels

- `Total Events`
- `Noise Reduced`
- `Noise Reduction`
- `Errors in the last hour`
- `Baseline Latency Report`
- `Correlated Incidents`
- `AIOps - Incident Candidate Alert`
- `Remediation Actions`
- `Incident Table`
- `Selected Incident AI Summary`
- `Top Root Causes`
- `MCP Investigation Results`
- `Remediation Status`
- `Incident Timeline`
- `MCP Tool Usage`
- `Investigation Source`
- `AI Assistant Usage`
- `Forecast Summary`
- `Forecast Risk Table`

### What the dashboard shows

- raw operational volume and noise reduction
- event-level errors and latency spikes
- correlated incident candidates with score and severity
- drill-down to incident-specific AI summary and evidence
- MCP evidence and tool usage
- lifecycle state from open to closed
- remediation controls for investigate, approve, execute, reject, and close
- forecast-ready latency risk and confidence

### Dashboard behavior

- `Investigate` opens a fresh analysis path.
- `Approve` is enabled only when the incident has RCA evidence.
- `Execute` is blocked until approval is recorded.
- `Reject` records that the operator declined remediation.
- `Close` finalizes the incident after execution.
- The dashboard refreshes from the JSONL writeback streams, so the state is visible in Splunk without manual reloads.

## Approval And Remediation

The incident is not closed directly after RCA.

The required order is:

1. Investigate
2. Review evidence
3. Approve
4. Execute simulated remediation
5. Close

This guardrail is enforced in the API and reflected in the dashboard actions.

Remediation behavior in the current repo:

- `Investigate` runs the evidence collection and RCA flow.
- `Approve` is only enabled after the incident has evidence and RCA.
- `Execute` only runs after approval and records a simulated safe action.
- `Reject` records that the operator declined the remediation.
- `Close` finalizes the lifecycle after execution.

## Audit Write-Back

Every meaningful stage emits JSONL audit records.

Splunk can search these logs for:

- incident creation
- investigation start and completion
- timeline events
- correlation events
- MCP tool metrics
- AI assistant prep
- forecast signals
- remediation transitions
- triage summaries

## Data Movement Between Splunk And Python

This is the part the demo depends on.

### From Python to Splunk

Python writes telemetry and workflow records to disk.

Splunk reads them through file monitors and parses them into searchable events.

### From Splunk to Python

Splunk can trigger FastAPI in two ways:

- the dashboard action links call the API endpoints directly
- a saved correlation alert can POST a webhook payload to the triage endpoint

The webhook payload may include:

- search name
- host
- service
- incident id
- trigger time
- severity

If fields are nested under a `result` object, the API still reads them.

### MCP tools used by the app

The project uses Splunk MCP as the evidence and metadata layer.

The main tools exercised by the app are:

- `splunk_get_info` for startup verification
- `splunk_get_indexes` to confirm the main index exists
- `splunk_get_metadata` for sourcetype, host, and source discovery
- `splunk_run_query` for incident evidence and alert-context queries

The client also exposes other Splunk MCP capabilities:

- `splunk_get_index_info`
- `splunk_get_knowledge_objects`
- `splunk_get_kv_store_collections`
- `splunk_run_saved_search`

The investigation path always favors `splunk_run_query` when it needs evidence from the telemetry stream.

### SPL helper surface for AI Assistant

The MCP client also exposes the SPL-focused helper names that line up with Splunk AI Assistant workflows:

- `saia_generate_spl`
- `saia_explain_spl`
- `saia_optimize_spl`
- `saia_ask_splunk_question`

In this repo those helpers are optional. The app still works when Splunk AI Assistant is not enabled and writes deterministic prompt plus SPL suggestions to the assistant logs so the dashboard can surface the same workflow.

## Project Layout

- `app/` FastAPI service, telemetry generator, MCP client, workflow logic, and storage helpers
- `splunk/` dashboard XML, SPL, and input/props templates
- `scripts/` helper scripts
- `tests/` unit and API coverage
- `data/` runtime logs and local state
- `requirements.txt` runtime dependencies
- `.env.example` environment template

## Local Run

1. Copy `.env.example` to `.env` and set any local values you need.
2. Install the dependencies from `requirements.txt`.
3. Run `.\run_all.ps1`.
4. Open the FastAPI dashboard at `http://127.0.0.1:8002/dashboard`.
5. Generate logs or trigger an incident from the dashboard or webhook flow.

`run_all.ps1` starts the FastAPI app and a small Codex CLI warm-up helper. `stop_all.ps1` stops the app listener and that helper only.

## Splunk Reference

Use [SPLUNK_GUIDE.md](SPLUNK_GUIDE.md) for the complete Splunk setup, dashboard actions, alerting, and HEC writeback configuration.

## Key Runtime Endpoints

- `GET /health`
- `POST /logs/generate`
- `POST /incidents/create`
- `GET /incidents`
- `GET /incidents/{incident_id}`
- `POST /incidents/{incident_id}/investigate`
- `GET` or `POST /incidents/{incident_id}/assistant`
- `POST /incidents/{incident_id}/approve`
- `POST /incidents/{incident_id}/reject`
- `POST /incidents/{incident_id}/execute`
- `POST /incidents/{incident_id}/close`
- `GET /dashboard`
- `POST /webhook/splunk-alert`

## Testing

The project is covered by API, telemetry, decision-engine, and MCP client tests under `tests/`.

## Public Release Notes

- `Investigate` triggers a fresh MCP + Codex pass.
- The dashboard prefers the latest AI triage record in `data/ai_triages.log` for AI summary fields.
- `mcp_evidence_summary` is persisted from investigation logs so it does not render as `null` after refresh.
- `run_all.ps1` and `stop_all.ps1` manage only the app port and the Codex CLI helper.
