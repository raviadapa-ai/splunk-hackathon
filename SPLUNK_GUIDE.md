# Splunk Guide

This is the single Splunk reference for the project. It covers file monitoring, parsing, dashboards, Splunk-to-Python data movement, webhook alerting, and HEC writeback.

## 1. What Splunk Owns

Splunk is responsible for:

- file monitoring
- JSON parsing
- event-time extraction
- baseline and correlation searches
- dashboards
- alerting and webhook delivery
- indexing the workflow audit trail

Python is responsible for:

- generating telemetry
- maintaining incident state
- turning evidence into RCA
- controlling remediation state changes
- writing the workflow audit logs that Splunk ingests

## 2. Files To Monitor

Configure file monitors for these JSONL files:

```text
data/app.log                  sourcetype=agentic-ops
data/incidents.log            sourcetype=aiops-incidents
data/aiops_investigations.log sourcetype=aiops-investigations
data/aiops_remediation.log    sourcetype=aiops-remediation
data/ai_triages.log           sourcetype=ai-mcp-triage-agent
data/ai_assistant.log         sourcetype=aiops-ai-assistant
data/forecast.log             sourcetype=aiops-forecast
data/system_health.log        sourcetype=aiops-system-health
data/index_health.log         sourcetype=aiops-index-health
data/metadata_snapshot.log    sourcetype=aiops-metadata
data/correlation.log          sourcetype=aiops-correlation
data/timeline.log             sourcetype=aiops-timeline
data/mcp_metrics.log          sourcetype=aiops-mcp-metrics
data/splunk_ai_activity.log   sourcetype=aiops-splunk-ai-activity
```

Do not monitor `data/incidents.json`.

## 3. Inputs Template

Use `splunk/inputs.conf.example` as the monitor template.

The key behavior is:

- point each stanza at the repo's `data/` files
- set `index = main`
- assign the matching sourcetype
- keep the local app config under `local/`

If you are configuring the source manually in the Splunk UI, use:

```text
Settings -> Data inputs -> Files & directories -> New Local File & Directory
```

Point the input at the repo telemetry stream and keep the destination index as `main`.

## 4. Props Template

Use `splunk/props.conf.example` for all JSON sourcetypes.

The parsing model is the same for each log stream:

- `SHOULD_LINEMERGE = false`
- `KV_MODE = json`
- `TIME_PREFIX = "timestamp":"`
- `TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3N%:z`
- `MAX_TIMESTAMP_LOOKAHEAD = 35`

This makes Splunk use the event timestamp from the JSON payload rather than file indexing time.

## 4a. Validate JSON Field Extraction

Run this search after the input is configured:

```spl
index=main sourcetype="agentic-ops"
| table _time service host endpoint status_code latency_ms error_type severity incident_id dependency deployment_version
| head 20
```

If the fields appear in separate columns, Splunk is parsing the JSON events correctly.

## 4b. Baseline and Correlation Searches

Save the following searches in Splunk:

```text
AIOps - Baseline Latency
AIOps - Noise Reduction
AIOps - Correlated Incident Candidates
```

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

## 5. Dashboard Overview

Import `splunk/dashboard_simple.xml` for the full operational dashboard.

The dashboard shows:

- Total Events
- Noise Reduced
- Noise Reduction
- Remediation Actions
- Incident Table
- Selected Incident AI Summary
- Correlated Incidents
- Top Root Causes
- MCP Investigation Results
- Remediation Status
- Incident Timeline
- MCP Tool Usage
- Investigation Source
- AI Assistant Usage
- Forecast Summary
- Forecast Risk Table

## 5a. SPL Queries Used By The Dashboard

The dashboard is intentionally driven by a compact query set that maps directly to the workflow.

### Telemetry and reduction

- `Total Events` counts all `agentic-ops` events.
- `Noise Reduced` flags benign traffic using status code, error type, and latency.
- `Noise Reduction` compares total, noise, and signal counts to show the reduction percentage.

### Incident and correlation

- `Incident Table` merges `aiops-incidents`, `aiops-investigations`, `aiops-remediation`, and `ai-mcp-triage-agent` into one incident view.
- `Correlated Incidents` reads `aiops-correlation` and displays the correlation score, signal list, host list, endpoint, event count, and peak CPU/memory pressure.
- `Top Root Causes` groups `aiops-investigations` by root cause.

### Investigation and remediation

- `MCP Investigation Results` reads `aiops-investigations` and surfaces `mcp_investigation`, `mcp_evidence_summary`, and `mcp_tools_used`.
- `Remediation Status` counts records from `aiops-remediation` by remediation status.
- `Incident Timeline` replays the state changes from `aiops-timeline`.

### MCP metrics and assistant output

- `MCP Tool Usage` aggregates `aiops-mcp-metrics` by `mcp_tool_usage`.
- `Investigation Source` classifies the source of the RCA result.
- `AI Assistant Usage` reads `aiops-ai-assistant` and shows the generated prompt, suggested SPL, and explanation.
- `Forecast Summary` and `Forecast Risk Table` read `aiops-forecast` and display predicted latency and confidence.

These queries are also represented in `splunk/dashboard_panels.spl` so panels can be reused or rebuilt without starting from scratch.

## 6. Dashboard Actions

The remediation action panel is the main operator path.

The action order is:

1. Select an incident row.
2. Run `Investigate`.
3. Review the incident summary and evidence panels.
4. Run `Prepare SPL`.
5. Run `Approve`.
6. Run `Execute`.
7. Run `Reject` if needed.
8. Run `Close` only after execution.

The action links call FastAPI directly. `Investigate` forces a fresh MCP + Codex pass so the dashboard and report reflect the latest evidence.

## 6a. Splunk AI Assistant For SPL

If Splunk AI Assistant is enabled in your Splunk instance, it can be used as the analyst copilot for SPL work.

Use it to:

- generate SPL from incident context or a plain-language request
- explain what an existing SPL query does
- optimize a query for readability or performance
- iterate on the correlation search before saving it as an alert

The application already prepares AI Assistant-ready artifacts:

- `data/ai_assistant.log` stores the prompt, intent, suggested SPL, and explanation
- `data/splunk_ai_activity.log` stores the same preparation as an operator-facing workflow event

That means the dashboard can show AI Assistant output even when the feature is disabled on the target instance, and analysts can copy the same prompt into Splunk AI Assistant when it is available.

## 7. What Happens During Investigation

When the operator runs `Investigate`, Python does the following:

1. Loads or hydrates the incident.
2. Queries Splunk MCP for related evidence.
3. Falls back to alert-context evidence if MCP is unavailable.
4. Runs the deterministic RCA engine.
5. Invokes Codex for a fresh second-pass AI summary when the CLI is available.
6. Writes investigation and incident lifecycle logs back to disk.
7. Updates the dashboard once Splunk ingests the new logs.

The investigation output is stored in:

- `data/incidents.log`
- `data/aiops_investigations.log`
- `data/timeline.log`
- `data/correlation.log`
- `data/mcp_metrics.log`
- `data/ai_assistant.log`
- `data/forecast.log`
- `data/ai_triages.log`

`data/ai_triages.log` is the primary source for the dashboard AI summary field, and `data/aiops_investigations.log` is the primary source for MCP evidence summary.

## 8. Data Movement Between Splunk And Python

### Splunk to Python

Splunk can drive the workflow in two ways.

- Dashboard links call FastAPI endpoints directly.
- A Splunk alert can POST a webhook payload to `/webhook/splunk-alert`.

The webhook payload can carry top-level or nested `result` fields. The app reads:

- `search_name`
- `host`
- `service`
- `incident_id`
- `severity`
- `trigger_time`

### MCP tools used by the app

The project uses Splunk MCP as the evidence and metadata layer.

The main tools exercised by the app are:

- `splunk_get_info` for startup verification
- `splunk_get_indexes` to confirm the main index exists
- `splunk_get_metadata` for sourcetype, host, and source discovery
- `splunk_run_query` for incident evidence and alert-context queries

The client also exposes other Splunk MCP capabilities:

- `splunk_get_kv_store_collections`
- `splunk_get_knowledge_objects`
- `splunk_run_saved_search`
- `splunk_get_index_info`

The investigation path always favors `splunk_run_query` when it needs evidence from the telemetry stream.

### SPL helper surface for AI Assistant

The MCP client also exposes the SPL-oriented helper names that align with Splunk AI Assistant workflows:

- `saia_generate_spl`
- `saia_explain_spl`
- `saia_optimize_spl`
- `saia_ask_splunk_question`

These helpers support query generation, explanation, optimization, and natural-language SPL questions when AI Assistant is available. In this repo the application still functions without the feature being enabled because it writes assistant-ready prompt and SPL artifacts to the local logs.

#### Webhook configuration in Splunk

Use this when a search or correlation alert should create or update an incident in Python.

Configure the alert action so it sends an HTTP POST to:

```text
http://127.0.0.1:8002/webhook/splunk-alert
```

Recommended settings:

- Method: `POST`
- Content type: `application/json`
- Authentication: none for local demo, bearer token if you enabled `AGENTIC_OPS_API_TOKEN`
- Trigger condition: correlation search or notable alert
- Alert body: include the field names above, either at the top level or under `result`

Recommended body example:

```json
{
  "search_name": "High database timeout rate",
  "host": "checkout-01",
  "service": "checkout-api",
  "incident_id": "inc-20260613120000-acde12",
  "severity": "HIGH",
  "trigger_time": "2026-06-13T12:00:00Z"
}
```

The FastAPI handler is tolerant of common Splunk field names:

- `search_name`, `alert_name`, `name`
- `incident_id`, `sid`
- `trigger_time`, `triggered_time`, `time`

What happens after the POST:

1. The app creates or hydrates the incident.
2. The incident is stored in `data/incidents.json`.
3. Splunk MCP evidence is queried if available.
4. The deterministic RCA engine runs.
5. Codex enhancement runs if the CLI is available.
6. The app writes `aiops-incidents`, `aiops-investigations`, `aiops-correlation`, `aiops-timeline`, `aiops-ai-assistant`, `aiops-forecast`, and `ai-mcp-triage-agent`.
7. The dashboard reflects the new state after ingestion.

### Python to Splunk

After the workflow runs, Python writes new JSONL records to disk.

Splunk ingests those records and updates the dashboard.

That loop is what makes the platform feel interactive:

- incident state changes are visible in `aiops-incidents`
- evidence and RCA appear in `aiops-investigations`
- timeline events appear in `aiops-timeline`
- correlation results appear in `aiops-correlation`
- assistant-ready SPL appears in `aiops-ai-assistant`
- forecast signals appear in `aiops-forecast`
- triage summary and writeback metadata appear in `ai-mcp-triage-agent`

## 8a. AI Assistant In Splunk

When Splunk AI Assistant is available in the target instance, it is the natural place to:

- generate a candidate SPL query from the incident context
- explain why a search is returning noise or missing matches
- optimize a search before saving it as a panel or alert

The app prepares the same workflow by writing prompt and suggested SPL artifacts to `data/ai_assistant.log` and `data/splunk_ai_activity.log`, so the dashboard can show the AI Assistant path even when the feature is not activated.

## 9. HEC Writeback

Use HEC only if you want the AI triage summary written back into Splunk as a separate event stream.

### Steps

1. In Splunk, open `Settings -> Data Inputs -> HTTP Event Collector`.
2. Enable HEC in `Global Settings`.
3. Create a token for AI triage writeback.
4. Give the token access to the `ai_triages` index.
5. Keep the source as `ai-mcp-triage-agent` if you want the stream to match the existing project sourcetype.
6. Set these environment variables in `.env` or your shell:

```powershell
$env:SPLUNK_HEC_URL="https://your-splunk-instance:8088/services/collector"
$env:SPLUNK_HEC_TOKEN="<hec-token>"
$env:SPLUNK_HEC_AI_TRIAGE_INDEX="ai_triages"
$env:SPLUNK_HEC_VERIFY_TLS="true"
```

#### What Python sends to HEC

The app posts a JSON event to Splunk HEC with:

- `host`
- `source=ai-mcp-triage-agent`
- `sourcetype=_json`
- `index=ai_triages`
- `event.timestamp`
- `event.status=TRIAGED`
- `event.original_alert`
- `event.target_host`
- `event.incident_id`
- `event.service`
- `event.severity`
- `event.confidence_score`
- `event.llm_provider`
- `event.ai_summary`
- `event.ai_reasoning`
- `event.ai_root_cause_summary`
- `event.mcp_evidence_summary`
- `event.alert_payload`

#### HEC behavior

- If the URL or token is missing, the app skips HEC and records `hec_status={"status":"skipped","reason":"hec_not_configured"}`.
- If Splunk returns an HTTP error, triage still completes and the error is recorded in `hec_status`.
- The local triage log in `data/ai_triages.log` always captures the writeback outcome.
- Use TLS verification only when the Splunk cert is trusted; disable it only for local self-signed test instances.

### Behavior

- If HEC is configured, FastAPI posts the AI summary to Splunk.
- If HEC is missing, the app still completes triage.
- The `hec_status` field is written into `data/ai_triages.log`.
- Failed or skipped HEC writeback does not block investigation, approval, or remediation.

## 10. SPL Search Examples

Use these to verify each stage.

### Raw telemetry

```spl
index=main sourcetype="agentic-ops"
| stats count by service severity error_type
```

### Incident correlation

```spl
index=main sourcetype="aiops-correlation"
| table _time incident_id service host endpoint incident_class signals correlation_score window event_count
```

### Investigation output

```spl
index=main sourcetype="aiops-investigations" incident_id!="none"
| table _time incident_id service root_cause confidence_score evidence_summary ai_summary mcp_evidence_summary mcp_tools_used
```

### Timeline

```spl
index=main sourcetype="aiops-timeline" incident_id!="none"
| table _time incident_id service severity status event root_cause remediation_status mcp_investigation
```

### Forecast

```spl
index=main sourcetype="aiops-forecast"
| table _time incident_id service forecast_horizon predicted_latency_ms confidence_score model_name model_source
```

### AI triage writeback

```spl
index=ai_triages source="ai-mcp-triage-agent"
| table _time incident_id service status severity root_cause confidence_score ai_summary hec_status
```

## 11. What To Expect In Each Stage

### Stage 1: Telemetry ingestion

- Splunk reads `data/app.log`.
- The telemetry stream contains normal traffic plus anomalies.
- `agentic-ops` shows baseline behavior and outliers.

### Stage 2: Noise reduction

- Splunk separates routine traffic from signals.
- The dashboard uses the signal count and reduction panels to show what was filtered.

### Stage 3: Correlation

- Signals are grouped into a 5-minute window.
- The correlation score is computed from signal density, host spread, and event count.
- The result becomes a candidate incident.

### Stage 4: Incident creation

- FastAPI creates or hydrates the incident.
- The incident is stored in `data/incidents.json`.
- `aiops-incidents` receives the lifecycle events.

### Stage 5: Evidence gathering

- FastAPI asks Splunk MCP for supporting evidence.
- `aiops-mcp-metrics` records the tool usage.
- If MCP fails, the app falls back to alert-context evidence.

### Stage 6: RCA and assistant prep

- The decision engine produces root cause, confidence, and recommended actions.
- `aiops-investigations` stores the investigation record.
- `aiops-ai-assistant` stores the prompt and SPL suggestion.

### Stage 7: Forecast and risk

- The app generates a forecast signal from the evidence.
- `aiops-forecast` stores the risk model summary.
- The dashboard shows forecast summary and forecast risk rows.

### Stage 8: Approval and remediation

- Approval is required before execution.
- Execution is simulated.
- Closure happens after execution.
- `aiops-remediation` and `aiops-timeline` capture the state changes.

### Stage 9: Writeback and audit

- The AI triage summary can be written back to Splunk through HEC.
- `ai_triages` stores the writeback summary and HEC status.
- The dashboard reflects the final state after ingestion.

If you are packaging this publicly, keep the local launcher minimal:

- `run_all.ps1` starts only the FastAPI app and the Codex CLI helper.
- `stop_all.ps1` stops only the app listener and the Codex CLI helper.

## 12. Dashboard Troubleshooting

If a panel is empty, check these first:

- the file monitor exists for the matching `data/` log
- the sourcetype matches the dashboard search
- the app wrote a record with a `timestamp`
- the event landed in `index=main`
- the JSON props are deployed

If the AI triage writeback panel is empty:

- confirm `SPLUNK_HEC_URL`
- confirm `SPLUNK_HEC_TOKEN`
- confirm the `ai_triages` index exists
- confirm the token can write to that index

## 13. Operational Summary

The project is designed so Splunk can show the whole lifecycle:

- telemetry in
- signal reduction
- correlation
- incident creation
- MCP evidence
- RCA
- approval
- execution
- closure
- writeback

That is the core story the repo is built to demonstrate.


