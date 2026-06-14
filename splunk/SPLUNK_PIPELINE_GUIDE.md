# Splunk Agentic Ops Incident Copilot Pipeline Guide

This guide walks through the full Splunk Agentic Ops Incident Copilot pipeline in Splunk, from raw telemetry to the final dashboard.

## Submission Notes

Use this guide as the technical companion to the GitHub README. For a judge or reviewer, the important things are:

- the repo can be cloned and run locally
- Splunk can ingest the JSONL files with the provided example configs
- the dashboard shows noise reduction, correlation, investigation, remediation, AI Assistant, and forecast evidence
- the submission package excludes local caches, generated data, and secrets

See [PUBLIC_RELEASE.md](PUBLIC_RELEASE.md) for the exact include/exclude list.

Current runtime files:

```text
data/app.log                  telemetry stream
data/incidents.log            incident lifecycle audit
data/aiops_investigations.log investigation evidence and MCP enrichment
data/aiops_remediation.log    approval and remediation audit
data/ai_triages.log           AI root-cause summary and Codex/HEC writeback audit
data/ai_assistant.log         AI Assistant-ready SPL prompts and generated suggestions
data/forecast.log             forecast-ready time-series signals
data/system_health.log        Splunk MCP startup health
data/index_health.log         Splunk index validation
data/metadata_snapshot.log    Splunk metadata discovery
data/correlation.log          correlation events
data/timeline.log             incident lifecycle timeline
data/mcp_metrics.log          MCP query metrics
data/splunk_ai_activity.log   Splunk AI Assistant usage audit
data/incidents.json           local incident state store, not a Splunk input
```

## 1. Confirm Log Ingestion

Verify that Splunk is receiving the application logs:

```spl
index=main sourcetype="agentic-ops"
| stats count by sourcetype source host
```

Expected source:

```text
E:\capstone-pro\splunk-hackathon-FINAL\data\app.log
```

The dashboard also depends on incident lifecycle, investigation, and remediation events. Add these file monitors in Splunk:

```text
E:\capstone-pro\splunk-hackathon-FINAL\data\app.log
E:\capstone-pro\splunk-hackathon-FINAL\data\incidents.log
E:\capstone-pro\splunk-hackathon-FINAL\data\aiops_investigations.log
E:\capstone-pro\splunk-hackathon-FINAL\data\aiops_remediation.log
E:\capstone-pro\splunk-hackathon-FINAL\data\ai_triages.log
E:\capstone-pro\splunk-hackathon-FINAL\data\system_health.log
E:\capstone-pro\splunk-hackathon-FINAL\data\index_health.log
E:\capstone-pro\splunk-hackathon-FINAL\data\metadata_snapshot.log
E:\capstone-pro\splunk-hackathon-FINAL\data\correlation.log
E:\capstone-pro\splunk-hackathon-FINAL\data\timeline.log
E:\capstone-pro\splunk-hackathon-FINAL\data\mcp_metrics.log
E:\capstone-pro\splunk-hackathon-FINAL\data\splunk_ai_activity.log
```

Use these sourcetypes:

```text
data/app.log                  sourcetype=agentic-ops
data/incidents.log            sourcetype=aiops-incidents
data/aiops_investigations.log sourcetype=aiops-investigations
data/aiops_remediation.log    sourcetype=aiops-remediation
data/ai_triages.log           sourcetype=ai-mcp-triage-agent
data/system_health.log        sourcetype=aiops-system-health
data/index_health.log         sourcetype=aiops-index-health
data/metadata_snapshot.log    sourcetype=aiops-metadata
data/correlation.log          sourcetype=aiops-correlation
data/timeline.log             sourcetype=aiops-timeline
data/mcp_metrics.log          sourcetype=aiops-mcp-metrics
data/splunk_ai_activity.log   sourcetype=aiops-splunk-ai-activity
```

`data/aiops_investigations.log` is the permanent investigation audit stream. Do not also monitor `data/investigations.log`; that older file has been retired to avoid duplicate investigation events.

Splunk UI path:

```text
Settings -> Data inputs -> Files & directories -> New Local File & Directory
```

Use index `main`.

## 2. Validate JSON Field Extraction

Run:

```spl
index=main sourcetype="agentic-ops"
| table _time service host endpoint status_code latency_ms error_type severity incident_id dependency deployment_version
| head 20
```

If fields appear in separate columns, Splunk is parsing the JSON events correctly.

## 3. Create Baseline Latency Report

Save this as:

```text
AIOps - Baseline Latency
```

Search:

```spl
index=main sourcetype="agentic-ops"
| bin _time span=1m
| eval latency_ms=tonumber(latency_ms), status_code=tonumber(status_code), error_type=coalesce(error_type,"null")
| stats avg(latency_ms) as avg_latency stdev(latency_ms) as std_latency p95(latency_ms) as p95_latency by _time service
```

This establishes normal latency behavior per service.

## 4. Create Noise Reduction Report

Save this as:

```text
AIOps - Noise Reduction
```

Search:

```spl
index=main sourcetype="agentic-ops"
| eval latency_ms=tonumber(latency_ms), status_code=tonumber(status_code), error_type=coalesce(error_type,"null"), severity=coalesce(severity,"UNKNOWN")
| eventstats avg(latency_ms) as baseline_avg stdev(latency_ms) as baseline_std p95(latency_ms) as baseline_p95 by service
| eval z_score=if(baseline_std>0,(latency_ms-baseline_avg)/baseline_std,0)
| eval is_signal=case(
    status_code>=500, 1,
    error_type IN ("database_timeout","upstream_api_failure","auth_failure","deployment_regression","cpu_saturation"), 1,
    error_type="latency_regression" AND z_score>=2.5, 1,
    z_score>=3, 1,
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
    error_type="latency_regression" OR z_score>2.5, "latency_anomaly",
    true(), "noise"
)
| where signal!="noise"
```

This removes normal events and keeps meaningful operational signals.

## 5. Create Correlation Search

Save this as:

```text
AIOps - Correlated Incident Candidates
```

Search:

```spl
index=main sourcetype="agentic-ops"
| eval latency_ms=tonumber(latency_ms), status_code=tonumber(status_code), error_type=coalesce(error_type,"null"), severity=coalesce(severity,"UNKNOWN"), incident_id=coalesce(incident_id,"none")
| eventstats avg(latency_ms) as baseline_avg stdev(latency_ms) as baseline_std p95(latency_ms) as baseline_p95 by service
| eval z_score=if(baseline_std>0,(latency_ms-baseline_avg)/baseline_std,0)
| eval signal=case(
    status_code>=500, "server_error",
    error_type="database_timeout", "database_timeout",
    error_type="upstream_api_failure", "dependency_failure",
    error_type="auth_failure", "auth_failure",
    error_type="deployment_regression", "deployment_regression",
    error_type="cpu_saturation", "cpu_saturation",
    error_type="latency_regression" OR z_score>2.5, "latency_anomaly",
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
    dc(trace_id) as affected_traces
    latest(severity) as severity
    latest(status_code) as status_code
    by _time service incident_id _time_bucket
| eval signal_count=tonumber(signal_count)
| eval correlation_score=signal_count + mvcount(signals)*2 + mvcount(hosts) + mvcount(endpoints)
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

This produces incident candidates from grouped signals, deduplicated by `service + incident_id + 5 minute bucket`.

## 6. Create an Incident Candidate Alert

From the correlation search, choose:

```text
Save As -> Alert
```

Recommended alert settings:

```text
Name: AIOps - Incident Candidate Alert
Schedule: Every 5 minutes
Time range: Last 5 minutes
Trigger condition: Number of results is greater than 0
Throttle: service + incident_id for 10 minutes
```

This gives Splunk-side incident detection.

If you want the alert to create a human-readable incident identifier in the payload sent to FastAPI, include `incident_id`, `service`, `host`, `search_name`, `severity`, and `trigger_time` in the webhook body. Splunk does not create the incident record in this project. Python does.

## 7. Start the API for Investigation

The FastAPI app queries Splunk through MCP and writes investigation events to:

```text
data/aiops_investigations.log
```

Start the API:

```powershell
$env:PYTHONPATH=".\.pythonlibs"
py -3.12 -m uvicorn app.main:app --host 127.0.0.1 --port 8002
```

Create an incident:

```powershell
Invoke-RestMethod -Method Post http://127.0.0.1:8002/incidents/create `
  -Body '{"incident_type":"auth_failure","inject_burst":true}' `
  -ContentType 'application/json'
```

List incidents:

```powershell
Invoke-RestMethod http://127.0.0.1:8002/incidents
```

Investigate the returned incident:

```powershell
Invoke-RestMethod -Method Post http://127.0.0.1:8002/incidents/<incident_id>/investigate
```

The investigation call writes to both `data/incidents.log` and `data/aiops_investigations.log`. The incident log carries lifecycle state such as `status`, `incident_status`, and `investigation_status`. The investigation log carries the RCA payload such as `root_cause`, `confidence_score`, `evidence_summary`, `ai_summary`, `llm_provider`, `mcp_evidence_summary`, and `mcp_investigation`.

The webhook triage flow also writes to `data/ai_triages.log`. That event keeps the final AI summary, the selected provider, and the HEC writeback status together so Splunk can search the agent output separately from the incident lifecycle.

Validate investigation events in Splunk:

```spl
index=main sourcetype="aiops-incidents"
| table _time incident_id service status incident_status investigation_status severity root_cause confidence_score evidence_summary mcp_evidence_summary
| sort - _time
```

Validate mandatory MCP startup evidence:

```spl
index=main sourcetype IN ("aiops-system-health","aiops-index-health","aiops-metadata")
| table _time sourcetype status splunk_version server_name index_name exists event_count known_sourcetypes fallback_reason
| sort - _time
```

## 7a. Configure the Splunk Webhook

Use this when you want Splunk to POST an alert directly to the FastAPI triage endpoint.

1. Open Splunk and go to `Settings -> Searches, reports, and alerts`.
2. Open the alert you want to automate, or create a new alert from your correlation search.
3. In the alert actions, enable `Webhook`.
4. Set the webhook URL to:

```text
http://127.0.0.1:8002/webhook/splunk-alert
```

5. Use `POST` as the method.
6. Set the content type to `application/json`.
7. Send a JSON body that matches the fields the API accepts. A minimal payload looks like this:

```json
{
  "search_name": "AIOps - Incident Candidate Alert",
  "host": "checkout-01",
  "service": "checkout-api",
  "incident_id": "inc-20260609103000-acde12",
  "trigger_time": "2026-06-09T10:30:00Z",
  "severity": "HIGH",
  "result": {
    "host": "checkout-01",
    "service": "checkout-api",
    "incident_id": "inc-20260609103000-acde12"
  }
}
```

8. Save the alert and test it once with a known incident candidate.
9. Confirm the POST landed in FastAPI by checking `data/incidents.log` and `data/ai_triages.log`.

The webhook handler reads the top-level fields first, then falls back to the nested `result` object. If your Splunk alert payload uses a different field shape, map those values into `search_name`, `host`, `service`, `incident_id`, and `trigger_time`.

## 7b. Configure HEC Writeback in Splunk

Use this when you want the AI summary stored back into Splunk as a separate event stream.

1. In Splunk, open `Settings -> Data Inputs -> HTTP Event Collector`.
2. Open `Global Settings` and make sure HEC is enabled.
3. Create a new token for AI triage writeback.
4. Set the token name to something like `ai-triage-writeback`.
5. Set the default index to `ai_triages` if you want the token to target that index by default.
6. Set the source to `ai-mcp-triage-agent` or leave the source to be provided by the app.
7. Give the token permission to write to the `ai_triages` index.
8. Copy the token value and set the FastAPI environment variables:

```powershell
$env:SPLUNK_HEC_URL="https://your-splunk-instance:8088/services/collector"
$env:SPLUNK_HEC_TOKEN="<hec-token>"
$env:SPLUNK_HEC_AI_TRIAGE_INDEX="ai_triages"
$env:SPLUNK_HEC_VERIFY_TLS="true"
```

9. Ensure the `ai_triages` index exists in Splunk before sending events.
10. Trigger the webhook again and confirm the writeback record appears in Splunk:

```spl
index=ai_triages source="ai-mcp-triage-agent"
| table _time incident_id service status original_alert target_host llm_provider ai_summary ai_root_cause_summary mcp_evidence_summary hec_status
| sort - _time
```

If HEC is not configured, the webhook still completes triage and records `hec_status=skipped` in `data/ai_triages.log`.

## 8. Run Human Approval and Simulated Remediation

Run this flow from the Splunk dashboard:

```text
Open the saved Splunk dashboard for this project
```

In the `Incident Table` panel, click an incident row to set the `incident_id` token. Then use the `Remediation Actions` panel to run `Investigate`, `Approve`, `Execute`, `Reject`, or `Close`. The links target the matching FastAPI endpoints, but the operator workflow is driven from Splunk and the dashboard refresh shows the new state after each action.

Approve:

```powershell
Invoke-RestMethod -Method Post http://127.0.0.1:8002/incidents/<incident_id>/approve `
  -Body '{"approved_by":"demo-operator"}' `
  -ContentType 'application/json'
```

Execute remediation simulation:

```powershell
Invoke-RestMethod -Method Post http://127.0.0.1:8002/incidents/<incident_id>/execute
```

Close an executed incident:

```powershell
Invoke-RestMethod -Method Post http://127.0.0.1:8002/incidents/<incident_id>/close
```

This writes remediation events to:

```text
data/aiops_remediation.log
```

Validate remediation events in Splunk:

```spl
index=main sourcetype="aiops-remediation"
| table _time incident_id service status remediation_status action result approved_by
| sort - _time
```

Validate AI triage writeback events in Splunk:

```spl
index=main sourcetype="ai-mcp-triage-agent"
| table _time incident_id service status original_alert target_host llm_provider ai_summary ai_root_cause_summary mcp_evidence_summary hec_status
| sort - _time
```

## 9. Create the Final Dashboard

Use the provided dashboard XML:

```text
splunk/dashboard_simple.xml
```

Splunk UI path:

```text
Dashboards -> Create New Dashboard -> Classic Dashboard -> Source
```

Paste the XML from:

```text
E:\capstone-pro\splunk-hackathon-FINAL\splunk\dashboard_simple.xml
```

Dashboard panels:

```text
Total Events
Noise Reduced
Noise Reduction
Correlated Incidents
Top Root Causes
MCP Investigation Results
Remediation Status
Incident Timeline
MCP Tool Usage
Confidence Scores
Investigation Source
Incident Table
Remediation Actions
Application signal summary
Investigation Summary
Remediation Summary
```

Dashboard queries used in `splunk/dashboard_simple.xml`:

```spl
index=main sourcetype="agentic-ops"
| stats count as total_events
```

```spl
index=main sourcetype="agentic-ops"
| eval is_noise=if(status_code<500 AND error_type="null" AND latency_ms<1000,1,0)
| stats count(eval(is_noise=1)) as noise_events
```

```spl
index=main sourcetype="agentic-ops" earliest=-24h@h latest=now
| eval status_code=tonumber(status_code), latency_ms=tonumber(latency_ms), error_type=coalesce(error_type,"null")
| eval is_noise=if(status_code<500 AND error_type="null" AND latency_ms<1000, 1, 0)
| stats count as total_events count(eval(is_noise=1)) as noise_events count(eval(is_noise=0)) as signal_events
| eval signal_events=total_events-noise_events
| eval noise_reduction_pct=if(total_events=0,0,round((noise_events/total_events)*100,2))
| fields noise_reduction_pct signal_events noise_events total_events
```

```spl
index=main sourcetype="aiops-incidents" incident_id!="none"
| sort 0 - _time
| stats first(_time) as last_seen first(severity) as severity first(incident_status) as incident_status first(status) as status by incident_id
| eval current_status=coalesce(incident_status,status,"UNKNOWN"), severity=coalesce(severity,"UNKNOWN")
| stats count as incidents by severity current_status
```

```spl
index=main sourcetype="aiops-investigations" incident_id!="none"
| sort 0 - _time
| stats first(root_cause) as root_cause by incident_id
| eval root_cause=coalesce(root_cause,"unknown")
| stats count as incidents by root_cause
| sort - incidents
```

```spl
index=main sourcetype="aiops-remediation" incident_id!="none"
| sort 0 - _time
| stats first(remediation_status) as remediation_status by incident_id
| eval remediation_status=coalesce(remediation_status,"UNKNOWN")
| stats count as incidents by remediation_status
```

```spl
index=main (sourcetype="aiops-incidents" OR sourcetype="aiops-investigations" OR sourcetype="aiops-remediation") incident_id!="none"
| eventstats latest(_time) as incident_last_seen by incident_id
| stats latest(service) as service latest(severity) as severity latest(status) as status latest(incident_status) as incident_status latest(investigation_status) as investigation_status latest(root_cause) as root_cause latest(remediation_status) as remediation_status latest(confidence_score) as confidence_score max(incident_last_seen) as _time by incident_id
| eval current_status=coalesce(incident_status,status,"UNKNOWN"), remediation_status=coalesce(remediation_status,"NOT_STARTED"), investigation_status=coalesce(investigation_status,"NOT_STARTED")
| fields _time incident_id service severity current_status investigation_status remediation_status root_cause confidence_score
| sort - _time
```

```spl
index=main sourcetype="aiops-incidents" incident_id!="none"
| sort 0 - _time
| stats first(_time) as _time first(service) as service first(status) as status first(incident_status) as incident_status first(investigation_status) as investigation_status first(severity) as severity by incident_id
| eval current_status=coalesce(incident_status,status,"UNKNOWN")
| fields _time incident_id service current_status investigation_status severity
| sort - _time
```

```spl
index=main sourcetype="agentic-ops"
| eval status_code=tonumber(status_code), latency_ms=tonumber(latency_ms), error_type=coalesce(error_type,"null"), severity=coalesce(severity,"UNKNOWN")
| stats count as events avg(latency_ms) as avg_latency_ms max(latency_ms) as max_latency_ms count(eval(status_code>=500 OR error_type!="null")) as signal_events by service severity error_type
| eval avg_latency_ms=round(avg_latency_ms,2)
| sort - signal_events - events
```

```spl
index=main sourcetype="aiops-investigations" incident_id!="none"
| sort 0 - _time
| stats count as record_count first(_time) as _time first(service) as service first(severity) as severity first(status) as status first(incident_status) as incident_status first(investigation_status) as investigation_status first(root_cause) as root_cause first(confidence_score) as confidence_score first(evidence_summary) as evidence_summary first(mcp_evidence_summary) as mcp_evidence_summary first(mcp_investigation) as mcp_investigation by incident_id
| sort - _time
```

```spl
index=main sourcetype="aiops-remediation" incident_id!="none"
| sort 0 - _time
| stats first(_time) as _time first(service) as service first(status) as status first(remediation_status) as remediation_status first(action) as action first(result) as result first(approved_by) as approved_by first(evidence_summary) as evidence_summary first(mcp_evidence_summary) as mcp_evidence_summary first(investigation_status) as investigation_status first(mcp_investigation) as mcp_investigation by incident_id
| sort - _time
```

```spl
index=main sourcetype="ai-mcp-triage-agent"
| stats latest(_time) as _time latest(service) as service latest(status) as status latest(original_alert) as original_alert latest(target_host) as target_host latest(llm_provider) as llm_provider latest(ai_summary) as ai_summary latest(ai_root_cause_summary) as ai_root_cause_summary latest(mcp_evidence_summary) as mcp_evidence_summary latest(hec_status) as hec_status by incident_id
| sort - _time
```

## 10. Final Validation Queries

Application signal summary:

```spl
index=main sourcetype="agentic-ops"
| stats count by service severity error_type
```

Investigation summary:

```spl
index=main sourcetype="aiops-investigations"
| table _time incident_id service severity status root_cause confidence_score evidence_summary ai_summary llm_provider
| sort - _time
```

Remediation summary:

```spl
index=main sourcetype="aiops-remediation"
| table _time incident_id service remediation_status action result approved_by
| sort - _time
```

## End-to-End Flow

```text
app.log
  -> Splunk ingestion
  -> incidents.log
  -> incident lifecycle events
  -> noise reduction SPL
  -> correlation SPL
  -> incident candidate alert
  -> MCP-backed investigation
  -> aiops_investigations.log
  -> ai_triages.log
  -> human approval and simulated remediation
  -> aiops_remediation.log
  -> final dashboard
```

## Incident Flow and Severity Ownership

The full pre-remediation flow is documented in [INCIDENT_FLOW_SEQUENCE.md](/E:/capstone-pro/splunk-hackathon-FINAL/INCIDENT_FLOW_SEQUENCE.md).

At a high level:

- Splunk ingests the raw telemetry and computes baseline, anomaly, and correlation scores.
- The correlation search assigns a candidate severity to the grouped signal set.
- Python creates or reuses the incident ID, persists the canonical incident record, and finalizes severity after investigation.
- Final severity used for remediation is stored in the Python incident state and in the audit events that Splunk indexes.
- Remediation only starts after investigation is complete and approval is granted.

## Architecture

```text
Telemetry generator
  -> app/telemetry.py
  -> data/app.log
  -> data/incidents.log
  -> Splunk file monitor
  -> SPL noise reduction and correlation
  -> candidate incidents in Splunk
  -> FastAPI app in app/main.py
  -> Splunk MCP evidence lookup when available
  -> data/aiops_investigations.log
  -> data/ai_triages.log
  -> human approval and remediation actions
  -> data/aiops_remediation.log
  -> Splunk dashboard refresh
```

Core components:

```text
app/main.py              FastAPI endpoints, dashboard rendering, incident lifecycle
app/telemetry.py         Event generation, deterministic demo timeline, JSONL write helpers
app/storage.py           Incident persistence and append-only audit logs
app/models.py            Shared telemetry, evidence, incident, and result schemas
splunk/inputs.conf.example  File monitoring template for the JSONL sources
splunk/props.conf.example    Timestamp parsing template for _time and JSON extraction
splunk/dashboard_simple.xml  Live dashboard panels and action links
```

## Project Flow

```text
1. Telemetry is generated locally and written as JSON lines to `data/app.log`.
2. Incident lifecycle events are written to `data/incidents.log`, while `data/incidents.json` remains the local state store.
3. Splunk ingests the JSONL files and parses `_time` from the `timestamp` field.
4. SPL removes noise and groups related signals into incident candidates.
5. The operator opens the Splunk dashboard, selects an incident, and runs the incident action links from the `Remediation Actions` panel.
6. Click `Prepare SPL` to generate AI Assistant-ready prompt and SPL records for the incident.
7. The app queries Splunk MCP when available, persists MCP evidence immediately, and builds deterministic RCA.
8. Codex reasoning is mandatory and does not replace the persisted MCP evidence.
9. Investigation output is written to `data/aiops_investigations.log` with `sourcetype=aiops-investigations`.
10. The AI RCA summary, MCP evidence summary, and HEC writeback status are written to `data/ai_triages.log` with `sourcetype=ai-mcp-triage-agent`.
11. The app also prepares AI Assistant-ready SPL prompts in `data/ai_assistant.log` and forecast-ready signals in `data/forecast.log`.
12. The Splunk dashboard uses those forecast records to populate `Forecast Summary` and `Forecast Risk Table`.
13. Approval, execution, and closure actions are written to `data/aiops_remediation.log`.
14. Splunk dashboard panels refresh and show the updated incident state automatically.
```

## Submission Checklist

Before you hand this repo to a judge:

1. Confirm `README.md` tells them how to install, run, and demo the project.
2. Confirm `splunk/dashboard_simple.xml` and the `splunk/*.example` files are present.
3. Confirm `PUBLIC_RELEASE.md` matches the files you intend to publish.
4. Confirm no real `.env`, `.venv`, `data/`, or cache directories are included.
5. Keep the demo focused on the judge-visible path: reduce noise, correlate, investigate, approve, execute, close.

## Incident ID Ownership

In this project, Splunk does not create the incident ID for the triggered alert. Python does.

The incident ID is created in `app/telemetry.py` when telemetry injection happens:

```python
incident_id = f"inc-{utc_now().strftime('%Y%m%d%H%M%S')}-{uuid4().hex[:6]}"
```

The same Python-side incident ID then flows through:

1. `data/app.log` as `incident_id` on correlated telemetry events.
2. `data/incidents.log` when the incident is created or updated.
3. `data/aiops_investigations.log` after MCP-backed investigation.
4. `data/ai_triages.log` after AI summary generation and HEC writeback status recording.
5. `data/aiops_remediation.log` during approval and remediation.
6. Splunk searches and dashboard panels, which group and display on `incident_id`.

For a Splunk-triggered alert that posts to `/webhook/splunk-alert`, the alert may pass an existing `incident_id`. If it does not, the FastAPI code creates one locally and persists it in the logs and state store before writing the follow-up records.

## MCP Token Note

The Splunk MCP endpoint is:

```text
https://127.0.0.1:8089/services/mcp
```

In `C:\Users\HOME\.codex\config.toml`, make sure the bearer token starts directly with:

```text
eyJ...
```

If extra characters appear before `eyJ`, Splunk returns:

```text
Authentication failed: Invalid or expired token
```
