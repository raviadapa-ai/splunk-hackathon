# Application Interaction Overview

## How Your Application Interacts With Splunk

Your application uses Splunk as the telemetry, correlation, and audit layer.

- `app/telemetry.py` writes JSONL events to `data/app.log` and other workflow logs.
- Splunk file inputs monitor the `data/` files and parse them as searchable events.
- Saved searches perform baseline checks, noise reduction, and correlation scoring.
- Splunk can trigger the FastAPI triage path through `POST /webhook/splunk-alert`.
- The app can write investigation and remediation output back into log files so Splunk can re-ingest and display the results.
- Splunk MCP is used for evidence, metadata, and runtime verification during investigation.

## How AI Models Or Agents Are Integrated

The app uses both deterministic logic and optional AI assistance.

- `SplunkMCPClient` gathers evidence from Splunk MCP tools.
- `CodexRcaAgent` performs a second-pass RCA when the Codex CLI is available.
- The RCA flow builds a structured JSON prompt from the incident, evidence, and recent event context.
- If Codex is unavailable or returns invalid output, the app falls back to deterministic RCA rules.
- The app also writes AI assistant and forecast artifacts to log files so Splunk can surface them in the dashboard.

## Data Flow Between Services, APIs, And Application Components

### 1. Telemetry generation

- `app/telemetry.py` produces synthetic operational events.
- Events are written to local JSONL files under `data/`.
- These records include incident context, latency, status codes, dependency data, and resource pressure signals.

### 2. Splunk ingestion and analysis

- Splunk monitors the JSONL files as file-based inputs.
- JSON fields and event timestamps are extracted for search and aggregation.
- Saved searches calculate baselines, reduce noise, and build correlated incident candidates.

### 3. FastAPI incident handling

- Splunk alerts or dashboard actions call FastAPI endpoints such as `/webhook/splunk-alert` and the incident APIs.
- FastAPI creates or hydrates the canonical incident record in `data/incidents.json`.
- The app stores investigation state, remediation state, and AI output for later review.

### 4. Evidence and AI processing

- The app calls Splunk MCP to gather evidence and metadata.
- Deterministic RCA logic produces a stable baseline outcome.
- Codex can refine that result when the CLI is available.
- Final investigation and remediation records are written back to the workflow logs.

### 5. Dashboard visibility

- Splunk re-ingests the workflow logs.
- The dashboard reads the updated incident, investigation, and remediation streams.
- Operators can review the latest state, evidence, and AI summary from the same data pipeline.
