# Ready-to-Paste `inputs.conf`

This file contains the missing file monitors for the project logs that are not currently showing up in Splunk metadata.

Use the exact Windows path below if the repo lives at:

`E:\capstone-pro\splunk-hackathon-FINAL`

If your repo is in a different location, replace only the root path and keep the file names unchanged.

## `inputs.conf`

```ini
[monitor://E:\capstone-pro\splunk-hackathon-FINAL\data\app.log]
disabled = 0
index = main
sourcetype = agentic-ops

[monitor://E:\capstone-pro\splunk-hackathon-FINAL\data\incidents.log]
disabled = 0
index = main
sourcetype = aiops-incidents

[monitor://E:\capstone-pro\splunk-hackathon-FINAL\data\aiops_investigations.log]
disabled = 0
index = main
sourcetype = aiops-investigations

[monitor://E:\capstone-pro\splunk-hackathon-FINAL\data\aiops_remediation.log]
disabled = 0
index = main
sourcetype = aiops-remediation

[monitor://E:\capstone-pro\splunk-hackathon-FINAL\data\ai_triages.log]
disabled = 0
index = main
sourcetype = ai-mcp-triage-agent

[monitor://E:\capstone-pro\splunk-hackathon-FINAL\data\ai_assistant.log]
disabled = 0
index = main
sourcetype = aiops-ai-assistant

[monitor://E:\capstone-pro\splunk-hackathon-FINAL\data\forecast.log]
disabled = 0
index = main
sourcetype = aiops-forecast

[monitor://E:\capstone-pro\splunk-hackathon-FINAL\data\system_health.log]
disabled = 0
index = main
sourcetype = aiops-system-health

[monitor://E:\capstone-pro\splunk-hackathon-FINAL\data\index_health.log]
disabled = 0
index = main
sourcetype = aiops-index-health

[monitor://E:\capstone-pro\splunk-hackathon-FINAL\data\metadata_snapshot.log]
disabled = 0
index = main
sourcetype = aiops-metadata

[monitor://E:\capstone-pro\splunk-hackathon-FINAL\data\correlation.log]
disabled = 0
index = main
sourcetype = aiops-correlation

[monitor://E:\capstone-pro\splunk-hackathon-FINAL\data\timeline.log]
disabled = 0
index = main
sourcetype = aiops-timeline

[monitor://E:\capstone-pro\splunk-hackathon-FINAL\data\mcp_metrics.log]
disabled = 0
index = main
sourcetype = aiops-mcp-metrics

[monitor://E:\capstone-pro\splunk-hackathon-FINAL\data\splunk_ai_activity.log]
disabled = 0
index = main
sourcetype = aiops-splunk-ai-activity
```

## Where To Put It

Place the file in the local app config directory on the Splunk instance that should ingest these files:

`$SPLUNK_HOME/etc/apps/agentic_ops/local/inputs.conf`

If you are testing in an existing app, use that app’s `local/` directory.

## How To Configure It

1. Copy the `inputs.conf` block above into the target Splunk app’s `local/inputs.conf`.
2. Make sure the repo is actually mounted or copied at the path used in the stanzas.
3. Keep `index = main` unless you intentionally want a different index.
4. Confirm the `props.conf` JSON parsing settings are deployed too:
   - `SHOULD_LINEMERGE = false`
   - `KV_MODE = json`
   - `TIME_PREFIX = "timestamp":"`
   - `TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3N%:z`
   - `MAX_TIMESTAMP_LOOKAHEAD = 35`
5. Restart Splunk or reload the inputs if your deployment supports it.
6. Verify ingestion with searches like:
   - `index=main sourcetype="aiops-ai-assistant"`
   - `index=main sourcetype="aiops-forecast"`
   - `index=main sourcetype="aiops-timeline"`
   - `index=main sourcetype="aiops-mcp-metrics"`

## Why This Is Needed

The dashboard is built around these sourcetypes. If a sourcetype is not monitored, the corresponding panel will stay at zero or blank even if the app is generating the file locally.

## Notes

- `data/incidents.json` is state storage, not a log source, so it should not be monitored.
- The internal Splunk log paths you listed under `$SPLUNK_HOME\var\log\...` are separate from the project logs. Add them only if you want Splunk internals indexed too.
- The project’s generated AI Assistant and forecast files are the ones most likely responsible for the all-zero dashboard panels if they are missing from inputs.
