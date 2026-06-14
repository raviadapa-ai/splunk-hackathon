# Ready-to-Paste `props.conf`

Use this exact file in:

`$SPLUNK_HOME/etc/apps/agentic_ops/local/props.conf`

This is the format the project is tuned for. It uses the `timestamp` field as the event time and preserves the timezone offset written by the app.

## `props.conf`

```ini
[agentic-ops]
SHOULD_LINEMERGE = false
KV_MODE = json
TIME_PREFIX = "timestamp":"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3N%:z
MAX_TIMESTAMP_LOOKAHEAD = 35

[aiops-incidents]
SHOULD_LINEMERGE = false
KV_MODE = json
TIME_PREFIX = "timestamp":"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3N%:z
MAX_TIMESTAMP_LOOKAHEAD = 35

[aiops-investigations]
SHOULD_LINEMERGE = false
KV_MODE = json
TIME_PREFIX = "timestamp":"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3N%:z
MAX_TIMESTAMP_LOOKAHEAD = 35

[aiops-remediation]
SHOULD_LINEMERGE = false
KV_MODE = json
TIME_PREFIX = "timestamp":"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3N%:z
MAX_TIMESTAMP_LOOKAHEAD = 35

[ai-mcp-triage-agent]
SHOULD_LINEMERGE = false
KV_MODE = json
TIME_PREFIX = "timestamp":"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3N%:z
MAX_TIMESTAMP_LOOKAHEAD = 35

[aiops-ai-assistant]
SHOULD_LINEMERGE = false
KV_MODE = json
TIME_PREFIX = "timestamp":"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3N%:z
MAX_TIMESTAMP_LOOKAHEAD = 35

[aiops-forecast]
SHOULD_LINEMERGE = false
KV_MODE = json
TIME_PREFIX = "timestamp":"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3N%:z
MAX_TIMESTAMP_LOOKAHEAD = 35

[aiops-system-health]
SHOULD_LINEMERGE = false
KV_MODE = json
TIME_PREFIX = "timestamp":"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3N%:z
MAX_TIMESTAMP_LOOKAHEAD = 35

[aiops-index-health]
SHOULD_LINEMERGE = false
KV_MODE = json
TIME_PREFIX = "timestamp":"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3N%:z
MAX_TIMESTAMP_LOOKAHEAD = 35

[aiops-metadata]
SHOULD_LINEMERGE = false
KV_MODE = json
TIME_PREFIX = "timestamp":"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3N%:z
MAX_TIMESTAMP_LOOKAHEAD = 35

[aiops-correlation]
SHOULD_LINEMERGE = false
KV_MODE = json
TIME_PREFIX = "timestamp":"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3N%:z
MAX_TIMESTAMP_LOOKAHEAD = 35

[aiops-timeline]
SHOULD_LINEMERGE = false
KV_MODE = json
TIME_PREFIX = "timestamp":"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3N%:z
MAX_TIMESTAMP_LOOKAHEAD = 35

[aiops-mcp-metrics]
SHOULD_LINEMERGE = false
KV_MODE = json
TIME_PREFIX = "timestamp":"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3N%:z
MAX_TIMESTAMP_LOOKAHEAD = 35

[aiops-splunk-ai-activity]
SHOULD_LINEMERGE = false
KV_MODE = json
TIME_PREFIX = "timestamp":"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3N%:z
MAX_TIMESTAMP_LOOKAHEAD = 35
```

## Why This Version

The app writes JSONL records with a `timestamp` field like:

`2026-06-13T11:14:09.419+05:30`

This config tells Splunk to use that field as `_time` directly, which keeps the dashboard queries aligned with the real event time.

## Important

Do not replace this with `INDEXED_EXTRACTIONS = json` unless you know you want index-time JSON field extraction and have tested the timestamp behavior carefully. For this project, the repo's JSON parsing template is the safer option.
