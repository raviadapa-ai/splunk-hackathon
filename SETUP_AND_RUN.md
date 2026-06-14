# Setup and Run

This file covers the shortest path to get the app running locally on Windows.

## Setup

1. Clone the repository.
2. Copy `.env.example` to `.env`.
3. Fill in the values for the local Splunk MCP endpoint and any HEC or Codex settings you want to use.
4. Install the Python dependencies from `requirements.txt`.

If you want to create a local virtual environment first, use:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

The startup script uses a local `.venv` if it exists. If not, it falls back to `py -3.12`.

## Run

1. Start the app with `.\run_all.ps1`.
2. Open `http://127.0.0.1:8002/dashboard`.
3. Optionally generate telemetry with `python -m scripts.run_generator --demo-timeline --overwrite`.
4. Trigger an incident from the dashboard or webhook flow if you want to exercise the full path.

Useful commands:

```powershell
python -m scripts.run_generator --demo-timeline --overwrite
.\stop_all.ps1
```

`run_all.ps1` starts the FastAPI app and a small Codex CLI warm-up helper. `stop_all.ps1` stops the app listener and that helper only.
