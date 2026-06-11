import os
import re
import tomllib
from typing import Any

import httpx

from app.config import DEFAULT_INDEX
from app.models import Evidence


SPLUNK_MCP_URL = os.getenv("SPLUNK_MCP_URL", "https://127.0.0.1:8089/services/mcp")
SPLUNK_MCP_AUTH_HEADER = os.getenv("SPLUNK_MCP_AUTH_HEADER", "")


def _normalize_auth_header(auth_header: str) -> str:
    value = auth_header.strip()
    if not value:
        return ""
    token = value.removeprefix("Bearer").strip() if value.startswith("Bearer") else value
    jwt_start = token.find("eyJ")
    if jwt_start > 0:
        token = token[jwt_start:]
    return f"Bearer {token}"


def _codex_config_auth_header() -> str:
    config_path = os.path.expanduser("~/.codex/config.toml")
    try:
        with open(config_path, "rb") as handle:
            config = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return ""

    server = config.get("mcp_servers", {}).get("splunk-mcp-server", {})
    args = server.get("args", [])
    if not isinstance(args, list):
        return ""
    for arg in args:
        if isinstance(arg, str) and arg.startswith("Authorization: Bearer "):
            return arg.replace("Authorization: ", "", 1)
    return ""


def _coerce_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item not in {None, ""}]
    if isinstance(value, str):
        if not value:
            return []
        return [item for item in re.split(r"\s*,\s*", value) if item]
    return [str(value)]


def _coerce_number(value: Any) -> float:
    if value in {None, ""}:
        return 0
    if isinstance(value, int | float):
        return float(value)
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0


def _escape_splunk_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def extract_result_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    result = payload.get("result", {})
    rows = result.get("structuredContent", {}).get("results", [])
    if not rows:
        rows = payload.get("results") or []
    if not isinstance(rows, list):
        rows = [rows]
    return [row for row in rows if isinstance(row, dict)]


def _evidence_from_rows(incident_id: str, service: str | None, rows: list[dict[str, Any]]) -> Evidence | None:
    if not rows:
        return None

    first_row = rows[0]
    evidence = {
        "service": first_row.get("service", service or ""),
        "incident_id": first_row.get("incident_id", incident_id),
        "event_count": len(rows),
        "error_types": [str(row.get("error_type")) for row in rows if row.get("error_type") not in {None, "", "null"}],
        "hosts": [str(row.get("host")) for row in rows if row.get("host")],
        "endpoints": [str(row.get("endpoint")) for row in rows if row.get("endpoint")],
        "dependencies": [str(row.get("dependency")) for row in rows if row.get("dependency")],
        "regions": [str(row.get("user_region")) for row in rows if row.get("user_region")],
        "avg_latency_ms": sum(_coerce_number(row.get("latency_ms")) for row in rows) / len(rows),
        "max_latency_ms": max(_coerce_number(row.get("latency_ms")) for row in rows),
        "max_cpu_pct": max(_coerce_number(row.get("cpu_pct")) for row in rows),
        "max_memory_pct": max(_coerce_number(row.get("memory_pct")) for row in rows),
        "max_db_pool_pct": max(_coerce_number(row.get("db_connection_pool_pct")) for row in rows),
        "deployment_versions": [str(row.get("deployment_version")) for row in rows if row.get("deployment_version")],
    }
    return Evidence.model_validate(evidence)


def extract_result_text(payload: dict[str, Any]) -> str:
    result = payload.get("result", {})
    content = result.get("content") or payload.get("content") or []
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    parts = []
    for item in content:
        if isinstance(item, dict) and item.get("text"):
            parts.append(str(item["text"]))
        elif isinstance(item, str):
            parts.append(item)
    return "\n".join(parts)


class SplunkMCPClient:
    def __init__(self, url: str = SPLUNK_MCP_URL, auth_header: str = SPLUNK_MCP_AUTH_HEADER) -> None:
        self.url = url
        resolved_auth = auth_header or os.getenv("SPLUNK_MCP_BEARER_TOKEN", "") or _codex_config_auth_header()
        normalized_auth = _normalize_auth_header(resolved_auth)
        self.headers = {"Authorization": normalized_auth} if normalized_auth else {}

    def _tool_payload(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=15, verify=False) as client:
            response = await client.post(self.url, json=self._tool_payload(tool_name, arguments), headers=self.headers)
            response.raise_for_status()
            payload = response.json()
            if "error" in payload:
                raise ValueError(payload["error"])
            return payload

    async def run_query(
        self,
        query: str,
        earliest_time: str = "-10m",
        latest_time: str = "now",
        row_limit: int = 10,
    ) -> dict[str, Any]:
        return await self.call_tool(
            "splunk_run_query",
            {
                "query": query,
                "earliest_time": earliest_time,
                "latest_time": latest_time,
                "row_limit": row_limit,
            },
        )

    async def query_alert_logs(
        self,
        *,
        host: str | None = None,
        service: str | None = None,
        incident_id: str | None = None,
        earliest_time: str = "-10m",
        latest_time: str = "now",
        row_limit: int = 10,
    ) -> list[dict[str, Any]]:
        clauses = [f"index={DEFAULT_INDEX}", 'sourcetype="agentic-ops"']
        if incident_id:
            clauses.append(f'incident_id="{_escape_splunk_value(incident_id)}"')
        if host:
            clauses.append(f'host="{_escape_splunk_value(host)}"')
        if service:
            clauses.append(f'service="{_escape_splunk_value(service)}"')
        query = " ".join(clauses) + " | sort - _time | head " + str(row_limit)
        payload = await self.run_query(query, earliest_time=earliest_time, latest_time=latest_time, row_limit=row_limit)
        return extract_result_rows(payload)

    async def query_incident_evidence(self, incident_id: str, service: str | None = None) -> Evidence | None:
        service_clause = f' service="{service}"' if service else ""
        queries = [
            (
                f'index={DEFAULT_INDEX} sourcetype="agentic-ops" incident_id="{incident_id}"{service_clause} '
                "| stats count as event_count values(error_type) as error_types values(host) as hosts "
                "values(endpoint) as endpoints values(dependency) as dependencies values(user_region) as regions "
                "avg(latency_ms) as avg_latency_ms max(latency_ms) as max_latency_ms max(cpu_pct) as max_cpu_pct "
                "max(memory_pct) as max_memory_pct max(db_connection_pool_pct) as max_db_pool_pct "
                "values(deployment_version) as deployment_versions by service incident_id"
            ),
            (
                f'index={DEFAULT_INDEX} incident_id="{incident_id}" '
                "| stats count as event_count values(sourcetype) as error_types values(host) as hosts "
                "values(endpoint) as endpoints values(dependency) as dependencies values(user_region) as regions "
                "avg(latency_ms) as avg_latency_ms max(latency_ms) as max_latency_ms max(cpu_pct) as max_cpu_pct "
                "max(memory_pct) as max_memory_pct max(db_connection_pool_pct) as max_db_pool_pct "
                "values(deployment_version) as deployment_versions by service incident_id"
            ),
        ]

        for spl in queries:
            try:
                payload = await self.call_tool(
                    "splunk_run_query",
                    {"query": spl, "earliest_time": "-24h", "latest_time": "now", "row_limit": 1},
                )
            except (httpx.HTTPError, ValueError):
                continue

            rows = extract_result_rows(payload)
            if not rows:
                continue
            row = rows[0]
            if isinstance(row, dict) and "text" not in row:
                evidence = {
                    "service": row.get("service", service or ""),
                    "incident_id": row.get("incident_id", incident_id),
                    "event_count": int(_coerce_number(row.get("event_count"))),
                    "error_types": _coerce_list(row.get("error_types")),
                    "hosts": _coerce_list(row.get("hosts")),
                    "endpoints": _coerce_list(row.get("endpoints")),
                    "dependencies": _coerce_list(row.get("dependencies")),
                    "regions": _coerce_list(row.get("regions")),
                    "avg_latency_ms": _coerce_number(row.get("avg_latency_ms")),
                    "max_latency_ms": _coerce_number(row.get("max_latency_ms")),
                    "max_cpu_pct": _coerce_number(row.get("max_cpu_pct")),
                    "max_memory_pct": _coerce_number(row.get("max_memory_pct")),
                    "max_db_pool_pct": _coerce_number(row.get("max_db_pool_pct")),
                    "deployment_versions": _coerce_list(row.get("deployment_versions")),
                }
                return Evidence.model_validate(evidence)

        raw_rows = await self.query_alert_logs(
            host=None,
            service=service,
            incident_id=incident_id,
            earliest_time="-24h",
            latest_time="now",
            row_limit=50,
        )
        evidence = _evidence_from_rows(incident_id, service, raw_rows)
        if evidence:
            return evidence

        if service:
            raw_rows = await self.query_alert_logs(
                host=None,
                service=service,
                incident_id=None,
                earliest_time="-24h",
                latest_time="now",
                row_limit=50,
            )
            return _evidence_from_rows(incident_id, service, raw_rows)

        return None
