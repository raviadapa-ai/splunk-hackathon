import os
import re
import time
import tomllib
from pathlib import Path
from typing import Any

import httpx

from app.config import DEFAULT_INDEX
from app.models import Evidence
from app.storage import write_mcp_metric_event

SPLUNK_MCP_URL = os.getenv("SPLUNK_MCP_URL", "https://127.0.0.1:8089/services/mcp")
SPLUNK_MCP_AUTH_HEADER = os.getenv("SPLUNK_MCP_AUTH_HEADER", "")


def _env_flag(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _normalize_auth_header(auth_header: str) -> str:
    value = auth_header.strip()
    if not value:
        return ""
    token = (
        value.removeprefix("Bearer").strip() if value.startswith("Bearer") else value
    )
    jwt_start = token.find("eyJ")
    if jwt_start > 0:
        token = token[jwt_start:]
    return f"Bearer {token}"


def _codex_config_auth_header() -> str:
    codex_home = Path(os.getenv("CODEX_HOME") or os.path.expanduser("~/.codex"))
    config_path = codex_home / "config.toml"
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


def _metric_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def extract_result_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    result = payload.get("result", {})
    rows = result.get("structuredContent", {}).get("results", [])
    if not rows:
        rows = payload.get("results") or []
    if not isinstance(rows, list):
        rows = [rows]
    return [row for row in rows if isinstance(row, dict)]


def _evidence_from_rows(
    incident_id: str, service: str | None, rows: list[dict[str, Any]]
) -> Evidence | None:
    if not rows:
        return None

    first_row = rows[0]
    evidence = {
        "service": first_row.get("service", service or ""),
        "incident_id": first_row.get("incident_id", incident_id),
        "event_count": len(rows),
        "error_types": [
            str(row.get("error_type"))
            for row in rows
            if row.get("error_type") not in {None, "", "null"}
        ],
        "hosts": [str(row.get("host")) for row in rows if row.get("host")],
        "endpoints": [str(row.get("endpoint")) for row in rows if row.get("endpoint")],
        "dependencies": [
            str(row.get("dependency")) for row in rows if row.get("dependency")
        ],
        "regions": [
            str(row.get("user_region")) for row in rows if row.get("user_region")
        ],
        "avg_latency_ms": sum(_coerce_number(row.get("latency_ms")) for row in rows)
        / len(rows),
        "max_latency_ms": max(_coerce_number(row.get("latency_ms")) for row in rows),
        "max_cpu_pct": max(_coerce_number(row.get("cpu_pct")) for row in rows),
        "max_memory_pct": max(_coerce_number(row.get("memory_pct")) for row in rows),
        "max_db_pool_pct": max(
            _coerce_number(row.get("db_connection_pool_pct")) for row in rows
        ),
        "deployment_versions": [
            str(row.get("deployment_version"))
            for row in rows
            if row.get("deployment_version")
        ],
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
    def __init__(
        self,
        url: str = SPLUNK_MCP_URL,
        auth_header: str = SPLUNK_MCP_AUTH_HEADER,
        verify_tls: bool | None = None,
        timeout: float = 8,
    ) -> None:
        self.url = url
        self.timeout = timeout
        self.verify_tls = (
            _env_flag("SPLUNK_MCP_VERIFY_TLS", default=True)
            if verify_tls is None
            else verify_tls
        )
        resolved_auth = (
            auth_header
            or os.getenv("SPLUNK_MCP_BEARER_TOKEN", "")
            or _codex_config_auth_header()
        )
        normalized_auth = _normalize_auth_header(resolved_auth)
        self.headers = {"Authorization": normalized_auth} if normalized_auth else {}

    def _tool_payload(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }

    async def call_tool(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, verify=self.verify_tls
            ) as client:
                response = await client.post(
                    self.url,
                    json=self._tool_payload(tool_name, arguments),
                    headers=self.headers,
                )
                response.raise_for_status()
                payload = response.json()
                if "error" in payload:
                    raise ValueError(payload["error"])
                elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
                write_mcp_metric_event(
                    {
                        "timestamp": _metric_timestamp(),
                        "mcp_query_count": 1,
                        "mcp_success_count": 1,
                        "mcp_failure_count": 0,
                        "mcp_tool_usage": tool_name,
                        "tool_name": tool_name,
                        "duration_ms": elapsed_ms,
                        "average_investigation_time": elapsed_ms,
                        "status": "success",
                        "sourcetype": "aiops-mcp-metrics",
                    }
                )
                return payload
        except Exception as exc:
            elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
            write_mcp_metric_event(
                {
                    "timestamp": _metric_timestamp(),
                    "mcp_query_count": 1,
                    "mcp_success_count": 0,
                    "mcp_failure_count": 1,
                    "mcp_tool_usage": tool_name,
                    "tool_name": tool_name,
                    "duration_ms": elapsed_ms,
                    "average_investigation_time": elapsed_ms,
                    "status": "failure",
                    "error": str(exc)[:500],
                    "sourcetype": "aiops-mcp-metrics",
                }
            )
            raise

    async def get_info(self) -> dict[str, Any]:
        return await self.call_tool("splunk_get_info", {})

    async def get_indexes(self, row_limit: int = 1000) -> dict[str, Any]:
        return await self.call_tool("splunk_get_indexes", {"row_limit": row_limit})

    async def get_metadata(
        self,
        metadata_type: str,
        index: str = DEFAULT_INDEX,
        earliest_time: str = "-24h",
        latest_time: str = "now",
        row_limit: int = 1000,
    ) -> dict[str, Any]:
        return await self.call_tool(
            "splunk_get_metadata",
            {
                "type": metadata_type,
                "index": index,
                "earliest_time": earliest_time,
                "latest_time": latest_time,
                "row_limit": row_limit,
            },
        )

    async def saia_generate_spl(self, prompt: str) -> dict[str, Any]:
        raise RuntimeError("Splunk AI Assistant is disabled: feature_not_activated")

    async def saia_optimize_spl(self, spl: str) -> dict[str, Any]:
        raise RuntimeError("Splunk AI Assistant is disabled: feature_not_activated")

    async def saia_explain_spl(self, spl: str) -> dict[str, Any]:
        raise RuntimeError("Splunk AI Assistant is disabled: feature_not_activated")

    async def saia_ask_splunk_question(self, prompt: str) -> dict[str, Any]:
        raise RuntimeError("Splunk AI Assistant is disabled: feature_not_activated")

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
        query = (
            " ".join(clauses)
            + " | spath input=_raw path=host output=event_host"
            + " | spath input=_raw path=endpoint output=event_endpoint"
            + " | spath input=_raw path=dependency output=event_dependency"
            + " | spath input=_raw path=service output=event_service"
            + " | spath input=_raw path=error_type output=event_error_type"
            + " | spath input=_raw path=user_region output=event_user_region"
            + " | spath input=_raw path=deployment_version output=event_deployment_version"
            + " | spath input=_raw path=latency_ms output=event_latency_ms"
            + " | spath input=_raw path=cpu_pct output=event_cpu_pct"
            + " | spath input=_raw path=memory_pct output=event_memory_pct"
            + " | spath input=_raw path=db_connection_pool_pct output=event_db_pool_pct"
            + " | eval host=coalesce(event_host, host), endpoint=coalesce(event_endpoint, endpoint),"
            + " dependency=coalesce(event_dependency, dependency), service=coalesce(event_service, service)"
            + " | eval error_type=coalesce(event_error_type, error_type),"
            + " user_region=coalesce(event_user_region, user_region),"
            + " deployment_version=coalesce(event_deployment_version, deployment_version)"
            + " | eval latency_ms=tonumber(coalesce(event_latency_ms, latency_ms)),"
            + " cpu_pct=tonumber(coalesce(event_cpu_pct, cpu_pct)),"
            + " memory_pct=tonumber(coalesce(event_memory_pct, memory_pct)),"
            + " db_connection_pool_pct=tonumber(coalesce(event_db_pool_pct, db_connection_pool_pct))"
            + " | sort - _time | head "
            + str(row_limit)
        )
        payload = await self.run_query(
            query,
            earliest_time=earliest_time,
            latest_time=latest_time,
            row_limit=row_limit,
        )
        return extract_result_rows(payload)

    async def query_incident_evidence(
        self, incident_id: str, service: str | None = None
    ) -> Evidence | None:
        evidence_window = os.getenv("SPLUNK_MCP_EVIDENCE_WINDOW", "-2h")
        service_clause = f' service="{service}"' if service else ""
        queries = [
            (
                f'index={DEFAULT_INDEX} sourcetype="agentic-ops" incident_id="{incident_id}"{service_clause} '
                "| spath input=_raw path=host output=event_host "
                "| spath input=_raw path=service output=event_service "
                "| spath input=_raw path=endpoint output=event_endpoint "
                "| spath input=_raw path=dependency output=event_dependency "
                "| spath input=_raw path=error_type output=event_error_type "
                "| spath input=_raw path=user_region output=event_region "
                "| spath input=_raw path=deployment_version output=event_deployment_version "
                "| spath input=_raw path=latency_ms output=event_latency_ms "
                "| spath input=_raw path=cpu_pct output=event_cpu_pct "
                "| spath input=_raw path=memory_pct output=event_memory_pct "
                "| spath input=_raw path=db_connection_pool_pct output=event_db_pool_pct "
                "| eval evidence_service=coalesce(event_service, service), "
                "evidence_host=coalesce(event_host, host), "
                "evidence_endpoint=coalesce(event_endpoint, endpoint), "
                "evidence_dependency=coalesce(event_dependency, dependency), "
                "evidence_error_type=coalesce(event_error_type, error_type), "
                "evidence_region=coalesce(event_region, user_region), "
                "evidence_deployment_version=coalesce(event_deployment_version, deployment_version), "
                "evidence_latency_ms=tonumber(coalesce(event_latency_ms, latency_ms)), "
                "evidence_cpu_pct=tonumber(coalesce(event_cpu_pct, cpu_pct)), "
                "evidence_memory_pct=tonumber(coalesce(event_memory_pct, memory_pct)), "
                "evidence_db_pool_pct=tonumber(coalesce(event_db_pool_pct, db_connection_pool_pct)) "
                "| stats count as event_count values(evidence_error_type) as error_types values(evidence_host) as hosts "
                "values(evidence_endpoint) as endpoints values(evidence_dependency) as dependencies values(evidence_region) as regions "
                "avg(evidence_latency_ms) as avg_latency_ms max(evidence_latency_ms) as max_latency_ms max(evidence_cpu_pct) as max_cpu_pct "
                "max(evidence_memory_pct) as max_memory_pct max(evidence_db_pool_pct) as max_db_pool_pct "
                "values(evidence_deployment_version) as deployment_versions by evidence_service incident_id "
                "| rename evidence_service as service"
            ),
        ]

        for spl in queries:
            try:
                payload = await self.call_tool(
                    "splunk_run_query",
                    {
                        "query": spl,
                        "earliest_time": evidence_window,
                        "latest_time": "now",
                        "row_limit": 1,
                    },
                )
            except (httpx.HTTPError, ValueError):
                continue

            rows = extract_result_rows(payload)
            if not rows:
                continue
            row = rows[0]
            if isinstance(row, dict) and "text" not in row:
                evidence_payload = {
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
                return Evidence.model_validate(evidence_payload)

        raw_rows = await self.query_alert_logs(
            host=None,
            service=service,
            incident_id=incident_id,
            earliest_time=evidence_window,
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
                earliest_time=evidence_window,
                latest_time="now",
                row_limit=50,
            )
            return _evidence_from_rows(incident_id, service, raw_rows)

        return None
