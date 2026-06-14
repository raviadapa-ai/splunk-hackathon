import asyncio

from app.splunk_mcp_client import SplunkMCPClient


def test_incident_evidence_queries_only_agentic_ops(monkeypatch) -> None:
    calls: list[str] = []

    async def fake_call_tool(self, tool_name, arguments):
        calls.append(arguments["query"])
        return {"result": {"content": []}}

    async def fake_query_alert_logs(self, **kwargs):
        return []

    monkeypatch.setattr(SplunkMCPClient, "call_tool", fake_call_tool)
    monkeypatch.setattr(SplunkMCPClient, "query_alert_logs", fake_query_alert_logs)

    client = SplunkMCPClient()
    result = asyncio.run(client.query_incident_evidence("inc-test", "auth-api"))

    assert result is None
    assert len(calls) == 1
    query = calls[0]
    assert 'sourcetype="agentic-ops"' in query
    assert "values(sourcetype) as error_types" not in query
    assert "spath input=_raw path=host output=event_host" in query
    assert "values(evidence_host) as hosts" in query
