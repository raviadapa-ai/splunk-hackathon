from pathlib import Path


def test_correlation_search_uses_cpu_and_memory_pressure() -> None:
    correlation_spl = Path("splunk/correlation_search.spl").read_text(encoding="utf-8")
    alert_candidate_spl = Path("splunk/alert_candidate.spl").read_text(encoding="utf-8")
    dashboard_xml = Path("splunk/dashboard_simple.xml").read_text(encoding="utf-8")
    main_py = Path("app/main.py").read_text(encoding="utf-8")

    for spl in (correlation_spl, alert_candidate_spl):
        assert "cpu_pct" in spl
        assert "memory_pct" in spl
        assert "baseline_cpu_avg" in spl
        assert "baseline_memory_avg" in spl
        assert "cpu_pressure" in spl
        assert "memory_pressure" in spl
        assert "resource_pressure_score" in spl

    assert "coalesce(mvjoin(signals, \", \"), error_type, \"unknown\")" in dashboard_xml
    assert "latest(evidence_summary) as evidence_summary" in dashboard_xml
    assert "mcp_evidence_summary=coalesce(mcp_evidence_summary,evidence_summary,ai_summary,\"\")" in dashboard_xml
    assert "target=\"_blank\"" in main_py
    assert "window.open(this.href" in main_py
    assert '"ai_summary": incident.ai_summary' in main_py
