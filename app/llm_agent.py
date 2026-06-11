import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from app.config import ROOT_DIR
from app.decision_engine import decide_investigation
from app.models import Evidence, Incident, InvestigationResult


class CodexRcaAgent:
    def __init__(
        self,
        executable: str = "codex",
        model: str | None = None,
        timeout_seconds: int = 180,
        workdir: Path | None = None,
    ) -> None:
        self.executable = executable
        self.model = model or os.getenv("CODEX_RCA_MODEL") or None
        self.timeout_seconds = timeout_seconds
        self.workdir = workdir or ROOT_DIR

    def available(self) -> bool:
        return shutil.which(self.executable) is not None

    def _build_prompt(
        self,
        alert_name: str,
        incident: Incident,
        evidence: Evidence,
        raw_events: list[dict[str, Any]],
    ) -> str:
        context = {
            "alert_name": alert_name,
            "incident": incident.model_dump(mode="json"),
            "evidence": evidence.model_dump(mode="json"),
            "raw_events": raw_events[:10],
        }
        return (
            "You are an expert SRE triage agent.\n"
            "Analyze the provided alert and telemetry context.\n"
            "Return valid JSON only with these keys:\n"
            "root_cause, severity, confidence_score, evidence_summary, ai_summary,\n"
            "recommended_actions, safe_remediation_actions.\n"
            "Use concise, operationally useful language. Do not add prose outside JSON.\n\n"
            f"Context JSON:\n{json.dumps(context, indent=2, ensure_ascii=True)}"
        )

    @staticmethod
    def _extract_json(text: str) -> dict[str, Any]:
        cleaned = text.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`")
            if cleaned.startswith("json"):
                cleaned = cleaned[4:].strip()
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            start = cleaned.find("{")
            end = cleaned.rfind("}")
            if start >= 0 and end > start:
                return json.loads(cleaned[start : end + 1])
            raise

    @staticmethod
    def _normalize_severity(value: Any) -> str:
        severity = str(value or "MEDIUM").upper()
        if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            return "MEDIUM"
        return severity

    def analyze(
        self,
        *,
        alert_name: str,
        incident: Incident,
        evidence: Evidence,
        raw_events: list[dict[str, Any]],
    ) -> InvestigationResult:
        if not self.available():
            fallback = decide_investigation(evidence, source="rules_fallback")
            fallback.ai_summary = fallback.ai_summary or f"RCA fallback for {incident.service}: {fallback.root_cause}."
            return fallback

        prompt = self._build_prompt(alert_name, incident, evidence, raw_events)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, suffix=".txt") as output_file:
            output_path = Path(output_file.name)

        cmd = [self.executable, "exec", "--ephemeral", "--sandbox", "read-only", "--output-last-message", str(output_path)]
        if self.model:
            cmd.extend(["--model", self.model])
        if os.getenv("CODEX_IGNORE_USER_CONFIG", "").lower() in {"1", "true", "yes"}:
            cmd.append("--ignore-user-config")
        cmd.append(prompt)

        try:
            completed = subprocess.run(
                cmd,
                cwd=str(self.workdir),
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
            if completed.returncode != 0:
                raise RuntimeError((completed.stderr or completed.stdout or "codex exited with an error").strip())
            raw_response = output_path.read_text(encoding="utf-8").strip()
            parsed = self._extract_json(raw_response)
            evidence_summary = str(parsed.get("evidence_summary", "")).strip()
            ai_summary = str(parsed.get("ai_summary", "")).strip()
            result = InvestigationResult(
                incident_id=incident.incident_id,
                service=incident.service,
                severity=self._normalize_severity(parsed.get("severity")),
                root_cause=str(parsed.get("root_cause", "correlated service anomaly")),
                confidence_score=max(0.0, min(float(parsed.get("confidence_score", 0.5)), 0.95)),
                evidence_summary=evidence_summary or "LLM analysis did not include an evidence summary.",
                ai_summary=ai_summary or None,
                recommended_actions=[str(item) for item in parsed.get("recommended_actions", []) if item not in {None, ""}],
                safe_remediation_actions=[
                    str(item) for item in parsed.get("safe_remediation_actions", []) if item not in {None, ""}
                ],
                source="codex",
                raw_response=raw_response,
            )
            if not result.ai_summary:
                result.ai_summary = (
                    f"RCA for {result.service}: root cause appears to be {result.root_cause}. "
                    f"Confidence {result.confidence_score:.2f}. {result.evidence_summary}"
                ).strip()
            return result
        except Exception:
            fallback = decide_investigation(evidence, source="rules_fallback")
            fallback.ai_summary = fallback.ai_summary or f"RCA fallback for {incident.service}: {fallback.root_cause}."
            return fallback
        finally:
            try:
                output_path.unlink(missing_ok=True)
            except OSError:
                pass
