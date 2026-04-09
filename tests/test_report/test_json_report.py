"""Tests for JSON report generation."""

import json
import tempfile
from pathlib import Path

from warden.models import ComplianceMapping, Finding, ScanResult, Severity
from warden.report.json_writer import write_json_report
from warden.scoring.engine import apply_scores


def _make_result() -> ScanResult:
    result = ScanResult(target_path="/test/project")
    result.findings = [
        Finding(
            layer=1, scanner="code_analyzer", file="agent.py", line=42,
            severity=Severity.CRITICAL, dimension="D1",
            message="Test finding", remediation="Fix it",
            compliance=ComplianceMapping(eu_ai_act="Article 15", owasp_llm="LLM01"),
        ),
    ]
    apply_scores(result, {"D1": 10, "D2": 5})
    return result


def test_json_has_scoring_version():
    result = _make_result()
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "report.json"
        write_json_report(result, path)
        data = json.loads(path.read_text())
        assert "scoring_version" in data
        assert data["scoring_version"] == "4.3"


def test_json_has_all_dimensions():
    result = _make_result()
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "report.json"
        write_json_report(result, path)
        data = json.loads(path.read_text())
        dims = data["score"]["dimensions"]
        assert len(dims) == 17


def test_json_has_findings():
    result = _make_result()
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "report.json"
        write_json_report(result, path)
        data = json.loads(path.read_text())
        assert len(data["findings"]) == 1
        assert data["findings"][0]["severity"] == "CRITICAL"


def test_json_has_trap_defense():
    result = _make_result()
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "report.json"
        write_json_report(result, path)
        data = json.loads(path.read_text())
        assert "trap_defense" in data
        assert "deepmind_citation" in data["trap_defense"]


def test_json_has_compliance_in_findings():
    result = _make_result()
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "report.json"
        write_json_report(result, path)
        data = json.loads(path.read_text())
        compliance = data["findings"][0]["compliance"]
        assert compliance["eu_ai_act"] == "Article 15"
        assert compliance["owasp_llm"] == "LLM01"


def test_json_raw_max_is_235():
    result = _make_result()
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "report.json"
        write_json_report(result, path)
        data = json.loads(path.read_text())
        assert data["score"]["raw_max"] == 235
