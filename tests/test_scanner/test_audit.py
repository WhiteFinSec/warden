"""Tests for Layer 7: Audit & compliance scanner."""

import tempfile
from pathlib import Path

from warden.scanner.audit_scanner import scan_audit


def test_no_audit_logging():
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "main.py").write_text("print('hello')\n")
        findings, _ = scan_audit(Path(tmpdir))
        assert any("audit logging" in f.message.lower() for f in findings)


def test_has_audit_logging():
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "main.py").write_text("""
import logging
logger = logging.getLogger(__name__)

class AuditLog:
    def record(self, event):
        logger.info(f"AUDIT: {event}")
""")
        findings, scores = scan_audit(Path(tmpdir))
        assert not any("No audit logging" in f.message for f in findings)
        assert scores.get("D5", 0) > 0


def test_no_compliance_reference():
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "main.py").write_text("x = 1\n")
        findings, _ = scan_audit(Path(tmpdir))
        assert any("compliance framework" in f.message.lower() for f in findings)


def test_has_compliance_reference():
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "main.py").write_text("""
# SOC2 Type II compliance mapping
# GDPR Article 17 - Right to erasure
import logging
logger = logging.getLogger(__name__)

class AuditTrail:
    pass

LOG_RETENTION_DAYS = 90
""")
        findings, scores = scan_audit(Path(tmpdir))
        assert not any("No compliance framework" in f.message for f in findings)
        assert scores.get("D14", 0) > 0


def test_no_structured_logging():
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "main.py").write_text("print('debug info')\n")
        findings, _ = scan_audit(Path(tmpdir))
        assert any("structured logging" in f.message.lower() for f in findings)


def test_coverage_gate_skips_pure_csharp_project():
    """No Python files in file_counts → scanner emits zero findings.

    Regression for the 2026-04-11 VigIA foot-gun: pure C#/.NET projects
    were being hit with absence-based audit findings from a Python-only
    scanner, dragging their score below PARTIAL even when the C#
    analyzer independently scored D5/D14 well.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "Program.cs").write_text("class P {}\n")
        file_counts = {"python": 0, "js": 0, "other": 0, "csharp": 1}
        findings, scores = scan_audit(
            Path(tmpdir), file_counts=file_counts,
        )
        assert findings == []
        assert scores == {}


def test_coverage_gate_allows_python_project():
    """file_counts with python > 0 → scanner runs normally."""
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "main.py").write_text("print('hello')\n")
        file_counts = {"python": 1, "js": 0, "other": 0, "csharp": 0}
        findings, _ = scan_audit(
            Path(tmpdir), file_counts=file_counts,
        )
        # Same as the ungated "no audit logging" case
        assert any("audit logging" in f.message.lower() for f in findings)


def test_missing_file_counts_back_compat():
    """Calling without file_counts must keep the pre-v1.7.0 behavior."""
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "main.py").write_text("print('hello')\n")
        findings, _ = scan_audit(Path(tmpdir))
        assert any("audit logging" in f.message.lower() for f in findings)
