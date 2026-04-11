"""Tests for D17: Trap defense scanner."""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from warden.scanner.trap_defense_scanner import scan_trap_defense


def test_no_defenses_all_findings():
    """Empty project = D17 score 0, all findings present."""
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "main.py").write_text("print('hello')\n")
        findings, scores, status = scan_trap_defense(Path(tmpdir))
        assert scores["D17"] == 0
        assert not status.content_injection
        assert not status.rag_poisoning
        assert not status.behavioral_traps
        assert not status.approval_integrity
        assert not status.adversarial_testing
        assert len(findings) == 8  # 4 defense + 4 testing


def test_env_var_enables_defense():
    """Setting TRAP_DEFENSE_ENABLED should detect content injection defense."""
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "main.py").write_text("print('hello')\n")
        with patch.dict(os.environ, {"TRAP_DEFENSE_ENABLED": "true"}):
            findings, scores, status = scan_trap_defense(Path(tmpdir))
            assert status.content_injection
            assert scores["D17"] >= 1


def test_code_pattern_detection():
    """Code with ContentInjectionDetector class = defense detected."""
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "defense.py").write_text("""
class ContentInjectionDetector:
    def scan(self, content):
        pass

class MemoryIntegrityGuard:
    pass

class PostExecutionVerifier:
    pass

class ApprovalIntegrityVerifier:
    def check_approval_fatigue(self):
        pass
""")
        findings, scores, status = scan_trap_defense(Path(tmpdir))
        assert status.content_injection
        assert status.rag_poisoning
        assert status.behavioral_traps
        assert status.approval_integrity
        assert scores["D17"] >= 4  # All 4 defense checks pass


def test_adversarial_testing_detection():
    """Code with red team patterns = testing detected."""
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "tests.py").write_text("""
def red_team_test():
    pass

def test_attack_template():
    pass

class Gulliver:
    pass

def test_before_after_governance():
    attack_blocked = True
""")
        findings, scores, status = scan_trap_defense(Path(tmpdir))
        assert status.adversarial_testing
        assert status.tool_attack_simulation
        assert status.chaos_engineering
        assert status.before_after_comparison
        assert scores["D17"] >= 6  # All 4 testing checks pass


def test_full_defense_max_score():
    """All 8 sub-checks satisfied = D17 score 10."""
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "defense.py").write_text("""
class ContentInjectionDetector: pass
class MemoryIntegrityGuard: pass
class PostExecutionVerifier: pass
class ApprovalIntegrityVerifier:
    def check_approval_fatigue(self): pass
""")
        (Path(tmpdir) / "tests.py").write_text("""
def red_team_test(): pass
def test_attack_template(): pass
class Gulliver: pass
def before_after_test():
    attack_blocked = True
""")
        findings, scores, status = scan_trap_defense(Path(tmpdir))
        assert scores["D17"] == 10
        # Only findings should be if some sub-checks are missing
        d17_findings = [f for f in findings if f.dimension == "D17"]
        assert len(d17_findings) == 0


def test_deepmind_citation_in_status():
    """TrapDefenseStatus always has the DeepMind citation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "main.py").write_text("x = 1\n")
        _, _, status = scan_trap_defense(Path(tmpdir))
        assert "DeepMind" in status.deepmind_citation
        assert "Franklin" in status.deepmind_citation


def test_coverage_gate_skips_pure_csharp_project():
    """No Python files in file_counts → scanner emits zero findings.

    Regression for the 2026-04-11 VigIA foot-gun: pure C#/.NET projects
    were being hit with 8 absence-based D17 findings from a Python-only
    scanner, dragging their score below PARTIAL even when the C#
    analyzer independently scored D17 well.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "Program.cs").write_text("class P {}\n")
        file_counts = {"python": 0, "js": 0, "other": 0, "csharp": 1}
        findings, scores, status = scan_trap_defense(
            Path(tmpdir), file_counts=file_counts,
        )
        assert findings == []
        assert scores == {"D17": 0}
        # Status must be clean — nothing was detected (nothing scanned)
        assert not status.content_injection


def test_coverage_gate_allows_python_project():
    """file_counts with python > 0 → scanner runs normally."""
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "main.py").write_text("print('hello')\n")
        file_counts = {"python": 1, "js": 0, "other": 0, "csharp": 0}
        findings, scores, _ = scan_trap_defense(
            Path(tmpdir), file_counts=file_counts,
        )
        # Same as the ungated "no defenses all findings" case
        assert len(findings) == 8
        assert scores["D17"] == 0


def test_missing_file_counts_back_compat():
    """Calling without file_counts must keep the pre-v1.7.0 behavior."""
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "main.py").write_text("print('hello')\n")
        findings, scores, _ = scan_trap_defense(Path(tmpdir))
        assert len(findings) == 8
        assert scores["D17"] == 0
