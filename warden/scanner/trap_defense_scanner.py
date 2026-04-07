"""D17: Trap defense detection based on Google DeepMind 'AI Agent Traps' paper.

8 sub-checks: 4 defense (runtime protection) + 4 testing (proactive chaos).
Total: 10 points.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from warden.models import ComplianceMapping, Finding, Severity, TrapDefenseStatus
from warden.scanner._common import SKIP_DIRS

# --- Sub-check definitions ---

DEFENSE_CHECKS = [
    {
        "id": "content_injection",
        "name": "Content Injection Defense",
        "points": 1,
        "env_vars": ["TRAP_DEFENSE_ENABLED", "CONTENT_INJECTION_DEFENSE"],
        "code_patterns": [
            r"ContentInjectionDetector",
            r"content.*injection.*scan",
            r"html.*sanitiz",
            r"zero.?width.*detect",
            r"hidden.*instruction.*detect",
        ],
        "severity": Severity.CRITICAL,
        "message": "No content injection defense — hidden HTML/CSS/zero-width instructions pass to agents undetected",
        "deepmind_stat": "86% attack success rate",
        "compliance": ComplianceMapping(
            eu_ai_act="Article 15",
            owasp_llm="LLM01",
            mitre_atlas="AML.T0051",
        ),
    },
    {
        "id": "rag_poisoning",
        "name": "RAG/Memory Poisoning Protection",
        "points": 1,
        "env_vars": ["RAG_POISONING_SCAN", "RAG_DEFENSE_ENABLED"],
        "code_patterns": [
            r"MemoryIntegrityGuard",
            r"rag.*poison",
            r"knowledge.*base.*scan",
            r"document.*sanitiz",
            r"memory.*integrity",
        ],
        "severity": Severity.CRITICAL,
        "message": "No RAG poisoning protection — knowledge base documents not scanned for embedded instructions",
        "deepmind_stat": "<0.1% contamination = >80% attack success",
        "compliance": ComplianceMapping(
            eu_ai_act="Article 15",
            owasp_llm="LLM01",
            mitre_atlas="AML.T0049",
        ),
    },
    {
        "id": "behavioral_traps",
        "name": "Behavioral Trap Detection",
        "points": 1,
        "env_vars": ["BEHAVIORAL_TRAP_DEFENSE", "BEHAVIOR_MONITOR_ENABLED"],
        "code_patterns": [
            r"PostExecutionVerifier",
            r"behavior.*trap",
            r"behavioral.*monitor",
            r"action.*drift.*detect",
            r"post.*execution.*verif",
        ],
        "severity": Severity.HIGH,
        "message": "No behavioral trap detection — post-execution behavioral changes not monitored",
        "deepmind_stat": "10/10 M365 Copilot attacks succeeded",
        "compliance": ComplianceMapping(
            eu_ai_act="Article 14",
            owasp_llm="LLM07",
            mitre_atlas="AML.T0051",
        ),
    },
    {
        "id": "approval_integrity",
        "name": "Approval Integrity Verification",
        "points": 1,
        "env_vars": ["APPROVAL_INTEGRITY_CHECK"],
        "code_patterns": [
            r"ApprovalIntegrityVerifier",
            r"approval.*fatigue",
            r"approval.*integrity",
            r"action.*summary.*verify",
            r"approve.*cross.?check",
        ],
        "severity": Severity.HIGH,
        "message": (
            "No approval integrity verification -- agent summaries for approval "
            "not cross-checked against actual actions"
        ),
        "deepmind_stat": "Approval fatigue exploitation",
        "compliance": ComplianceMapping(
            eu_ai_act="Article 14",
            owasp_llm="LLM07",
            mitre_atlas="AML.T0048",
        ),
    },
]

TESTING_CHECKS = [
    {
        "id": "adversarial_testing",
        "name": "Prompt-Level Attack Testing (OWASP)",
        "points": 2,
        "code_patterns": [
            r"red.?team",
            r"adversarial.*test",
            r"prompt.*inject.*test",
            r"jailbreak.*test",
        ],
        "severity": Severity.MEDIUM,
        "message": "No adversarial testing evidence — no red team, no prompt injection tests",
    },
    {
        "id": "tool_attack_simulation",
        "name": "Tool-Call Attack Simulation",
        "points": 2,
        "code_patterns": [
            r"attack.*template",
            r"malicious.*tool",
            r"tool.*attack.*sim",
            r"adversarial.*tool",
        ],
        "severity": Severity.MEDIUM,
        "message": "No tool-call attack simulation — agent tool calls not tested against adversarial inputs",
    },
    {
        "id": "chaos_engineering",
        "name": "Multi-Agent Chaos Engineering",
        "points": 1,
        "code_patterns": [
            r"[Gg]ulliver",
            r"chaos.*engineer",
            r"swarm.*test",
            r"multi.*agent.*stress",
        ],
        "severity": Severity.MEDIUM,
        "message": "No multi-agent chaos engineering — agent swarms not stress tested",
    },
    {
        "id": "before_after_comparison",
        "name": "Before/After Governance Comparison",
        "points": 1,
        "code_patterns": [
            r"before.*after",
            r"attack.*blocked",
            r"governance.*comparison",
            r"a.?b.*test.*governance",
        ],
        "severity": Severity.MEDIUM,
        "message": "No before/after governance comparison — no A/B testing of governance effectiveness",
        "deepmind_stat": '"comprehensive evaluation suites needed" — DeepMind',
    },
]


def scan_trap_defense(target: Path) -> tuple[list[Finding], dict[str, int], TrapDefenseStatus]:
    """D17: Scan for trap defense and adversarial testing capabilities.

    Returns (findings, raw_dimension_scores, trap_defense_status).
    """
    findings: list[Finding] = []
    status = TrapDefenseStatus()
    d17_score = 0

    # Collect all Python source for pattern matching
    all_source = _collect_source(target)

    # Run defense checks (4 pts)
    for check in DEFENSE_CHECKS:
        detected = _check_defense(check, all_source)
        setattr(status, check["id"], detected)
        if detected:
            d17_score += check["points"]
        else:
            findings.append(Finding(
                layer=8, scanner="trap_defense_scanner",
                file=str(target), line=0,
                severity=check["severity"], dimension="D17",
                message=f"{check['message']}. ({check.get('deepmind_stat', '')})",
                remediation="Deploy trap defense layer on tool results",
                compliance=check.get("compliance", ComplianceMapping()),
            ))

    # Run testing checks (6 pts)
    for check in TESTING_CHECKS:
        detected = _check_testing(check, all_source)
        setattr(status, check["id"], detected)
        if detected:
            d17_score += check["points"]
        else:
            findings.append(Finding(
                layer=8, scanner="trap_defense_scanner",
                file=str(target), line=0,
                severity=check["severity"], dimension="D17",
                message=check["message"],
                remediation="Implement adversarial testing for agent systems",
            ))

    scores = {"D17": min(d17_score, 10)}
    return findings, scores, status


def _check_defense(check: dict, all_source: str) -> bool:
    """Check if a defense sub-check is satisfied via env vars or code patterns."""
    # Check environment variables
    for env_var in check.get("env_vars", []):
        val = os.environ.get(env_var, "")
        if val.lower() in ("true", "1", "enabled", "yes"):
            return True

    # Check code patterns
    for pattern in check.get("code_patterns", []):
        if re.search(pattern, all_source, re.IGNORECASE):
            return True

    return False


def _check_testing(check: dict, all_source: str) -> bool:
    """Check if a testing sub-check is satisfied via code patterns."""
    for pattern in check.get("code_patterns", []):
        if re.search(pattern, all_source, re.IGNORECASE):
            return True
    return False


def _collect_source(target: Path) -> str:
    """Collect all Python source code from the target."""
    import os

    sources: list[str] = []
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            if fname.endswith(".py"):
                try:
                    sources.append(
                        (Path(dirpath) / fname).read_text(
                            encoding="utf-8", errors="ignore"
                        )
                    )
                except OSError:
                    continue
    return "\n".join(sources)


def _should_skip(filepath: Path) -> bool:
    parts = filepath.parts
    return bool(SKIP_DIRS.intersection(parts))
