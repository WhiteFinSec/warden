"""Layer 8: CI/CD Governance — GitHub Actions, branch protection, CODEOWNERS."""

from __future__ import annotations

import os
import re
from pathlib import Path

from warden.models import ComplianceMapping, Finding, Severity
from warden.scanner._common import SKIP_DIRS

# --- Patterns ---

_SECRETS_WITHOUT_OIDC = re.compile(r"\$\{\{\s*secrets\.\w+\s*\}\}", re.IGNORECASE)
_ID_TOKEN_WRITE = re.compile(r"id-token\s*:\s*write", re.IGNORECASE)
_CONTINUE_ON_ERROR = re.compile(r"continue-on-error\s*:\s*true", re.IGNORECASE)
_ENVIRONMENT_BLOCK = re.compile(r"^\s+environment\s*:", re.MULTILINE)
_CONCURRENCY_BLOCK = re.compile(r"^concurrency\s*:", re.MULTILINE)
_PULL_REQUEST_TRIGGER = re.compile(r"^\s*-?\s*pull_request", re.MULTILINE)
_BRANCH_PROTECTION = re.compile(r"""if:\s*github\.ref\s*==\s*['"]refs/heads/main['"]""")



def scan_cicd(target: Path) -> tuple[list[Finding], dict[str, int]]:
    """Layer 8: Scan CI/CD configuration for governance patterns.

    Returns (findings, raw_dimension_scores).
    """
    findings: list[Finding] = []

    workflow_files = _find_workflow_files(target)
    for wf in workflow_files:
        findings.extend(_analyze_workflow(wf))

    has_codeowners = _has_codeowners(target)
    if not has_codeowners and workflow_files:
        findings.append(Finding(
            layer=8, scanner="cicd_scanner",
            file=str(target / ".github" / "CODEOWNERS"), line=0,
            severity=Severity.MEDIUM, dimension="D3",
            message="No .github/CODEOWNERS file — no code ownership enforcement",
            remediation="Add CODEOWNERS to enforce review requirements per path",
            compliance=ComplianceMapping(eu_ai_act="Article 9"),
        ))

    scores = _calculate_scores(findings, workflow_files, has_codeowners)
    return findings, scores


def _find_workflow_files(target: Path) -> list[Path]:
    """Find GitHub Actions workflow YAML files using os.walk."""
    results: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        # Only look inside .github/workflows directories
        rel = Path(dirpath).relative_to(target)
        if rel.parts[:2] != (".github", "workflows"):
            continue
        for fname in filenames:
            if fname.endswith((".yml", ".yaml")):
                results.append(Path(dirpath) / fname)
    return results


def _has_codeowners(target: Path) -> bool:
    """Check for CODEOWNERS in standard locations."""
    candidates = [
        target / ".github" / "CODEOWNERS",
        target / "CODEOWNERS",
        target / "docs" / "CODEOWNERS",
    ]
    return any(c.is_file() for c in candidates)


def _analyze_workflow(filepath: Path) -> list[Finding]:
    """Analyze a single GitHub Actions workflow file."""
    findings: list[Finding] = []
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return findings

    lines = content.splitlines()

    # Check: secrets used without OIDC (id-token: write)
    has_oidc = bool(_ID_TOKEN_WRITE.search(content))
    for i, line in enumerate(lines, 1):
        if _SECRETS_WITHOUT_OIDC.search(line) and not has_oidc:
            findings.append(Finding(
                layer=8, scanner="cicd_scanner",
                file=str(filepath), line=i,
                severity=Severity.HIGH, dimension="D4",
                message="Secret used without OIDC — long-lived credential in workflow",
                remediation="Use OIDC (id-token: write) for cloud auth instead of static secrets",
                compliance=ComplianceMapping(owasp_llm="LLM09"),
            ))
            break  # One finding per file is sufficient

    # Check: continue-on-error: true (suppresses failures)
    for i, line in enumerate(lines, 1):
        if _CONTINUE_ON_ERROR.search(line):
            findings.append(Finding(
                layer=8, scanner="cicd_scanner",
                file=str(filepath), line=i,
                severity=Severity.MEDIUM, dimension="D3",
                message="continue-on-error: true — pipeline failures silently suppressed",
                remediation="Remove continue-on-error or scope it to non-critical steps only",
            ))

    # Check: no concurrency block (parallel deploys possible)
    if not _CONCURRENCY_BLOCK.search(content):
        findings.append(Finding(
            layer=8, scanner="cicd_scanner",
            file=str(filepath), line=1,
            severity=Severity.MEDIUM, dimension="D3",
            message="No concurrency block — parallel deployments possible",
            remediation="Add concurrency: group with cancel-in-progress to prevent parallel deploys",
        ))

    # Check: no environment block with reviewers
    if not _ENVIRONMENT_BLOCK.search(content):
        findings.append(Finding(
            layer=8, scanner="cicd_scanner",
            file=str(filepath), line=1,
            severity=Severity.LOW, dimension="D14",
            message="No environment: block — no required reviewers for deployments",
            remediation="Add environment: production with required reviewers in GitHub settings",
            compliance=ComplianceMapping(eu_ai_act="Article 14"),
        ))

    # Check: no branch protection guard
    if not _BRANCH_PROTECTION.search(content) and "push:" in content:
        findings.append(Finding(
            layer=8, scanner="cicd_scanner",
            file=str(filepath), line=1,
            severity=Severity.MEDIUM, dimension="D14",
            message="Push trigger without branch protection guard",
            remediation="Add if: github.ref == 'refs/heads/main' or restrict push trigger branches",
        ))

    return findings


def _calculate_scores(
    findings: list[Finding],
    workflow_files: list[Path],
    has_codeowners: bool,
) -> dict[str, int]:
    """Score dimensions D3 and D14 based on CI/CD governance signals."""
    scores: dict[str, int] = {}

    if not workflow_files:
        return scores

    d3_deductions = sum(1 for f in findings if f.dimension == "D3")

    # D3: Policy Coverage — max contribution 4
    d3 = 4
    d3 -= min(d3_deductions, 3)
    if has_codeowners:
        d3 = min(d3 + 1, 4)
    scores["D3"] = max(0, d3)

    # D14: Compliance Maturity — earn points for governance signals,
    # not "has CI minus deductions". Having workflows is baseline, not compliance.
    d14 = 0
    all_content = ""
    for wf in workflow_files:
        try:
            all_content += wf.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            pass
    # +1 for environment blocks (required reviewers for deploys)
    if _ENVIRONMENT_BLOCK.search(all_content):
        d14 += 1
    # +1 for branch protection guards
    if _BRANCH_PROTECTION.search(all_content):
        d14 += 1
    # +1 for OIDC (no static secrets)
    if _ID_TOKEN_WRITE.search(all_content):
        d14 += 1
    scores["D14"] = min(d14, 3)

    return scores
