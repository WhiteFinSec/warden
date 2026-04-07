"""Layer 7: Audit & compliance analysis."""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

from warden.models import ComplianceMapping, Finding, Severity

COMPLIANCE_KEYWORDS = {
    "gdpr", "soc2", "soc 2", "iso27001", "iso 27001",
    "eu ai act", "eu_ai_act", "hipaa", "pci",
    "nist", "fedramp", "ccpa",
}


def scan_audit(
    target: Path,
    on_file: object = None,
) -> tuple[list[Finding], dict[str, int]]:
    """Layer 7: Scan for audit logging and compliance patterns.

    Returns (findings, raw_dimension_scores).
    on_file: optional callable invoked per file scanned (for progress).
    """
    _progress = on_file if callable(on_file) else None
    findings: list[Finding] = []
    has_audit_logging = False
    has_structured_logging = False
    has_retention_policy = False
    has_compliance_ref = False
    has_pii_in_logs = False

    for py_file in target.rglob("*.py"):
        if _should_skip(py_file):
            continue
        if _progress:
            _progress()
        try:
            source = py_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        # Check for audit logging
        if re.search(r"audit.*log|log.*audit|AuditLog|audit_trail", source, re.IGNORECASE):
            has_audit_logging = True

        # Check for structured logging
        if re.search(r"structlog|import logging|logging\.getLogger", source):
            has_structured_logging = True

        # Check for retention/rotation
        if re.search(r"retention|rotation|max_age|log_retention|RotatingFileHandler", source, re.IGNORECASE):
            has_retention_policy = True

        # Check for compliance references
        for keyword in COMPLIANCE_KEYWORDS:
            if keyword in source.lower():
                has_compliance_ref = True
                break

        # Check for PII in logs
        try:
            tree = ast.parse(source, filename=str(py_file))
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                chain = _call_chain(node)
                if any(k in chain for k in ("logger.info", "logger.debug", "logging.info", "log.info")):
                    for arg in node.args:
                        if isinstance(arg, ast.JoinedStr):  # f-string
                            src_snippet = ast.dump(arg).lower()
                            if any(k in src_snippet for k in (
                                "request", "body", "message", "content",
                                "prompt", "response", "password", "email",
                            )):
                                has_pii_in_logs = True
                                findings.append(Finding(
                                    layer=7, scanner="audit_scanner",
                                    file=str(py_file), line=node.lineno,
                                    severity=Severity.HIGH, dimension="D5",
                                    message="Potential PII/sensitive data logged via f-string",
                                    remediation="Redact sensitive fields before logging",
                                    compliance=ComplianceMapping(
                                        eu_ai_act="Article 15",
                                        owasp_llm="LLM06",
                                    ),
                                ))

    # Generate findings for missing controls
    if not has_audit_logging:
        findings.append(Finding(
            layer=7, scanner="audit_scanner",
            file=str(target), line=0,
            severity=Severity.CRITICAL, dimension="D5",
            message="No audit logging for tool calls detected",
            remediation="Add audit logging for all tool/agent executions",
            compliance=ComplianceMapping(eu_ai_act="Article 12"),
        ))

    if not has_structured_logging:
        findings.append(Finding(
            layer=7, scanner="audit_scanner",
            file=str(target), line=0,
            severity=Severity.MEDIUM, dimension="D5",
            message="No structured logging detected — logs stored as plain text",
            remediation="Use structlog or logging module for structured, searchable logs",
        ))

    if not has_retention_policy:
        findings.append(Finding(
            layer=7, scanner="audit_scanner",
            file=str(target), line=0,
            severity=Severity.MEDIUM, dimension="D5",
            message="No log retention policy detected",
            remediation="Configure log rotation and retention periods",
        ))

    if not has_compliance_ref:
        findings.append(Finding(
            layer=7, scanner="audit_scanner",
            file=str(target), line=0,
            severity=Severity.MEDIUM, dimension="D14",
            message="No compliance framework mapping found in code or config",
            remediation="Map controls to GDPR, SOC2, EU AI Act, or other frameworks",
        ))

    scores = _calculate_scores(
        has_audit_logging, has_structured_logging,
        has_retention_policy, has_compliance_ref, has_pii_in_logs,
    )
    return findings, scores


def _call_chain(node: ast.Call) -> str:
    parts: list[str] = []
    cur: Any = node.func
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def _calculate_scores(
    has_audit: bool,
    has_structured: bool,
    has_retention: bool,
    has_compliance: bool,
    has_pii: bool,
) -> dict[str, int]:
    scores: dict[str, int] = {}

    # D5: Log Hygiene
    d5 = 0
    if has_audit:
        d5 += 3
    if has_structured:
        d5 += 2
    if has_retention:
        d5 += 2
    if has_pii:
        d5 -= 2
    scores["D5"] = max(0, min(d5, 6))

    # D14: Compliance Maturity
    d14 = 0
    if has_compliance:
        d14 += 3
    if has_audit and has_retention:
        d14 += 2  # Evidence of compliance practices
    scores["D14"] = min(d14, 4)

    return scores


def _should_skip(filepath: Path) -> bool:
    parts = filepath.parts
    skip_dirs = {
        ".venv", "venv", "node_modules", ".git", "__pycache__",
        "dist", "build", "site-packages", "out", ".next", ".omc", ".claude",
    }
    return bool(skip_dirs.intersection(parts))
