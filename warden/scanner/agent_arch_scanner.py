"""Layer 5: Agent architecture analysis."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from warden.models import ComplianceMapping, Finding, Severity


def scan_agent_arch(target: Path) -> tuple[list[Finding], dict[str, int]]:
    """Layer 5: Scan agent architecture patterns.

    Returns (findings, raw_dimension_scores).
    """
    findings: list[Finding] = []

    import os

    skip_dirs = {
        ".venv", "venv", "node_modules", ".git", "__pycache__",
        "dist", "build", "site-packages", "out", ".next", ".omc", ".claude",
    }
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fname in filenames:
            if fname.endswith(".py"):
                findings.extend(_analyze_agent_file(Path(dirpath) / fname))

    scores = _calculate_scores(findings, target)
    return findings, scores


def _analyze_agent_file(filepath: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        source = filepath.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(source, filename=str(filepath))
    except (SyntaxError, UnicodeDecodeError, OSError):
        return findings

    detector = AgentArchDetector(str(filepath))
    detector.visit(tree)
    findings.extend(detector.findings)

    # Regex-based checks for patterns AST can't easily catch
    findings.extend(_regex_checks(filepath, source))

    return findings


class AgentArchDetector(ast.NodeVisitor):
    AGENT_CLASSES = {"Agent", "ChatAgent", "ReActAgent", "AssistantAgent",
                     "AutoGenAgent", "CrewAgent", "LangChainAgent"}

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.findings: list[Finding] = []
        self._in_agent_class = False

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        is_agent = (
            node.name in self.AGENT_CLASSES or
            any(node.name.endswith(suffix) for suffix in ("Agent", "Bot", "Assistant")) or
            any(self._base_name(b) in self.AGENT_CLASSES for b in node.bases)
        )

        if is_agent:
            self._in_agent_class = True
            self._check_agent_class(node)
            self.generic_visit(node)
            self._in_agent_class = False
        else:
            self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func_name = self._call_name(node)

        # Agent spawning sub-agents without limits
        if self._in_agent_class and func_name in self.AGENT_CLASSES:
            self.findings.append(Finding(
                layer=5, scanner="agent_arch_scanner",
                file=self.filepath, line=node.lineno,
                severity=Severity.HIGH, dimension="D8",
                message="Agent spawns sub-agents without depth limit",
                remediation="Add max_depth or spawn limit to prevent recursive agent creation",
                compliance=ComplianceMapping(eu_ai_act="Article 14"),
            ))

        self.generic_visit(node)

    def _check_agent_class(self, node: ast.ClassDef) -> None:
        source = ast.dump(node).lower()

        # No permission model
        has_permission = any(k in source for k in ("permission", "role", "authorize", "rbac"))
        if not has_permission:
            self.findings.append(Finding(
                layer=5, scanner="agent_arch_scanner",
                file=self.filepath, line=node.lineno,
                severity=Severity.HIGH, dimension="D8",
                message=f"Agent class '{node.name}' has no permission model",
                remediation="Add role/permission checks before tool dispatch",
            ))

        # No cost tracking
        has_cost = any(k in source for k in ("cost", "budget", "token_count", "usage"))
        if not has_cost:
            self.findings.append(Finding(
                layer=5, scanner="agent_arch_scanner",
                file=self.filepath, line=node.lineno,
                severity=Severity.MEDIUM, dimension="D12",
                message=f"Agent class '{node.name}' has no cost tracking",
                remediation="Track token usage and costs per agent execution",
            ))

        # No lifecycle states
        has_lifecycle = any(k in source for k in (
            "state", "status", "suspended", "retired", "lifecycle",
        ))
        if not has_lifecycle:
            self.findings.append(Finding(
                layer=5, scanner="agent_arch_scanner",
                file=self.filepath, line=node.lineno,
                severity=Severity.MEDIUM, dimension="D8",
                message=f"Agent class '{node.name}' has no defined lifecycle states",
                remediation="Add state machine (ACTIVE/SUSPENDED/RETIRED) for agent lifecycle",
            ))

    def _base_name(self, node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return ""

    def _call_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return ""


def _regex_checks(filepath: Path, source: str) -> list[Finding]:
    findings: list[Finding] = []

    # Check for unrestricted tool access patterns
    if re.search(r"tools\s*=\s*(?:all_tools|get_all_tools|tools_list)\b", source):
        line = _find_line(source, "tools")
        findings.append(Finding(
            layer=5, scanner="agent_arch_scanner",
            file=str(filepath), line=line,
            severity=Severity.CRITICAL, dimension="D3",
            message="Agent has access to ALL tools — no scoping or allowlist",
            remediation="Scope tools to only what the agent needs for its task",
            compliance=ComplianceMapping(eu_ai_act="Article 15"),
        ))

    return findings


def _find_line(source: str, keyword: str) -> int:
    for i, line in enumerate(source.splitlines(), 1):
        if keyword in line:
            return i
    return 1


def _calculate_scores(findings: list[Finding], target: Path) -> dict[str, int]:
    scores: dict[str, int] = {}

    # D3: Policy — check for policy engine signals
    d3_findings = sum(1 for f in findings if f.dimension == "D3")
    policy_signals = _count_signals(target, [
        r"policy.*engine", r"allow.*list", r"tool.*scope",
        r"deny.*by.*default", r"permission.*check",
    ])
    scores["D3"] = max(0, min(policy_signals * 2, 6) - d3_findings * 3)

    # D8: Agent Identity
    d8_findings = sum(1 for f in findings if f.dimension == "D8")
    identity_signals = _count_signals(target, [
        r"agent.*registry", r"agent.*id", r"identity.*token",
        r"delegation.*chain", r"agent.*passport",
    ])
    scores["D8"] = max(0, min(identity_signals * 3, 9) - d8_findings * 2)

    # D12: Observability
    d12_findings = sum(1 for f in findings if f.dimension == "D12")
    scores["D12"] = max(0, 2 - d12_findings)

    return scores


def _count_signals(target: Path, patterns: list[str]) -> int:
    import os

    skip_dirs = {
        ".venv", "venv", "node_modules", ".git", "__pycache__",
        "dist", "build", "site-packages", "out", ".next", ".omc", ".claude",
    }
    count = 0
    compiled = [re.compile(p, re.IGNORECASE) for p in patterns]
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fname in filenames:
            if not fname.endswith(".py"):
                continue
            try:
                content = (Path(dirpath) / fname).read_text(
                    encoding="utf-8", errors="ignore"
                )
            except OSError:
                continue
            for pat in compiled:
                if pat.search(content):
                    count += 1
                    break
    return count


def _should_skip(filepath: Path) -> bool:
    parts = filepath.parts
    skip_dirs = {
        ".venv", "venv", "node_modules", ".git", "__pycache__",
        "dist", "build", "site-packages", "out", ".next", ".omc", ".claude",
    }
    return bool(skip_dirs.intersection(parts))
