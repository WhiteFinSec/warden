"""Layer 10: Framework-Specific Governance — LangChain, CrewAI, AutoGen, LlamaIndex."""

from __future__ import annotations

import os
import re
from pathlib import Path

from warden.models import ComplianceMapping, Finding, Severity
from warden.scanner._common import SKIP_DIRS

# --- Framework detection patterns ---

_LANGCHAIN_IMPORT = re.compile(r"(?:from\s+langchain|import\s+langchain)", re.IGNORECASE)
_CREWAI_IMPORT = re.compile(r"(?:from\s+crewai|import\s+crewai)", re.IGNORECASE)
_AUTOGEN_IMPORT = re.compile(r"(?:from\s+autogen|import\s+autogen)", re.IGNORECASE)
_LLAMAINDEX_IMPORT = re.compile(r"(?:from\s+llama_index|import\s+llama_index)", re.IGNORECASE)

# --- Governance signal patterns per framework ---

# LangChain: callbacks for observability
_LC_CALLBACK_MANAGER = re.compile(r"CallbackManager|BaseCallbackHandler", re.IGNORECASE)
_LC_ON_TOOL = re.compile(r"on_tool_start|on_tool_end|on_tool_error")
_LC_ON_CHAIN = re.compile(r"on_chain_start|on_chain_end|on_chain_error")

# CrewAI: guardrails and limits
_CREW_GUARDRAIL = re.compile(r"guardrail\s*=")
_CREW_MAX_ITER = re.compile(r"max_iter\s*=")
_CREW_TIMEOUT = re.compile(r"timeout\s*=")

# AutoGen: sandboxing and termination
_AG_DOCKER = re.compile(r"use_docker\s*[=:]")
_AG_TERMINATION = re.compile(r"is_termination_msg|termination")

# LlamaIndex: callbacks and limits
_LI_CALLBACK = re.compile(r"callback_manager\s*=")
_LI_SERVICE_CTX = re.compile(r"ServiceContext|Settings")

# Generic governance patterns
_GENERIC_MAX_TOKENS = re.compile(r"max_tokens\s*=")
_GENERIC_TEMPERATURE = re.compile(r"temperature\s*=\s*0(?:\.\d+)?")
_GENERIC_RETRY_BACKOFF = re.compile(r"(?:retry|backoff|exponential)", re.IGNORECASE)


def scan_frameworks(target: Path) -> tuple[list[Finding], dict[str, int]]:
    """Layer 10: Scan Python files for framework-specific governance patterns.

    Returns (findings, raw_dimension_scores).
    """
    findings: list[Finding] = []

    py_files = _find_py_files(target)

    frameworks_detected: set[str] = set()
    governance_signals = 0
    hitl_signals = 0

    for py_file in py_files:
        try:
            content = py_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        file_findings, fw_set, gov_count, hitl_count = _analyze_file(py_file, content)
        findings.extend(file_findings)
        frameworks_detected.update(fw_set)
        governance_signals += gov_count
        hitl_signals += hitl_count

    scores = _calculate_scores(findings, frameworks_detected, governance_signals, hitl_signals)
    return findings, scores


def _find_py_files(target: Path) -> list[Path]:
    """Find Python files using os.walk with skip_dirs pruning."""
    results: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            if fname.endswith(".py"):
                results.append(Path(dirpath) / fname)
    return results


def _analyze_file(
    filepath: Path,
    content: str,
) -> tuple[list[Finding], set[str], int, int]:
    """Analyze a single Python file for framework governance patterns.

    Returns (findings, frameworks_detected, governance_signal_count, hitl_signal_count).
    """
    findings: list[Finding] = []
    frameworks: set[str] = set()
    gov_signals = 0
    hitl_signals = 0

    # Detect which frameworks are used
    has_langchain = bool(_LANGCHAIN_IMPORT.search(content))
    has_crewai = bool(_CREWAI_IMPORT.search(content))
    has_autogen = bool(_AUTOGEN_IMPORT.search(content))
    has_llamaindex = bool(_LLAMAINDEX_IMPORT.search(content))

    if has_langchain:
        frameworks.add("langchain")
    if has_crewai:
        frameworks.add("crewai")
    if has_autogen:
        frameworks.add("autogen")
    if has_llamaindex:
        frameworks.add("llamaindex")

    # Only check governance if a framework is detected
    if not frameworks:
        return findings, frameworks, gov_signals, hitl_signals

    str_filepath = str(filepath)

    # --- LangChain checks ---
    if has_langchain:
        has_callbacks = bool(_LC_CALLBACK_MANAGER.search(content))
        has_tool_hooks = bool(_LC_ON_TOOL.search(content))
        has_chain_hooks = bool(_LC_ON_CHAIN.search(content))

        if has_callbacks:
            gov_signals += 1
        if has_tool_hooks:
            gov_signals += 1
            hitl_signals += 1
        if has_chain_hooks:
            gov_signals += 1

        if not has_callbacks and not has_tool_hooks:
            findings.append(Finding(
                layer=10, scanner="framework_scanner",
                file=str_filepath, line=_find_line(content, _LANGCHAIN_IMPORT),
                severity=Severity.HIGH, dimension="D6",
                message="LangChain used without CallbackManager — no tool/chain observability",
                remediation="Add CallbackManager with on_tool_start/on_chain_start handlers",
                compliance=ComplianceMapping(eu_ai_act="Article 13"),
            ))

    # --- CrewAI checks ---
    if has_crewai:
        has_guardrail = bool(_CREW_GUARDRAIL.search(content))
        has_max_iter = bool(_CREW_MAX_ITER.search(content))
        has_timeout = bool(_CREW_TIMEOUT.search(content))

        if has_guardrail:
            gov_signals += 1
            hitl_signals += 1
        if has_max_iter:
            gov_signals += 1
        if has_timeout:
            gov_signals += 1

        if not has_guardrail:
            findings.append(Finding(
                layer=10, scanner="framework_scanner",
                file=str_filepath, line=_find_line(content, _CREWAI_IMPORT),
                severity=Severity.HIGH, dimension="D7",
                message="CrewAI agent without guardrail — no output validation gate",
                remediation="Add guardrail= parameter to agent/task config for output validation",
            ))
        if not has_max_iter and not has_timeout:
            findings.append(Finding(
                layer=10, scanner="framework_scanner",
                file=str_filepath, line=_find_line(content, _CREWAI_IMPORT),
                severity=Severity.MEDIUM, dimension="D6",
                message="CrewAI agent without max_iter or timeout — unbounded execution",
                remediation="Set max_iter= and/or timeout= to prevent runaway agent loops",
            ))

    # --- AutoGen checks ---
    if has_autogen:
        has_docker = bool(_AG_DOCKER.search(content))
        has_termination = bool(_AG_TERMINATION.search(content))

        if has_docker:
            gov_signals += 1
        if has_termination:
            gov_signals += 1
            hitl_signals += 1

        if not has_docker:
            findings.append(Finding(
                layer=10, scanner="framework_scanner",
                file=str_filepath, line=_find_line(content, _AUTOGEN_IMPORT),
                severity=Severity.CRITICAL, dimension="D6",
                message="AutoGen code execution without Docker sandboxing",
                remediation="Set code_execution_config={'use_docker': True} for safe code execution",
                compliance=ComplianceMapping(owasp_llm="LLM01", mitre_atlas="AML.T0051"),
            ))
        if not has_termination:
            findings.append(Finding(
                layer=10, scanner="framework_scanner",
                file=str_filepath, line=_find_line(content, _AUTOGEN_IMPORT),
                severity=Severity.HIGH, dimension="D7",
                message="AutoGen agent without is_termination_msg — no conversation exit condition",
                remediation="Define is_termination_msg function to control when agents stop",
            ))

    # --- LlamaIndex checks ---
    if has_llamaindex:
        has_callback = bool(_LI_CALLBACK.search(content))
        has_service_ctx = bool(_LI_SERVICE_CTX.search(content))

        if has_callback:
            gov_signals += 1
        if has_service_ctx:
            gov_signals += 1

        if not has_callback:
            findings.append(Finding(
                layer=10, scanner="framework_scanner",
                file=str_filepath, line=_find_line(content, _LLAMAINDEX_IMPORT),
                severity=Severity.MEDIUM, dimension="D6",
                message="LlamaIndex used without callback_manager — no query observability",
                remediation="Set callback_manager= on your index/query engine for tracing",
            ))

    # --- Generic governance checks (apply to all framework files) ---
    if _GENERIC_MAX_TOKENS.search(content):
        gov_signals += 1
    if _GENERIC_TEMPERATURE.search(content):
        gov_signals += 1
    if _GENERIC_RETRY_BACKOFF.search(content):
        gov_signals += 1

    return findings, frameworks, gov_signals, hitl_signals


def _find_line(content: str, pattern: re.Pattern[str]) -> int:
    """Find the line number of the first match, or 1 if not found."""
    match = pattern.search(content)
    if match:
        return content[: match.start()].count("\n") + 1
    return 1


def _calculate_scores(
    findings: list[Finding],
    frameworks_detected: set[str],
    governance_signals: int,
    hitl_signals: int,
) -> dict[str, int]:
    """Score dimensions D6 and D7 based on framework governance."""
    scores: dict[str, int] = {}

    if not frameworks_detected:
        return scores

    d6_deductions = sum(1 for f in findings if f.dimension == "D6")
    d7_deductions = sum(1 for f in findings if f.dimension == "D7")

    # D6: Framework Coverage — max contribution 3
    # Base: 1 point per framework detected (up to 2), plus governance signals
    d6_base = min(len(frameworks_detected), 2) + min(governance_signals, 2)
    d6 = min(d6_base, 3)
    d6 = max(0, d6 - d6_deductions)
    scores["D6"] = min(d6, 3)

    # D7: Human-in-the-Loop — max contribution 3
    d7_base = min(hitl_signals, 3)
    d7 = max(0, d7_base - d7_deductions)
    scores["D7"] = min(d7, 3)

    return scores
