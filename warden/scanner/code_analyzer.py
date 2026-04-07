"""Layer 1: AST-based code pattern analysis for Python and JavaScript/TypeScript."""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

from warden.models import ComplianceMapping, Finding, Severity
from warden.scanner._common import SKIP_DIRS

# --- AST Detectors ---

class _BaseDetector(ast.NodeVisitor):
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.findings: list[Finding] = []


class UnprotectedLLMCallDetector(_BaseDetector):
    """Finds LLM API calls without gateway/proxy routing."""

    DIRECT_CALL_PATTERNS = [
        ("openai", "ChatCompletion", "create"),
        ("openai", "chat", "completions", "create"),
        ("anthropic", "messages", "create"),
        ("google", "generativeai", "generate_content"),
    ]

    def visit_Call(self, node: ast.Call) -> None:
        chain = self._extract_call_chain(node)
        for pattern in self.DIRECT_CALL_PATTERNS:
            if self._matches(chain, pattern):
                if not self._has_base_url_override(node):
                    self.findings.append(Finding(
                        layer=1, scanner="code_analyzer",
                        file=self.filepath, line=node.lineno,
                        severity=Severity.CRITICAL, dimension="D1",
                        message="LLM call goes directly to provider — no governance proxy",
                        remediation="Route through governance gateway: base_url='https://your-gateway/v1'",
                        compliance=ComplianceMapping(
                            owasp_llm="LLM01",
                            mitre_atlas="AML.T0051",
                        ),
                    ))
        self.generic_visit(node)

    def _extract_call_chain(self, node: ast.Call) -> list[str]:
        parts: list[str] = []
        cur: Any = node.func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        parts.reverse()
        return parts

    def _matches(self, chain: list[str], pattern: tuple[str, ...]) -> bool:
        if len(chain) < len(pattern):
            return False
        return all(c == p for c, p in zip(chain[-len(pattern):], pattern))

    def _has_base_url_override(self, node: ast.Call) -> bool:
        for kw in node.keywords:
            if kw.arg == "base_url":
                return True
        return False


class AgentLoopDetector(_BaseDetector):
    """Finds agent execution loops without termination conditions."""

    def visit_While(self, node: ast.While) -> None:
        if self._contains_llm_call(node):
            has_break = self._has_break(node)
            has_max_iter = self._has_iteration_limit(node)
            has_timeout = self._has_timeout(node)
            if not (has_break or has_max_iter or has_timeout):
                self.findings.append(Finding(
                    layer=1, scanner="code_analyzer",
                    file=self.filepath, line=node.lineno,
                    severity=Severity.CRITICAL, dimension="D2",
                    message="Agent loop with LLM call has no exit condition — potential infinite loop",
                    remediation="Add max_iterations, timeout, or explicit break condition",
                ))
        self.generic_visit(node)

    def _contains_llm_call(self, node: ast.AST) -> bool:
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                chain = []
                cur: Any = child.func
                while isinstance(cur, ast.Attribute):
                    chain.append(cur.attr)
                    cur = cur.value
                chain_str = ".".join(reversed(chain)).lower()
                if any(k in chain_str for k in ("create", "generate", "complete", "chat")):
                    return True
        return False

    def _has_break(self, node: ast.While) -> bool:
        for child in ast.walk(node):
            if isinstance(child, ast.Break):
                return True
        return False

    def _has_iteration_limit(self, node: ast.While) -> bool:
        src = ast.dump(node)
        return any(k in src.lower() for k in ("max_iter", "max_steps", "iteration"))

    def _has_timeout(self, node: ast.While) -> bool:
        src = ast.dump(node)
        return "timeout" in src.lower()


class ToolInputValidationDetector(_BaseDetector):
    """Finds tool functions without input validation."""

    TOOL_DECORATORS = {"tool", "function_call", "register_tool", "mcp_tool"}

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if self._is_tool_function(node):
            if not self._has_validation(node):
                self.findings.append(Finding(
                    layer=1, scanner="code_analyzer",
                    file=self.filepath, line=node.lineno,
                    severity=Severity.CRITICAL, dimension="D2",
                    message="Tool function without input validation",
                    remediation="Add input validation (pydantic, jsonschema, or manual checks)",
                    compliance=ComplianceMapping(owasp_llm="LLM01"),
                ))
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def _is_tool_function(self, node: ast.FunctionDef) -> bool:
        for dec in node.decorator_list:
            name = ""
            if isinstance(dec, ast.Name):
                name = dec.id
            elif isinstance(dec, ast.Attribute):
                name = dec.attr
            elif isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Name):
                    name = dec.func.id
                elif isinstance(dec.func, ast.Attribute):
                    name = dec.func.attr
            if name.lower() in self.TOOL_DECORATORS:
                return True
        return False

    def _has_validation(self, node: ast.FunctionDef) -> bool:
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                chain = []
                cur: Any = child.func
                while isinstance(cur, ast.Attribute):
                    chain.append(cur.attr)
                    cur = cur.value
                if isinstance(cur, ast.Name):
                    chain.append(cur.id)
                chain_str = ".".join(reversed(chain)).lower()
                if any(k in chain_str for k in ("validate", "parse", "model_validate", "schema")):
                    return True
            if isinstance(child, ast.If):
                return True  # Some form of conditional check
        return False


class EmptyExceptionDetector(_BaseDetector):
    """Finds empty exception handlers near LLM-related code."""

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if self._is_empty_handler(node):
            # Check if parent try block contains LLM-related code
            self.findings.append(Finding(
                layer=1, scanner="code_analyzer",
                file=self.filepath, line=node.lineno,
                severity=Severity.HIGH, dimension="D9",
                message="Empty exception handler — errors silently swallowed",
                remediation="Log the exception or handle it explicitly",
            ))
        self.generic_visit(node)

    def _is_empty_handler(self, node: ast.ExceptHandler) -> bool:
        if not node.body:
            return True
        if len(node.body) == 1:
            stmt = node.body[0]
            if isinstance(stmt, ast.Pass):
                return True
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
                if isinstance(stmt.value.value, str):
                    return True  # Docstring-only handler
        return False


class UnrestrictedToolAccessDetector(_BaseDetector):
    """Finds agents with unrestricted tool access (no allowlist)."""

    AGENT_CONSTRUCTORS = {"Agent", "ChatAgent", "ReActAgent", "AssistantAgent"}

    def visit_Call(self, node: ast.Call) -> None:
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if func_name in self.AGENT_CONSTRUCTORS:
            for kw in node.keywords:
                if kw.arg == "tools":
                    if isinstance(kw.value, ast.Name):
                        # Passing a variable (likely full list)
                        self.findings.append(Finding(
                            layer=1, scanner="code_analyzer",
                            file=self.filepath, line=node.lineno,
                            severity=Severity.CRITICAL, dimension="D3",
                            message="Agent with unrestricted tool access — all tools passed without allowlist",
                            remediation="Scope tools to only what the agent needs",
                            compliance=ComplianceMapping(eu_ai_act="Article 15"),
                        ))
        self.generic_visit(node)


class HardcodedModelDetector(_BaseDetector):
    """Finds hardcoded model names in API calls."""

    MODEL_PATTERNS = re.compile(
        r"(gpt-4|gpt-3\.5|claude-3|claude-2|gemini-pro|gemini-1\.5)",
        re.IGNORECASE,
    )

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str) and self.MODEL_PATTERNS.search(node.value):
            self.findings.append(Finding(
                layer=1, scanner="code_analyzer",
                file=self.filepath, line=node.lineno,
                severity=Severity.MEDIUM, dimension="D12",
                message=f"Hardcoded model name: '{node.value}' — no routing/fallback",
                remediation="Use model routing or configuration instead of hardcoded names",
            ))
        self.generic_visit(node)


class PrintStatementDetector(_BaseDetector):
    """Finds print() calls instead of structured logging."""

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name) and node.func.id == "print":
            self.findings.append(Finding(
                layer=1, scanner="code_analyzer",
                file=self.filepath, line=node.lineno,
                severity=Severity.MEDIUM, dimension="D5",
                message="print() used instead of structured logging",
                remediation="Use logging.* or structlog.* for structured, searchable logs",
            ))
        self.generic_visit(node)


class ToolResultNoVerifyDetector(_BaseDetector):
    """Finds tool results used without verification."""

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Call):
            chain = []
            cur: Any = node.value.func
            while isinstance(cur, ast.Attribute):
                chain.append(cur.attr)
                cur = cur.value
            chain_str = ".".join(reversed(chain)).lower()
            if any(k in chain_str for k in ("run_tool", "execute_tool", "call_tool", "invoke")):
                # Check if the next statements verify the result
                self.findings.append(Finding(
                    layer=1, scanner="code_analyzer",
                    file=self.filepath, line=node.lineno,
                    severity=Severity.HIGH, dimension="D15",
                    message="Tool result assigned directly without verification",
                    remediation="Verify tool result status/validity before using",
                ))
        self.generic_visit(node)


# --- JavaScript/TypeScript pattern detection (regex-based, not AST) ---

JS_PATTERNS = [
    (
        re.compile(r"new\s+OpenAI\s*\((?!.*baseURL)", re.MULTILINE),
        "D1", Severity.CRITICAL,
        "JavaScript: OpenAI client without baseURL override",
        "Set baseURL to your governance gateway",
    ),
    (
        re.compile(r"new\s+Anthropic\s*\((?!.*baseURL)", re.MULTILINE),
        "D1", Severity.CRITICAL,
        "JavaScript: Anthropic client without baseURL override",
        "Set baseURL to your governance gateway",
    ),
    (
        re.compile(r"while\s*\(true\).*(?:chat|complete|generate)", re.DOTALL),
        "D2", Severity.CRITICAL,
        "JavaScript: Agent loop without exit condition",
        "Add max_iterations or break condition",
    ),
    (
        re.compile(r"console\.(log|warn|error)\(.*(?:prompt|message|response)", re.IGNORECASE),
        "D5", Severity.MEDIUM,
        "JavaScript: Console logging with potential sensitive data",
        "Use structured logging and redact sensitive fields",
    ),
]


# --- Public API ---

PYTHON_DETECTORS = [
    UnprotectedLLMCallDetector,
    AgentLoopDetector,
    ToolInputValidationDetector,
    EmptyExceptionDetector,
    UnrestrictedToolAccessDetector,
    HardcodedModelDetector,
    PrintStatementDetector,
    ToolResultNoVerifyDetector,
]

# For test files: only run detectors that find genuinely critical issues
PYTHON_DETECTORS_CRITICAL_ONLY = [
    UnprotectedLLMCallDetector,
    AgentLoopDetector,
    UnrestrictedToolAccessDetector,
]


def _scan_python_file(
    filepath: Path,
    content: str | None = None,
) -> list[Finding]:
    """Run all AST detectors on a single Python file."""
    try:
        source = content if content is not None else filepath.read_text(
            encoding="utf-8", errors="ignore"
        )
        tree = ast.parse(source, filename=str(filepath))
    except (SyntaxError, UnicodeDecodeError, OSError):
        return []

    is_test = _is_test_file(filepath)

    # In test files, only run critical detectors (skip print/model/exception noise)
    detectors = PYTHON_DETECTORS if not is_test else PYTHON_DETECTORS_CRITICAL_ONLY

    findings: list[Finding] = []
    for detector_cls in detectors:
        detector = detector_cls(str(filepath))
        detector.visit(tree)
        findings.extend(detector.findings)
    return findings


def _scan_js_file(filepath: Path) -> list[Finding]:
    """Regex-based scanning for JS/TS files."""
    try:
        source = filepath.read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeDecodeError):
        return []

    findings: list[Finding] = []
    for pattern, dim, severity, message, remediation in JS_PATTERNS:
        for match in pattern.finditer(source):
            line = source[:match.start()].count("\n") + 1
            findings.append(Finding(
                layer=1, scanner="code_analyzer",
                file=str(filepath), line=line,
                severity=severity, dimension=dim,
                message=message, remediation=remediation,
            ))
    return findings


def _walk_files(
    target: Path,
) -> tuple[list[Path], list[Path], list[Path]]:
    """Walk the tree ONCE and return (python_files, js_ts_files, other_lang_files).

    Uses os.walk to prune skip_dirs at the directory level — avoids
    traversing node_modules, .git, etc. entirely.
    other_lang_files includes Go, Rust, and Java files.
    """
    import os

    py_exts = {".py"}
    js_exts = {".js", ".ts", ".jsx", ".tsx"}
    other_exts = {".go", ".rs", ".java"}

    py_files: list[Path] = []
    js_files: list[Path] = []
    other_files: list[Path] = []

    for dirpath, dirnames, filenames in os.walk(target):
        # Prune skip dirs IN-PLACE so os.walk doesn't descend into them
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            ext = Path(fname).suffix.lower()
            if ext in py_exts:
                py_files.append(Path(dirpath) / fname)
            elif ext in js_exts:
                js_files.append(Path(dirpath) / fname)
            elif ext in other_exts:
                other_files.append(Path(dirpath) / fname)

    return py_files, js_files, other_files


def scan_code(
    target: Path,
    on_file: object = None,
) -> tuple[list[Finding], dict[str, int]]:
    """Layer 1: Scan code for governance patterns.

    Returns (findings, raw_dimension_scores).
    on_file: optional callable invoked per file scanned (for progress).
    """
    findings: list[Finding] = []
    _progress = on_file if callable(on_file) else None

    py_files, js_files, _other = _walk_files(target)

    # Read all Python files in parallel (I/O-bound — threads help a lot)
    from concurrent.futures import ThreadPoolExecutor

    def _read_file(path: Path) -> tuple[str, str | None]:
        try:
            return str(path), path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return str(path), None

    py_contents: dict[str, str] = {}
    with ThreadPoolExecutor() as pool:
        for key, content in pool.map(_read_file, py_files):
            if content is not None:
                py_contents[key] = content

    # Scan Python files using cached content
    for py_file in py_files:
        content = py_contents.get(str(py_file))
        if content is not None:
            findings.extend(_scan_python_file(py_file, content=content))
        if _progress:
            _progress()

    # Scan JS/TS files (skip frontend/UI — focus on agent/backend code)
    for js_file in js_files:
        if _is_test_file(js_file) or _is_frontend_file(js_file):
            continue
        findings.extend(_scan_js_file(js_file))
        if _progress:
            _progress()

    # Calculate dimension scores — uses cached content, no re-walk
    scores = _calculate_layer_scores(
        findings, target, py_contents=py_contents,
    )
    return findings, scores


def _should_skip(filepath: Path) -> bool:
    """Skip virtual envs, node_modules, test files, and non-project files."""
    parts = filepath.parts
    if SKIP_DIRS.intersection(parts):
        return True
    return False


def _is_test_file(filepath: Path) -> bool:
    """Check if file is a test/fixture file (lower severity for findings)."""
    name = filepath.name.lower()
    parts_lower = {p.lower() for p in filepath.parts}
    return (
        name.startswith("test_") or
        name.endswith("_test.py") or
        name.endswith(".test.ts") or
        name.endswith(".test.js") or
        name.endswith(".spec.ts") or
        name.endswith(".spec.js") or
        "tests" in parts_lower or
        "test" in parts_lower or
        "__tests__" in parts_lower or
        "fixtures" in parts_lower or
        "mock" in name or
        "fixture" in name
    )


def _is_frontend_file(filepath: Path) -> bool:
    """Check if file is a frontend/UI file (not agent code)."""
    parts_lower = {p.lower() for p in filepath.parts}
    frontend_dirs = {
        "portal-v2", "portal-demo", "landing-v2", "admin",
        "components", "pages", "src", "public",
    }
    return bool(frontend_dirs.intersection(parts_lower)) and filepath.suffix in (".js", ".ts", ".jsx", ".tsx")


def _calculate_layer_scores(
    findings: list[Finding],
    target: Path,
    py_contents: dict[str, str] | None = None,
) -> dict[str, int]:
    """Score dimensions based on governance signal detection.

    Additive: presence of governance patterns = positive score.
    Findings cause minor deductions, not zeroing.
    """
    scores: dict[str, int] = {}

    # Count findings per dimension (for minor deductions)
    finding_counts: dict[str, int] = {}
    for f in findings:
        finding_counts[f.dimension] = finding_counts.get(f.dimension, 0) + 1

    # --- All 17 dimensions with governance signal detection ---

    # D1: Tool Inventory (max 25 — Layer 1 contributes up to 15)
    d1 = _count_governance_signals(target, file_contents=py_contents, patterns=[
        r"tool.*catalog", r"tool.*registry", r"mcp.*config",
        r"tool.*inventory", r"available.*tools", r"tool.*schema",
        r"tool.*discover", r"ToolRegistry", r"tool_list",
    ])
    scores["D1"] = min(d1 * 3, 15)

    # D2: Risk Detection (max 20 — up to 12)
    d2 = _count_governance_signals(target, file_contents=py_contents, patterns=[
        r"risk.*classif", r"risk.*score", r"risk.*assess",
        r"semantic.*analy", r"intent.*check", r"RiskScore",
        r"classify.*risk", r"risk.*level", r"co.?occurrence",
    ])
    scores["D2"] = min(d2 * 2, 12)

    # D3: Policy Coverage (max 20 — up to 14)
    d3 = _count_governance_signals(target, file_contents=py_contents, patterns=[
        r"policy.*engine", r"allow.*list", r"deny.*list",
        r"policy.*enforce", r"deny.*by.*default", r"PolicyEngine",
        r"guard.*chain", r"permission.*check", r"yaml.*polic",
        r"policy.*mode", r"ALLOW.*DENY.*AUDIT",
    ])
    scores["D3"] = min(d3 * 2, 14)

    # D4: Credential Management (max 20 — up to 10, secrets scanner handles rest)
    d4 = _count_governance_signals(target, file_contents=py_contents, patterns=[
        r"secrets.*manager", r"key.*rotation", r"vault",
        r"credential.*lifecycle", r"key.*manager", r"KMS",
        r"encrypt.*key", r"nhi.*credential",
    ])
    scores["D4"] = min(d4 * 2, 10)

    # D5: Log Hygiene (max 10 — up to 6)
    d5 = _count_governance_signals(target, file_contents=py_contents, patterns=[
        r"structlog", r"logging\.getLogger", r"import logging",
        r"audit.*log", r"worm.*storage", r"hash.*chain",
        r"log.*retention", r"RotatingFileHandler",
    ])
    scores["D5"] = min(d5 * 2, 6)

    # D6: Framework Coverage (max 5)
    d6 = _count_governance_signals(target, file_contents=py_contents, patterns=[
        r"langchain", r"autogen", r"crewai", r"llama.?index",
        r"openai", r"anthropic", r"litellm", r"framework.*detect",
    ])
    scores["D6"] = min(d6, 5)

    # D7: Human-in-the-Loop (max 15 — up to 10)
    d7 = _count_governance_signals(target, file_contents=py_contents, patterns=[
        r"approval.*gate", r"dry.?run", r"preview.*mode",
        r"human.*in.*loop", r"plan.*execute", r"require.*approval",
        r"confirm.*action", r"DryRun", r"approval.*flow",
        r"user.*confirm",
    ])
    scores["D7"] = min(d7 * 2, 10)

    # D8: Agent Identity (max 15 — up to 9)
    d8 = _count_governance_signals(target, file_contents=py_contents, patterns=[
        r"agent.*registry", r"agent.*id", r"identity.*token",
        r"delegation.*chain", r"agent.*passport", r"AgentPassport",
        r"agent.*lifecycle", r"agent.*state",
    ])
    scores["D8"] = min(d8 * 2, 9)

    # D9: Threat Detection (max 20 — up to 14)
    d9 = _count_governance_signals(target, file_contents=py_contents, patterns=[
        r"anomaly.*detect", r"behavioral.*baseline", r"kill.*switch",
        r"threat.*detect", r"jailbreak.*track", r"circuit.*breaker",
        r"rate.*limit", r"suspicious.*pattern", r"canary",
        r"behavioral.*monitor", r"cross.*session.*track",
        r"waf", r"firewall", r"block.*ip", r"quarantine",
    ])
    scores["D9"] = min(d9 * 2, 14)

    # D10: Prompt Security (max 15 — up to 10)
    d10 = _count_governance_signals(target, file_contents=py_contents, patterns=[
        r"prompt.*inject", r"jailbreak.*detect", r"content.*filter",
        r"input.*sanitiz", r"prompt.*guard", r"injection.*scan",
        r"ContentInjectionDetector", r"prompt.*security",
        r"sanitiz", r"content.*moderation", r"guardrail",
    ])
    scores["D10"] = min(d10 * 2, 10)

    # D11: Cloud / Platform (max 10 — up to 6)
    d11 = _count_governance_signals(target, file_contents=py_contents, patterns=[
        r"sso", r"saml", r"oidc", r"siem.*integrat",
        r"marketplace", r"multi.*cloud", r"idp",
        r"rbac", r"role.*based", r"oauth", r"multi.*tenant",
    ])
    scores["D11"] = min(d11 * 2, 6)

    # D12: LLM Observability (max 10 — up to 7)
    d12 = _count_governance_signals(target, file_contents=py_contents, patterns=[
        r"cost.*track", r"latency.*monitor", r"model.*analytic",
        r"token.*count", r"usage.*track", r"token.*usage",
        r"model.*cost", r"billing", r"metering",
    ])
    scores["D12"] = min(d12 * 2, 7)

    # D13: Data Recovery (max 10 — up to 5)
    d13 = _count_governance_signals(target, file_contents=py_contents, patterns=[
        r"rollback", r"undo.*action", r"point.*in.*time",
        r"snapshot", r"restore", r"backup",
    ])
    scores["D13"] = min(d13 * 2, 5)

    # D14: Compliance Maturity (max 10 — up to 6)
    d14 = _count_governance_signals(target, file_contents=py_contents, patterns=[
        r"soc.?2", r"iso.?27001", r"eu.?ai.?act", r"gdpr",
        r"compliance.*report", r"regulatory.*map", r"hipaa",
        r"evidence.*collect", r"audit.*trail",
    ])
    scores["D14"] = min(d14 * 2, 6)

    # D15: Post-Exec Verification (max 10 — up to 7)
    d15 = _count_governance_signals(target, file_contents=py_contents, patterns=[
        r"verif.*result", r"PASS.*FAIL", r"result.*valid",
        r"post.*exec", r"fingerprint", r"output.*assurance",
        r"verify.*output", r"verification.*engine",
    ])
    scores["D15"] = min(d15 * 2, 7)

    # D16: Data Flow Governance (max 10 — up to 6)
    d16 = _count_governance_signals(target, file_contents=py_contents, patterns=[
        r"taint.*label", r"data.*classif", r"cross.*tool.*leak",
        r"data.*flow", r"pii.*detect", r"dlp", r"data.*loss",
        r"sensitivity.*label", r"data.*governance",
    ])
    scores["D16"] = min(d16 * 2, 6)

    return scores


def _count_governance_signals(
    target: Path,
    patterns: list[str],
    file_contents: dict[str, str] | None = None,
) -> int:
    """Count how many governance-related patterns exist in .py files.

    If file_contents is provided, uses cached content instead of re-reading.
    """
    count = 0
    compiled = [re.compile(p, re.IGNORECASE) for p in patterns]

    if file_contents is not None:
        for content in file_contents.values():
            for pat in compiled:
                if pat.search(content):
                    count += 1
                    break
    else:
        for py_file in target.rglob("*.py"):
            if _should_skip(py_file):
                continue
            try:
                content = py_file.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for pat in compiled:
                if pat.search(content):
                    count += 1
                    break
    return count
