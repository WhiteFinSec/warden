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

    # Strip single-line comment lines to reduce false positives
    lines = source.splitlines(keepends=True)
    cleaned_lines = [
        ln if not ln.lstrip().startswith("//") else "\n"
        for ln in lines
    ]
    cleaned = "".join(cleaned_lines)

    findings: list[Finding] = []
    for pattern, dim, severity, message, remediation in JS_PATTERNS:
        for match in pattern.finditer(cleaned):
            line = cleaned[:match.start()].count("\n") + 1
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

    # --- All 17 dimensions with tiered governance signal detection ---
    # Strong patterns = governance-specific (3 pts each, boolean)
    # Weak patterns = generic app code (1 pt each, boolean, require co-occurrence)

    # D1: Tool Inventory (max 25 — Layer 1 up to 10, MCP up to 15)
    scores["D1"] = _score_governance_signals(py_contents,
        strong=[r"ToolRegistry", r"tool.*catalog", r"tool.*inventory",
                r"tool.*schema.*valid", r"tool.*discover.*regist"],
        weak=[r"tool.*list", r"available.*tools", r"mcp.*config"],
        strong_pts=2, weak_pts=1, cap=10, require_co_occurrence=2)

    # D2: Risk Detection (max 20 — Layer 1 up to 16, MCP up to 4)
    scores["D2"] = _score_governance_signals(py_contents,
        strong=[r"RiskScore", r"risk.*classif.*tool", r"risk.*assess.*agent",
                r"intent.*param.*consist", r"co.?occurrence.*detect"],
        weak=[r"risk.*score", r"risk.*level", r"semantic.*analy"],
        strong_pts=3, weak_pts=1, cap=16, require_co_occurrence=2)

    # D3: Policy Coverage (max 20 — Layer 1 up to 6, arch 6, cicd 4, mcp 6)
    scores["D3"] = _score_governance_signals(py_contents,
        strong=[r"PolicyEngine", r"policy.*enforce.*tool", r"deny.*by.*default",
                r"ALLOW.*DENY.*AUDIT", r"guard.*chain.*polic"],
        weak=[r"allow.*list", r"deny.*list", r"permission.*check",
              r"policy.*mode", r"yaml.*polic"],
        strong_pts=2, weak_pts=1, cap=6, require_co_occurrence=3)

    # D4: Credential Management (max 20 — Layer 1 up to 8, infra 6, mcp 4, cloud 3)
    scores["D4"] = _score_governance_signals(py_contents,
        strong=[r"secrets.*manager", r"key.*rotation", r"credential.*lifecycle",
                r"nhi.*credential", r"KMS.*encrypt"],
        weak=[r"vault", r"key.*manager", r"encrypt.*key"],
        strong_pts=3, weak_pts=1, cap=8, require_co_occurrence=2)

    # D5: Log Hygiene (max 10 — Layer 1 up to 4, audit up to 6)
    scores["D5"] = _score_governance_signals(py_contents,
        strong=[r"audit.*log.*tamper", r"worm.*storage", r"hash.*chain.*log",
                r"log.*retention.*polic", r"immutable.*log"],
        weak=[r"structlog", r"audit.*log", r"RotatingFileHandler"],
        strong_pts=2, weak_pts=1, cap=4, require_co_occurrence=2)

    # D6: Framework Coverage (max 5 — Layer 1 up to 2, framework 3)
    scores["D6"] = _score_governance_signals(py_contents,
        strong=[r"framework.*detect", r"framework.*govern"],
        weak=[r"langchain", r"autogen", r"crewai", r"llama.?index"],
        strong_pts=1, weak_pts=1, cap=2, require_co_occurrence=2)

    # D7: Human-in-the-Loop (max 15 — Layer 1 up to 12, framework 3)
    scores["D7"] = _score_governance_signals(py_contents,
        strong=[r"approval.*gate", r"human.*in.*loop", r"require.*approval",
                r"DryRun.*preview", r"approval.*flow.*enforce"],
        weak=[r"dry.?run", r"preview.*mode", r"confirm.*action",
              r"plan.*execute", r"user.*confirm"],
        strong_pts=3, weak_pts=1, cap=12, require_co_occurrence=2)

    # D8: Agent Identity (max 15 — Layer 1 up to 6, agent_arch 9)
    scores["D8"] = _score_governance_signals(py_contents,
        strong=[r"AgentPassport", r"agent.*registry.*identit",
                r"delegation.*chain", r"identity.*token.*agent"],
        weak=[r"agent.*id", r"agent.*lifecycle", r"agent.*state"],
        strong_pts=2, weak_pts=1, cap=6, require_co_occurrence=2)

    # D9: Threat Detection (max 20 — Layer 1 up to 16, infra 4)
    scores["D9"] = _score_governance_signals(py_contents,
        strong=[r"anomaly.*detect.*agent", r"behavioral.*baseline",
                r"kill.*switch", r"threat.*detect.*llm",
                r"cross.*session.*track", r"behavioral.*monitor"],
        weak=[r"circuit.*breaker", r"rate.*limit", r"jailbreak.*track",
              r"suspicious.*pattern", r"canary", r"quarantine"],
        strong_pts=3, weak_pts=1, cap=16, require_co_occurrence=2)

    # D10: Prompt Security (max 15 — Layer 1 up to 12, cloud 3)
    scores["D10"] = _score_governance_signals(py_contents,
        strong=[r"prompt.*inject.*detect", r"jailbreak.*detect",
                r"ContentInjectionDetector", r"prompt.*guard.*enforc"],
        weak=[r"content.*filter", r"input.*sanitiz", r"prompt.*security",
              r"content.*moderation", r"guardrail"],
        strong_pts=3, weak_pts=1, cap=12, require_co_occurrence=2)

    # D11: Cloud / Platform (max 10 — Layer 1 up to 6, cloud 4)
    scores["D11"] = _score_governance_signals(py_contents,
        strong=[r"siem.*integrat", r"multi.*tenant.*govern",
                r"marketplace.*govern"],
        weak=[r"sso", r"saml", r"oidc", r"rbac", r"oauth", r"multi.*tenant"],
        strong_pts=3, weak_pts=1, cap=6, require_co_occurrence=3)

    # D12: LLM Observability (max 10 — Layer 1 up to 8, agent_arch 2)
    scores["D12"] = _score_governance_signals(py_contents,
        strong=[r"model.*cost.*track", r"token.*usage.*monitor",
                r"llm.*observ", r"model.*analytic.*dashboard"],
        weak=[r"cost.*track", r"latency.*monitor", r"token.*count",
              r"usage.*track", r"metering"],
        strong_pts=3, weak_pts=1, cap=8, require_co_occurrence=2)

    # D13: Data Recovery (max 10 — Layer 1 up to 10, sole contributor)
    scores["D13"] = _score_governance_signals(py_contents,
        strong=[r"undo.*action.*agent", r"point.*in.*time.*recover",
                r"rollback.*tool.*call"],
        weak=[r"rollback", r"snapshot", r"restore", r"backup"],
        strong_pts=3, weak_pts=1, cap=10, require_co_occurrence=2)

    # D14: Compliance Maturity (max 10 — Layer 1 up to 2, audit 4, cicd 3, deps 4)
    scores["D14"] = _score_governance_signals(py_contents,
        strong=[r"compliance.*report.*generat", r"regulatory.*map.*dimen",
                r"evidence.*collect.*audit"],
        weak=[r"soc.?2", r"iso.?27001", r"eu.?ai.?act", r"gdpr",
              r"hipaa", r"audit.*trail"],
        strong_pts=2, weak_pts=1, cap=2, require_co_occurrence=2)

    # D15: Post-Exec Verification (max 10 — Layer 1 up to 10, sole contributor)
    scores["D15"] = _score_governance_signals(py_contents,
        strong=[r"output.*assurance", r"verification.*engine",
                r"post.*exec.*verif", r"verify.*output.*result"],
        weak=[r"PASS.*FAIL", r"result.*valid", r"fingerprint"],
        strong_pts=3, weak_pts=1, cap=10, require_co_occurrence=2)

    # D16: Data Flow Governance (max 10 — Layer 1 up to 10, sole contributor)
    scores["D16"] = _score_governance_signals(py_contents,
        strong=[r"taint.*label", r"cross.*tool.*leak", r"data.*governance.*polic",
                r"sensitivity.*label.*classif"],
        weak=[r"data.*classif", r"pii.*detect", r"dlp",
              r"data.*loss.*prevent", r"data.*flow.*govern"],
        strong_pts=3, weak_pts=1, cap=10, require_co_occurrence=2)

    return scores


def _count_governance_signals(
    target: Path,
    patterns: list[str],
    file_contents: dict[str, str] | None = None,
) -> int:
    """Count files matching governance patterns (legacy, used by D17/trap).

    For dimension scoring, prefer _score_governance_signals() which
    supports strong/weak tiers and co-occurrence.
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


def _score_governance_signals(
    file_contents: dict[str, str],
    strong: list[str],
    weak: list[str],
    strong_pts: int = 3,
    weak_pts: int = 1,
    cap: int = 10,
    require_co_occurrence: int = 0,
) -> int:
    """Score governance signals with strong/weak tiers and co-occurrence.

    - Strong patterns: governance-specific, earn `strong_pts` each (boolean per pattern).
    - Weak patterns: generic app code, earn `weak_pts` each (boolean per pattern).
    - Both are boolean: pattern present anywhere = 1 credit, regardless of file count.
    - require_co_occurrence: if > 0, weak patterns only count if at least this many
      distinct weak patterns matched (prevents single generic match from scoring).

    Returns score capped at `cap`.
    """
    strong_compiled = [re.compile(p, re.IGNORECASE) for p in strong]
    weak_compiled = [re.compile(p, re.IGNORECASE) for p in weak]

    # Boolean: did this pattern match anywhere across the codebase?
    strong_hits = [False] * len(strong_compiled)
    weak_hits = [False] * len(weak_compiled)

    for content in file_contents.values():
        for i, pat in enumerate(strong_compiled):
            if not strong_hits[i] and pat.search(content):
                strong_hits[i] = True
        for i, pat in enumerate(weak_compiled):
            if not weak_hits[i] and pat.search(content):
                weak_hits[i] = True

    score = sum(strong_pts for hit in strong_hits if hit)

    # Weak patterns only contribute if co-occurrence threshold met
    weak_count = sum(1 for hit in weak_hits if hit)
    if weak_count >= max(require_co_occurrence, 1):
        score += sum(weak_pts for hit in weak_hits if hit)

    return min(score, cap)
