"""Layer 11: Multi-Language Governance — Go, Rust, and Java AI agent patterns."""

from __future__ import annotations

import os
import re
from pathlib import Path

from warden.models import ComplianceMapping, Finding, Severity
from warden.scanner._common import SKIP_DIRS

# ---------------------------------------------------------------------------
# Go patterns
# ---------------------------------------------------------------------------

# Direct LLM client usage without proxy/gateway
_GO_DIRECT_OPENAI = re.compile(r"openai\.NewClient")
_GO_DIRECT_ANTHROPIC = re.compile(r"anthropic\.NewClient")

# Unsafe exec without input validation
_GO_EXEC_COMMAND = re.compile(r"exec\.Command\s*\(")
_GO_EXEC_VALIDATED = re.compile(
    r"(?:sanitize|validate|allow(?:ed)?|whitelist|safelist)\s*\(",
    re.IGNORECASE,
)

# Missing context.Context in API calls
_GO_CONTEXT_TIMEOUT = re.compile(r"context\.WithTimeout|context\.WithDeadline")
_GO_CONTEXT_ANY = re.compile(r"context\.(?:Background|TODO|WithCancel|WithValue)")

# Logging patterns
_GO_BASIC_LOG = re.compile(r"\blog\.(?:Print|Fatal|Panic)")
_GO_STRUCTURED_LOG = re.compile(r"(?:log/slog|go\.uber\.org/zap|github\.com/rs/zerolog)")

# Positive signals
_GO_RATE_LIMITER = re.compile(
    r"rate\.(?:NewLimiter|Limiter)|golang\.org/x/time/rate"
)

# ---------------------------------------------------------------------------
# Rust patterns
# ---------------------------------------------------------------------------

# Direct LLM API calls without gateway
_RS_REQWEST_CLIENT = re.compile(r"reqwest::Client")
_RS_LLM_URL = re.compile(
    r"""(?:api\.openai\.com|api\.anthropic\.com)""",
    re.IGNORECASE,
)

# Unsafe blocks near agent/LLM code
_RS_UNSAFE_BLOCK = re.compile(r"unsafe\s*\{")
_RS_AGENT_CONTEXT = re.compile(
    r"(?:agent|llm|model|chat|completion|prompt|anthropic|openai)",
    re.IGNORECASE,
)

# .unwrap() on HTTP responses near LLM calls
_RS_UNWRAP = re.compile(r"\.unwrap\(\)")

# Positive signals
_RS_TRACING = re.compile(r"tracing::instrument|#\[instrument\]")
_RS_TOKIO_TIMEOUT = re.compile(r"tokio::time::timeout")
_RS_RATE_LIMIT = re.compile(
    r"(?:governor|ratelimit|rate_limit|tower::limit)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Java patterns
# ---------------------------------------------------------------------------

# Direct OpenAI/Anthropic SDK usage
_JAVA_DIRECT_OPENAI = re.compile(
    r"(?:OpenAiService|new\s+OpenAI|OpenAiClient)",
)
_JAVA_DIRECT_ANTHROPIC = re.compile(
    r"(?:AnthropicClient|new\s+Anthropic)",
)

# Unrestricted tool access (Spring AI @Tool without auth)
_JAVA_TOOL_ANNOTATION = re.compile(r"@Tool\b")
_JAVA_AUTH_ANNOTATION = re.compile(
    r"@(?:PreAuthorize|Secured|RolesAllowed)\b",
)

# Missing audit logging in agent handlers
_JAVA_HANDLER_CLASS = re.compile(
    r"class\s+\w+(?:Handler|Controller|Service)\b",
)
_JAVA_AUDIT_LOGGING = re.compile(
    r"(?:@Slf4j|Logger\s|LoggerFactory|AuditLog)",
)

# Hardcoded API keys
_JAVA_HARDCODED_KEY = re.compile(
    r"""String\s+\w*[Kk]ey\w*\s*=\s*"(?:sk-|anthropic)""",
)

# Positive signals
_JAVA_OBSERVED = re.compile(r"@Observed\b")
_JAVA_TIMED = re.compile(r"@Timed\b")
_JAVA_RATE_LIMITER = re.compile(r"@RateLimiter\b")
_JAVA_SPRING_SECURITY = re.compile(
    r"@(?:EnableWebSecurity|EnableMethodSecurity|EnableGlobalMethodSecurity)\b",
)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def scan_multilang(target: Path) -> tuple[list[Finding], dict[str, int]]:
    """Layer 11: Scan Go, Rust, and Java files for AI agent governance patterns.

    Returns (findings, raw_dimension_scores).
    """
    findings: list[Finding] = []

    go_files, rs_files, java_files = _find_multilang_files(target)

    go_governance = 0
    rs_governance = 0
    java_governance = 0
    langs_with_governance: set[str] = set()

    for go_file in go_files:
        try:
            content = go_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        file_findings, gov_count = _analyze_go(go_file, content)
        findings.extend(file_findings)
        go_governance += gov_count
        if gov_count > 0:
            langs_with_governance.add("go")

    for rs_file in rs_files:
        try:
            content = rs_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        file_findings, gov_count = _analyze_rust(rs_file, content)
        findings.extend(file_findings)
        rs_governance += gov_count
        if gov_count > 0:
            langs_with_governance.add("rust")

    for java_file in java_files:
        try:
            content = java_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        file_findings, gov_count = _analyze_java(java_file, content)
        findings.extend(file_findings)
        java_governance += gov_count
        if gov_count > 0:
            langs_with_governance.add("java")

    total_files = len(go_files) + len(rs_files) + len(java_files)
    total_governance = go_governance + rs_governance + java_governance
    scores = _calculate_scores(
        findings, total_files, total_governance, langs_with_governance,
    )
    return findings, scores


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------


def _find_multilang_files(
    target: Path,
) -> tuple[list[Path], list[Path], list[Path]]:
    """Find Go, Rust, and Java files using os.walk with SKIP_DIRS pruning."""
    go_files: list[Path] = []
    rs_files: list[Path] = []
    java_files: list[Path] = []

    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            full = Path(dirpath) / fname
            if fname.endswith(".go"):
                go_files.append(full)
            elif fname.endswith(".rs"):
                rs_files.append(full)
            elif fname.endswith(".java"):
                java_files.append(full)

    return go_files, rs_files, java_files


# ---------------------------------------------------------------------------
# Go analysis
# ---------------------------------------------------------------------------


def _analyze_go(filepath: Path, content: str) -> tuple[list[Finding], int]:
    """Analyze a Go file for AI agent governance patterns.

    Returns (findings, governance_signal_count).
    """
    findings: list[Finding] = []
    gov_signals = 0
    str_path = str(filepath)

    # --- Direct LLM client usage without proxy ---
    if _GO_DIRECT_OPENAI.search(content):
        findings.append(Finding(
            layer=11, scanner="multilang_scanner",
            file=str_path, line=_find_line(content, _GO_DIRECT_OPENAI),
            severity=Severity.CRITICAL, dimension="D1",
            message="Direct OpenAI client usage without proxy/gateway — "
                    "no centralized governance or audit",
            remediation="Route LLM calls through a governance proxy "
                        "(e.g., SharkRouter) instead of direct SDK usage",
            compliance=ComplianceMapping(
                eu_ai_act="Article 14",
                owasp_llm="LLM05",
            ),
        ))
    if _GO_DIRECT_ANTHROPIC.search(content):
        findings.append(Finding(
            layer=11, scanner="multilang_scanner",
            file=str_path, line=_find_line(content, _GO_DIRECT_ANTHROPIC),
            severity=Severity.CRITICAL, dimension="D1",
            message="Direct Anthropic client usage without proxy/gateway — "
                    "no centralized governance or audit",
            remediation="Route LLM calls through a governance proxy "
                        "instead of direct SDK usage",
            compliance=ComplianceMapping(
                eu_ai_act="Article 14",
                owasp_llm="LLM05",
            ),
        ))

    # --- Unsafe exec ---
    if _GO_EXEC_COMMAND.search(content):
        if not _GO_EXEC_VALIDATED.search(content):
            findings.append(Finding(
                layer=11, scanner="multilang_scanner",
                file=str_path, line=_find_line(content, _GO_EXEC_COMMAND),
                severity=Severity.HIGH, dimension="D9",
                message="exec.Command used without input validation — "
                        "risk of command injection",
                remediation="Validate/sanitize all inputs before passing "
                            "to exec.Command; use allowlists where possible",
                compliance=ComplianceMapping(
                    owasp_llm="LLM01",
                    mitre_atlas="AML.T0051",
                ),
            ))

    # --- Missing context timeout/deadline ---
    has_ctx_timeout = bool(_GO_CONTEXT_TIMEOUT.search(content))
    has_ctx_any = bool(_GO_CONTEXT_ANY.search(content))

    if has_ctx_timeout:
        gov_signals += 1
    elif has_ctx_any:
        # Using context but no timeout/deadline
        findings.append(Finding(
            layer=11, scanner="multilang_scanner",
            file=str_path, line=_find_line(content, _GO_CONTEXT_ANY),
            severity=Severity.MEDIUM, dimension="D7",
            message="Context used without WithTimeout/WithDeadline — "
                    "API calls may hang indefinitely",
            remediation="Wrap LLM API calls with context.WithTimeout "
                        "or context.WithDeadline",
        ))

    # --- Logging quality ---
    has_basic_log = bool(_GO_BASIC_LOG.search(content))
    has_structured_log = bool(_GO_STRUCTURED_LOG.search(content))

    if has_structured_log:
        gov_signals += 1
    elif has_basic_log:
        findings.append(Finding(
            layer=11, scanner="multilang_scanner",
            file=str_path, line=_find_line(content, _GO_BASIC_LOG),
            severity=Severity.LOW, dimension="D5",
            message="Using basic log.Print instead of structured logging — "
                    "audit trail will lack queryable fields",
            remediation="Adopt log/slog, zap, or zerolog for structured, "
                        "machine-parseable logging",
        ))

    # --- Positive signals ---
    if _GO_RATE_LIMITER.search(content):
        gov_signals += 1

    return findings, gov_signals


# ---------------------------------------------------------------------------
# Rust analysis
# ---------------------------------------------------------------------------


def _analyze_rust(filepath: Path, content: str) -> tuple[list[Finding], int]:
    """Analyze a Rust file for AI agent governance patterns.

    Returns (findings, governance_signal_count).
    """
    findings: list[Finding] = []
    gov_signals = 0
    str_path = str(filepath)

    has_llm_url = bool(_RS_LLM_URL.search(content))
    has_agent_ctx = bool(_RS_AGENT_CONTEXT.search(content))

    # --- Direct LLM API calls without gateway ---
    if _RS_REQWEST_CLIENT.search(content) and has_llm_url:
        findings.append(Finding(
            layer=11, scanner="multilang_scanner",
            file=str_path, line=_find_line(content, _RS_REQWEST_CLIENT),
            severity=Severity.HIGH, dimension="D1",
            message="Direct HTTP calls to LLM API without governance "
                    "gateway — no centralized audit or policy enforcement",
            remediation="Route LLM requests through a governance proxy "
                        "instead of calling provider APIs directly",
            compliance=ComplianceMapping(
                eu_ai_act="Article 14",
                owasp_llm="LLM05",
            ),
        ))

    # --- Unsafe blocks in agent code ---
    if _RS_UNSAFE_BLOCK.search(content) and has_agent_ctx:
        findings.append(Finding(
            layer=11, scanner="multilang_scanner",
            file=str_path, line=_find_line(content, _RS_UNSAFE_BLOCK),
            severity=Severity.CRITICAL, dimension="D9",
            message="unsafe block in agent/LLM code — bypasses Rust's "
                    "memory safety guarantees in AI-critical path",
            remediation="Remove unsafe blocks from agent code or isolate "
                        "them behind a safe abstraction boundary",
            compliance=ComplianceMapping(
                owasp_llm="LLM01",
                mitre_atlas="AML.T0051",
            ),
        ))

    # --- .unwrap() on HTTP responses near LLM calls ---
    if _RS_UNWRAP.search(content) and has_llm_url:
        findings.append(Finding(
            layer=11, scanner="multilang_scanner",
            file=str_path, line=_find_line(content, _RS_UNWRAP),
            severity=Severity.MEDIUM, dimension="D6",
            message=".unwrap() used on HTTP response near LLM API call — "
                    "unhandled errors will panic at runtime",
            remediation="Use proper error handling (? operator or match) "
                        "instead of .unwrap() on API responses",
        ))

    # --- Positive signals ---
    if _RS_TRACING.search(content):
        gov_signals += 1
    if _RS_TOKIO_TIMEOUT.search(content):
        gov_signals += 1
    if _RS_RATE_LIMIT.search(content):
        gov_signals += 1

    return findings, gov_signals


# ---------------------------------------------------------------------------
# Java analysis
# ---------------------------------------------------------------------------


def _analyze_java(filepath: Path, content: str) -> tuple[list[Finding], int]:
    """Analyze a Java file for AI agent governance patterns.

    Returns (findings, governance_signal_count).
    """
    findings: list[Finding] = []
    gov_signals = 0
    str_path = str(filepath)

    # --- Direct OpenAI/Anthropic SDK usage ---
    if _JAVA_DIRECT_OPENAI.search(content):
        findings.append(Finding(
            layer=11, scanner="multilang_scanner",
            file=str_path, line=_find_line(content, _JAVA_DIRECT_OPENAI),
            severity=Severity.CRITICAL, dimension="D1",
            message="Direct OpenAI SDK usage without governance proxy — "
                    "no centralized audit or policy enforcement",
            remediation="Route LLM calls through a governance gateway; "
                        "do not instantiate provider SDKs directly",
            compliance=ComplianceMapping(
                eu_ai_act="Article 14",
                owasp_llm="LLM05",
            ),
        ))
    if _JAVA_DIRECT_ANTHROPIC.search(content):
        findings.append(Finding(
            layer=11, scanner="multilang_scanner",
            file=str_path, line=_find_line(content, _JAVA_DIRECT_ANTHROPIC),
            severity=Severity.CRITICAL, dimension="D1",
            message="Direct Anthropic SDK usage without governance proxy — "
                    "no centralized audit or policy enforcement",
            remediation="Route LLM calls through a governance gateway; "
                        "do not instantiate provider SDKs directly",
            compliance=ComplianceMapping(
                eu_ai_act="Article 14",
                owasp_llm="LLM05",
            ),
        ))

    # --- Unrestricted tool access ---
    if _JAVA_TOOL_ANNOTATION.search(content):
        if not _JAVA_AUTH_ANNOTATION.search(content):
            findings.append(Finding(
                layer=11, scanner="multilang_scanner",
                file=str_path, line=_find_line(content, _JAVA_TOOL_ANNOTATION),
                severity=Severity.HIGH, dimension="D2",
                message="Spring AI @Tool without authorization annotation — "
                        "any caller can invoke this tool unrestricted",
                remediation="Add @PreAuthorize, @Secured, or @RolesAllowed "
                            "to restrict tool access by role",
                compliance=ComplianceMapping(
                    eu_ai_act="Article 14",
                    owasp_llm="LLM06",
                ),
            ))

    # --- Missing audit logging in handler classes ---
    if _JAVA_HANDLER_CLASS.search(content):
        if not _JAVA_AUDIT_LOGGING.search(content):
            findings.append(Finding(
                layer=11, scanner="multilang_scanner",
                file=str_path,
                line=_find_line(content, _JAVA_HANDLER_CLASS),
                severity=Severity.HIGH, dimension="D5",
                message="Agent handler/controller class without audit "
                        "logging — no trace of agent decisions or actions",
                remediation="Add @Slf4j or a Logger instance to all "
                            "agent handler and controller classes",
                compliance=ComplianceMapping(
                    eu_ai_act="Article 12",
                    owasp_llm="LLM09",
                ),
            ))

    # --- Hardcoded API keys ---
    if _JAVA_HARDCODED_KEY.search(content):
        findings.append(Finding(
            layer=11, scanner="multilang_scanner",
            file=str_path, line=_find_line(content, _JAVA_HARDCODED_KEY),
            severity=Severity.CRITICAL, dimension="D4",
            message="Hardcoded API key detected in source — "
                    "credentials exposed in version control",
            remediation="Move API keys to environment variables or a "
                        "secrets manager; never commit credentials",
            compliance=ComplianceMapping(
                owasp_llm="LLM06",
                mitre_atlas="AML.T0024",
            ),
        ))

    # --- Positive signals ---
    if _JAVA_OBSERVED.search(content):
        gov_signals += 1
    if _JAVA_TIMED.search(content):
        gov_signals += 1
    if _JAVA_RATE_LIMITER.search(content):
        gov_signals += 1
    if _JAVA_SPRING_SECURITY.search(content):
        gov_signals += 1

    return findings, gov_signals


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def _calculate_scores(
    findings: list[Finding],
    total_files: int,
    total_governance: int,
    langs_with_governance: set[str],
) -> dict[str, int]:
    """Score dimensions D1 and D6 based on multi-language governance.

    Max contribution per dimension: 3.
    """
    scores: dict[str, int] = {}

    if total_files == 0:
        return scores

    d1_deductions = sum(1 for f in findings if f.dimension == "D1")
    d6_deductions = sum(1 for f in findings if f.dimension == "D6")

    # D1: Tool Inventory — +2 if multi-lang files exist with governance
    d1_base = min(len(langs_with_governance), 2) + (1 if total_governance >= 3 else 0)
    d1 = max(0, min(d1_base, 3) - d1_deductions)
    scores["D1"] = min(d1, 3)

    # D6: Framework Coverage — +2 if framework-specific governance found
    d6_base = min(total_governance, 2) + (1 if len(langs_with_governance) >= 2 else 0)
    d6 = max(0, min(d6_base, 3) - d6_deductions)
    scores["D6"] = min(d6, 3)

    return scores


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_line(content: str, pattern: re.Pattern[str]) -> int:
    """Find the line number of the first match, or 1 if not found."""
    match = pattern.search(content)
    if match:
        return content[: match.start()].count("\n") + 1
    return 1
