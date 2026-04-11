"""Layer 11: Multi-Language Governance — Go, Rust, Java, and C# AI agent patterns."""

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
# C# / .NET patterns (Microsoft.SemanticKernel, Microsoft.Extensions.AI,
# Azure OpenAI, MCP C# SDK)
# ---------------------------------------------------------------------------

# Framework imports — presence alone counts as an AI-agent signal file.
_CS_SEMANTIC_KERNEL = re.compile(
    r"using\s+Microsoft\.SemanticKernel(?:\.[A-Za-z.]+)?\s*;",
)
_CS_EXTENSIONS_AI = re.compile(
    r"using\s+Microsoft\.Extensions\.AI(?:\.[A-Za-z.]+)?\s*;",
)
_CS_AZURE_OPENAI = re.compile(
    r"using\s+Azure\.AI\.OpenAI(?:\.[A-Za-z.]+)?\s*;",
)
_CS_OPENAI_SDK = re.compile(
    r"using\s+OpenAI(?:\.[A-Za-z.]+)?\s*;",
)
_CS_MCP_SDK = re.compile(
    r"using\s+ModelContextProtocol(?:\.[A-Za-z.]+)?\s*;",
)

# Direct LLM client instantiation without a gateway base_url — the C# SDKs
# accept an endpoint URI in the ctor, so we look for `new Xyz(` and check
# whether an override endpoint is passed. We conservatively flag only the
# cases where we can SEE the direct provider URL or there is no endpoint
# argument at all.
_CS_AZURE_CLIENT_NEW = re.compile(
    r"new\s+(?:Azure)?OpenAIClient\s*\(",
)
_CS_CHAT_COMPLETION_SERVICE = re.compile(
    r"IChatCompletionService|IChatClient\b",
)
_CS_PROVIDER_URL = re.compile(
    r"""["'](?:https?://)?(?:api\.openai\.com|api\.anthropic\.com)""",
    re.IGNORECASE,
)
_CS_CUSTOM_ENDPOINT = re.compile(
    r"(?:Uri|Endpoint|base_?url|AzureOpenAIEndpoint)\s*[:=]",
    re.IGNORECASE,
)
_CS_HTTPCLIENT = re.compile(r"new\s+HttpClient\s*\(")

# Tool / function declaration marker — the Semantic Kernel / MCP canonical
# way to expose a method to an agent. Without authorization, any caller can
# invoke it.
_CS_KERNEL_FUNCTION = re.compile(
    r"\[\s*(?:KernelFunction|McpServerTool|Description)\b",
)
_CS_AUTHZ_ATTRIBUTE = re.compile(
    r"\[\s*[^]]*?\b(?:Authorize|RequirePermission|RequireClaim|RequireRole|"
    r"RequireAuthenticatedUser)\b",
)

# Logging — .NET canonical audit signal is ILogger<T> injected into the
# agent / controller. Absence in an AI handler class is D5.
_CS_ILOGGER = re.compile(r"ILogger<[A-Za-z0-9_]+>|ILoggerFactory")
_CS_AGENT_CLASS = re.compile(
    r"class\s+\w*(?:Agent|Orchestrator|Handler|Interceptor|Controller|"
    r"CommandHandler|Skill|Plugin)\b",
)

# Hardcoded credentials. We look for the common connection-string / key
# patterns you find inside appsettings*.json / .config / .cs literals.
_CS_HARDCODED_KEY = re.compile(
    r"""(?:ApiKey|AccessKey|OpenAIKey|AnthropicKey|SubscriptionKey|
         OpenAi__ApiKey|AzureOpenAI__ApiKey)
         \s*[:=]\s*["']
         (?:sk-[A-Za-z0-9]{10,}|[A-Za-z0-9]{32,})""",
    re.IGNORECASE | re.VERBOSE,
)
_CS_HARDCODED_TOKEN = re.compile(
    r"""(?:Bearer|Authorization)\s*[:=]\s*["']
        (?:sk-[A-Za-z0-9]{10,}|[A-Za-z0-9]{40,})""",
    re.IGNORECASE | re.VERBOSE,
)

# Positive signals — invariants, strict schema enforcement, structured
# errors, immutability, deterministic judge config. These map to the
# VigIA-style governance patterns the roadmap called out.
_CS_RESULT_MONAD = re.compile(
    r"\bResult<[A-Za-z0-9_,\s]+>",
)
_CS_IMMUTABLE = re.compile(
    r"\b(?:ImmutableDictionary|ImmutableList|ImmutableArray|"
    r"readonly\s+record\s+struct|readonly\s+record\s+class)\b",
)
_CS_JSON_SOURCE_GEN = re.compile(
    r"\[\s*JsonSerializable\b|\bJsonSerializerContext\b|\bJsonSourceGenerationOptions\b",
)
_CS_STRICT_SCHEMA = re.compile(
    r"ChatResponseFormat\.CreateJsonSchemaFormat|"
    r"ResponseFormat\s*=\s*ChatResponseFormat",
)
_CS_TEMP_ZERO = re.compile(
    r"Temperature\s*=\s*0(?:\.0)?f?\b",
)
_CS_FSM_GUARD = re.compile(
    r"\b(?:TransitionGuard|StateTransition|CanTransition|"
    r"InvariantEnforcer|CommandInterceptor)\b",
)
_CS_CANCELLATION = re.compile(
    r"\bCancellationToken(?:Source)?\b",
)

# Credential injection patterns — IOptions<T> / IConfiguration is the
# idiomatic .NET way to keep secrets out of code. Presence is a strong
# positive D4 signal.
_CS_IOPTIONS = re.compile(r"\bIOptions<[A-Za-z0-9_]+>|\bIOptionsMonitor<")
_CS_ICONFIGURATION = re.compile(r"\bIConfiguration\b|\bConfigurationBuilder\b")
_CS_SECRETS_REFERENCE = re.compile(
    r"\bAzureKeyVault\b|\bKeyVaultClient\b|\bSecretClient\b|\bUserSecrets\b",
)

# Record / value-type patterns. `readonly record struct` is the
# idiomatic .NET 10 immutable value type — a strong D8 signal that
# complements ImmutableDictionary.
_CS_READONLY_RECORD = re.compile(
    r"\breadonly\s+record\s+struct\b|\bsealed\s+record\b|\bpublic\s+record\s+struct\b",
)

# Microsoft.Extensions.AI canonical chat client. Presence in an AI file
# is a strong positive D1 signal (the project is using the blessed
# Microsoft abstraction, not rolling its own HTTP).
_CS_CHAT_CLIENT = re.compile(r"\bChatClient\b|\bIChatClient\b")

# --- D3 Policy Coverage signals ---
#
# InvariantEnforcer / InvariantValidator / RequireInvariant — the VigIA
# archetype: a centralized class that validates LLM output against a
# declarative blueprint before any downstream action. This is
# policy-as-code at its strongest.
_CS_INVARIANT_ENFORCER = re.compile(
    r"\bInvariantEnforcer\b|\bInvariantValidator\b|\bRequireInvariant\b"
    r"|\bValidateAndExtract\b|\bEnforceInvariants\b",
)

# ASP.NET Core authorization policies — AddAuthorization +
# AuthorizationPolicyBuilder + RequireClaim / RequireRole. This is the
# blessed .NET way of declaring "X can only be called by Y".
_CS_AUTH_POLICY = re.compile(
    r"\bAuthorizationPolicyBuilder\b|\bAddAuthorization\b|\bRequireClaim\b"
    r"|\bRequireRole\b|\bIAuthorizationHandler\b|\bAuthorizationPolicy\b",
)

# --- D11 Cloud / Platform signals ---
#
# Microsoft.Extensions.Hosting / Microsoft.Extensions.DependencyInjection
# usage — the .NET generic host is the platform substrate on which every
# non-trivial .NET app runs in cloud environments. IServiceCollection is
# the DI container.
_CS_EXTENSIONS_HOSTING = re.compile(
    r"Microsoft\.Extensions\.Hosting|Microsoft\.Extensions\.DependencyInjection"
    r"|\bIServiceCollection\b|\bWebApplication\.CreateBuilder\b|\bHostBuilder\b",
)

# Azure cloud identity & secrets integration. DefaultAzureCredential is
# the modern managed-identity entry point; SecretClient / KeyVault are
# the secrets store. Presence indicates a cloud-native credential plane.
_CS_AZURE_CLOUD = re.compile(
    r"\bDefaultAzureCredential\b|\bManagedIdentityCredential\b"
    r"|\bAzure\.Identity\b|\bAzure\.Security\.KeyVault\b",
)

# IHttpClientFactory + AddHttpClient pattern — the idiomatic .NET way to
# manage outbound HTTP connections (pooling, retry, socket reuse). A
# platform-hygiene signal rather than a direct governance one.
_CS_HTTPCLIENT_FACTORY = re.compile(
    r"\bIHttpClientFactory\b|\bAddHttpClient\b|\bAddHttpClientDefaults\b",
)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def scan_multilang(target: Path) -> tuple[list[Finding], dict[str, int]]:
    """Layer 11: Scan Go, Rust, Java, and C# files for AI agent governance patterns.

    Returns (findings, raw_dimension_scores).
    """
    findings: list[Finding] = []

    go_files, rs_files, java_files, cs_files, cs_config_files = _find_multilang_files(
        target
    )

    go_governance = 0
    rs_governance = 0
    java_governance = 0
    cs_governance = 0
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

    # Per-file signal dicts for C# — aggregated project-wide below so the
    # scoring helper can see patterns that span multiple files (e.g. a DDD
    # value object in one project + an orchestrator in another).
    cs_file_signals: list[dict[str, bool]] = []
    cs_ai_file_count = 0

    for cs_file in cs_files:
        try:
            content = cs_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        file_findings, gov_count, file_signals = _analyze_csharp(cs_file, content)
        findings.extend(file_findings)
        cs_governance += gov_count
        cs_file_signals.append(file_signals)
        if file_signals.get("is_ai_file"):
            cs_ai_file_count += 1
        if gov_count > 0:
            langs_with_governance.add("csharp")

    # C# config / appsettings*.json / *.config — scan as text for
    # hardcoded credentials. These are the .NET equivalent of .env leaks.
    for cfg_file in cs_config_files:
        try:
            content = cfg_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        findings.extend(_analyze_csharp_config(cfg_file, content))

    total_files = (
        len(go_files) + len(rs_files) + len(java_files) + len(cs_files)
    )
    total_governance = (
        go_governance + rs_governance + java_governance + cs_governance
    )
    scores = _calculate_scores(
        findings, total_files, total_governance, langs_with_governance,
    )

    # C# dimension scores are calculated separately and merged in — the
    # generic _calculate_scores only contributes to D1/D6, which caps a
    # pure-C# project at ~6 raw points. The C# helper maps aggregated
    # signals to D5/D7/D8/D12/D14/D17 directly so a well-governed .NET
    # codebase (VigIA-style: InvariantEnforcer, Result<T,E>, strict JSON
    # schemas, deterministic judge config) earns credit on the dimensions
    # those patterns actually belong to.
    if cs_file_signals:
        cs_scores = _calculate_csharp_dim_scores(
            cs_file_signals, cs_ai_file_count
        )
        for dim, pts in cs_scores.items():
            scores[dim] = scores.get(dim, 0) + pts

    return findings, scores


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------


def _find_multilang_files(
    target: Path,
) -> tuple[list[Path], list[Path], list[Path], list[Path], list[Path]]:
    """Find Go, Rust, Java, C#, and .NET config files via os.walk + SKIP_DIRS.

    Returns (go_files, rs_files, java_files, cs_files, cs_config_files).
    ``cs_config_files`` is the set of .NET-style configuration files we
    scan as text for hardcoded credentials: ``appsettings*.json``,
    ``*.config``, and ``launchSettings.json``. Scanned separately from
    ``cs_files`` so the C# analyzer only sees actual source.
    """
    go_files: list[Path] = []
    rs_files: list[Path] = []
    java_files: list[Path] = []
    cs_files: list[Path] = []
    cs_config_files: list[Path] = []

    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            full = Path(dirpath) / fname
            fname_lower = fname.lower()
            if fname.endswith(".go"):
                go_files.append(full)
            elif fname.endswith(".rs"):
                rs_files.append(full)
            elif fname.endswith(".java"):
                java_files.append(full)
            elif fname.endswith(".cs"):
                cs_files.append(full)
            elif (
                fname_lower.startswith("appsettings")
                and fname_lower.endswith(".json")
            ) or fname_lower == "launchsettings.json" or fname.endswith(".config"):
                cs_config_files.append(full)

    return go_files, rs_files, java_files, cs_files, cs_config_files


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
# C# / .NET analysis
# ---------------------------------------------------------------------------


def _analyze_csharp(
    filepath: Path, content: str
) -> tuple[list[Finding], int, dict[str, bool]]:
    """Analyze a C# file for AI agent governance patterns.

    Returns (findings, governance_signal_count, per_file_signals).

    ``per_file_signals`` is a flat dict of booleans keyed by the pattern
    name (``has_ilogger``, ``has_result_monad``, ``has_strict_schema``,
    etc.). ``scan_multilang`` aggregates these across the whole project
    and ``_calculate_csharp_dim_scores`` turns that aggregate into
    per-dimension raw scores — so a well-governed VigIA-style codebase
    earns credit on D5/D7/D8/D12/D14/D17 instead of getting capped at
    the generic D1+D6 multilang bonus.

    This detector is regex-based and optimized for the
    Microsoft.SemanticKernel / Microsoft.Extensions.AI / Azure.AI.OpenAI
    stack. It does not walk the syntax tree — Warden stays zero-deps.
    """
    findings: list[Finding] = []
    gov_signals = 0
    str_path = str(filepath)
    signals: dict[str, bool] = {
        "is_ai_file": False,
        "has_ilogger": False,
        "has_authz_attr": False,
        "has_kernel_function": False,
        "has_result_monad": False,
        "has_immutable": False,
        "has_readonly_record": False,
        "has_json_source_gen": False,
        "has_strict_schema": False,
        "has_temp_zero": False,
        "has_fsm_guard": False,
        "has_cancellation": False,
        "has_direct_http": False,
        "has_direct_llm_client": False,
        "has_hardcoded_key": False,
        "has_ioptions": False,
        "has_iconfiguration": False,
        "has_secrets_ref": False,
        "has_chat_client": False,
        # D3 policy-as-code signals
        "has_invariant_enforcer": False,
        "has_auth_policy": False,
        # D11 cloud / platform signals
        "has_extensions_hosting": False,
        "has_azure_cloud": False,
        "has_httpclient_factory": False,
    }

    # File needs to look like AI-agent code before we fire findings, or
    # we'll flood every .cs file in a big .NET monorepo with false
    # positives. "AI-agent" = imports one of the canonical frameworks or
    # references IChatCompletionService / IChatClient.
    is_ai_file = bool(
        _CS_SEMANTIC_KERNEL.search(content)
        or _CS_EXTENSIONS_AI.search(content)
        or _CS_AZURE_OPENAI.search(content)
        or _CS_OPENAI_SDK.search(content)
        or _CS_MCP_SDK.search(content)
        or _CS_CHAT_COMPLETION_SERVICE.search(content)
    )
    signals["is_ai_file"] = is_ai_file
    if not is_ai_file:
        # Still record invariant / ImmutableDictionary / Result-monad
        # signals on non-AI files — VigIA-style DDD value objects live in
        # shared domain projects that don't import SemanticKernel but
        # absolutely count as agent-governance evidence when the rest of
        # the solution IS an AI project. We only skip FINDINGS (the
        # absence-based D2/D5 findings) for non-AI files; positive
        # signals are still collected.
        if _CS_RESULT_MONAD.search(content):
            signals["has_result_monad"] = True
        if _CS_IMMUTABLE.search(content):
            signals["has_immutable"] = True
        if _CS_READONLY_RECORD.search(content):
            signals["has_readonly_record"] = True
        if _CS_JSON_SOURCE_GEN.search(content):
            signals["has_json_source_gen"] = True
        if _CS_FSM_GUARD.search(content):
            signals["has_fsm_guard"] = True
        if _CS_IOPTIONS.search(content):
            signals["has_ioptions"] = True
        if _CS_ICONFIGURATION.search(content):
            signals["has_iconfiguration"] = True
        if _CS_SECRETS_REFERENCE.search(content):
            signals["has_secrets_ref"] = True
        # D3 / D11 signals can live anywhere in the solution — VigIA puts
        # its InvariantEnforcer and DI composition in projects that don't
        # import SemanticKernel directly. Collect them from non-AI files too.
        if _CS_INVARIANT_ENFORCER.search(content):
            signals["has_invariant_enforcer"] = True
        if _CS_AUTH_POLICY.search(content):
            signals["has_auth_policy"] = True
        if _CS_EXTENSIONS_HOSTING.search(content):
            signals["has_extensions_hosting"] = True
        if _CS_AZURE_CLOUD.search(content):
            signals["has_azure_cloud"] = True
        if _CS_HTTPCLIENT_FACTORY.search(content):
            signals["has_httpclient_factory"] = True
        return findings, gov_signals, signals

    # --- Direct LLM client without gateway ---
    # `new OpenAIClient(...)` / `new AzureOpenAIClient(...)` with no custom
    # endpoint argument is a direct-to-provider call — no governance layer.
    # If a custom endpoint IS passed (Endpoint = new Uri(...) / base_url),
    # we treat this as routed and do NOT mark the file as a direct call —
    # VigIA's LocalInferenceClient.cs is the canonical example.
    if _CS_AZURE_CLIENT_NEW.search(content):
        if not _CS_CUSTOM_ENDPOINT.search(content):
            signals["has_direct_llm_client"] = True
            findings.append(Finding(
                layer=11, scanner="multilang_scanner",
                file=str_path, line=_find_line(content, _CS_AZURE_CLIENT_NEW),
                severity=Severity.CRITICAL, dimension="D1",
                message="OpenAIClient instantiated without a custom "
                        "endpoint — calls go directly to the provider with "
                        "no governance proxy",
                remediation="Pass an Azure/gateway endpoint URI to the "
                            "client ctor, or route through a governance "
                            "proxy (e.g., SharkRouter) instead of using "
                            "the SDK default endpoint",
                compliance=ComplianceMapping(
                    eu_ai_act="Article 14",
                    owasp_llm="LLM05",
                ),
            ))

    # Raw `new HttpClient(...)` near a provider URL literal is also a
    # direct call and evades any gateway.
    if _CS_HTTPCLIENT.search(content) and _CS_PROVIDER_URL.search(content):
        signals["has_direct_http"] = True
        findings.append(Finding(
            layer=11, scanner="multilang_scanner",
            file=str_path, line=_find_line(content, _CS_HTTPCLIENT),
            severity=Severity.HIGH, dimension="D1",
            message="Raw HttpClient posts to an LLM provider URL — "
                    "bypasses any governance gateway",
            remediation="Use the official SDK with a gateway endpoint, or "
                        "route the HttpClient through a governance proxy",
            compliance=ComplianceMapping(
                eu_ai_act="Article 14",
                owasp_llm="LLM05",
            ),
        ))

    # --- Tool exposure without authorization ---
    # [KernelFunction] / [McpServerTool] without a matching authorization
    # attribute means any caller can invoke the tool. In Semantic Kernel
    # this is the primary governance lever — it's the C# equivalent of
    # Spring AI's @Tool + @PreAuthorize combo.
    if _CS_KERNEL_FUNCTION.search(content):
        signals["has_kernel_function"] = True
        if not _CS_AUTHZ_ATTRIBUTE.search(content):
            findings.append(Finding(
                layer=11, scanner="multilang_scanner",
                file=str_path, line=_find_line(content, _CS_KERNEL_FUNCTION),
                severity=Severity.HIGH, dimension="D2",
                message="Semantic Kernel / MCP tool exposed without "
                        "authorization attribute — any caller can invoke it",
                remediation="Add [Authorize], [RequirePermission], or a "
                            "custom authorization attribute to every "
                            "[KernelFunction] / [McpServerTool] method",
                compliance=ComplianceMapping(
                    eu_ai_act="Article 14",
                    owasp_llm="LLM06",
                ),
            ))
        else:
            signals["has_authz_attr"] = True
            gov_signals += 1

    # --- Audit logging in agent classes ---
    # Agent / orchestrator / handler classes without ILogger<T> injection
    # have no audit trail. This is the D5 gap.
    if _CS_AGENT_CLASS.search(content):
        if not _CS_ILOGGER.search(content):
            findings.append(Finding(
                layer=11, scanner="multilang_scanner",
                file=str_path, line=_find_line(content, _CS_AGENT_CLASS),
                severity=Severity.HIGH, dimension="D5",
                message="Agent / orchestrator / handler class has no "
                        "ILogger<T> — no audit trail for agent decisions",
                remediation="Inject ILogger<T> (or ILoggerFactory) and log "
                            "every tool invocation, state transition, and "
                            "LLM call",
                compliance=ComplianceMapping(
                    eu_ai_act="Article 12",
                    owasp_llm="LLM09",
                ),
            ))
        else:
            signals["has_ilogger"] = True
            gov_signals += 1
    elif _CS_ILOGGER.search(content):
        # ILogger used outside an agent class still counts as an
        # observability signal at the project level (a shared logging
        # helper, a DI registration, etc.)
        signals["has_ilogger"] = True

    # --- Hardcoded credentials inside .cs literals ---
    if _CS_HARDCODED_KEY.search(content) or _CS_HARDCODED_TOKEN.search(content):
        signals["has_hardcoded_key"] = True
        pattern = (
            _CS_HARDCODED_KEY if _CS_HARDCODED_KEY.search(content)
            else _CS_HARDCODED_TOKEN
        )
        findings.append(Finding(
            layer=11, scanner="multilang_scanner",
            file=str_path, line=_find_line(content, pattern),
            severity=Severity.CRITICAL, dimension="D4",
            message="Hardcoded API key / bearer token in C# source — "
                    "credentials committed to version control",
            remediation="Move credentials to IConfiguration, environment "
                        "variables, Azure Key Vault, or another secrets "
                        "manager; rotate the exposed key immediately",
            compliance=ComplianceMapping(
                owasp_llm="LLM06",
                mitre_atlas="AML.T0024",
            ),
        ))

    # --- Positive signals (VigIA-style governance patterns) ---
    # Each distinct pattern is one signal AND is tracked in the per-file
    # signals dict so scan_multilang can aggregate project-wide and
    # _calculate_csharp_dim_scores can map to the right dimensions.
    if _CS_RESULT_MONAD.search(content):
        signals["has_result_monad"] = True
        gov_signals += 1  # D14 — structured error propagation
    if _CS_IMMUTABLE.search(content):
        signals["has_immutable"] = True
        gov_signals += 1  # D8 — state invariants / agent identity
    if _CS_READONLY_RECORD.search(content):
        signals["has_readonly_record"] = True
        gov_signals += 1  # D8 — .NET-canonical immutable value type
    if _CS_JSON_SOURCE_GEN.search(content):
        signals["has_json_source_gen"] = True
        gov_signals += 1  # D1 — compile-time schema enforcement
    if _CS_STRICT_SCHEMA.search(content):
        signals["has_strict_schema"] = True
        gov_signals += 1  # D1 / D17 — strict tool output schema
    if _CS_TEMP_ZERO.search(content):
        signals["has_temp_zero"] = True
        gov_signals += 1  # D17 — deterministic judge configuration
    if _CS_FSM_GUARD.search(content):
        signals["has_fsm_guard"] = True
        gov_signals += 1  # D7 — kill switch / state transition guards
    if _CS_CANCELLATION.search(content):
        signals["has_cancellation"] = True
        gov_signals += 1  # D7 — cancellation propagation
    if _CS_IOPTIONS.search(content):
        signals["has_ioptions"] = True
        gov_signals += 1  # D4 — clean credential injection
    if _CS_ICONFIGURATION.search(content):
        signals["has_iconfiguration"] = True
        gov_signals += 1  # D4 — IConfiguration-based secrets
    if _CS_SECRETS_REFERENCE.search(content):
        signals["has_secrets_ref"] = True
        gov_signals += 1  # D4 — explicit secrets manager reference
    if _CS_CHAT_CLIENT.search(content):
        signals["has_chat_client"] = True
        gov_signals += 1  # D1 — Microsoft.Extensions.AI canonical abstraction
    if _CS_INVARIANT_ENFORCER.search(content):
        signals["has_invariant_enforcer"] = True
        gov_signals += 1  # D3 — declarative policy-as-code on LLM output
    if _CS_AUTH_POLICY.search(content):
        signals["has_auth_policy"] = True
        gov_signals += 1  # D3 — ASP.NET Core authorization policy
    if _CS_EXTENSIONS_HOSTING.search(content):
        signals["has_extensions_hosting"] = True
        gov_signals += 1  # D11 — .NET generic host / DI platform
    if _CS_AZURE_CLOUD.search(content):
        signals["has_azure_cloud"] = True
        gov_signals += 1  # D11 — Azure managed identity / secrets integration
    if _CS_HTTPCLIENT_FACTORY.search(content):
        signals["has_httpclient_factory"] = True
        gov_signals += 1  # D11 — IHttpClientFactory pooled connections

    return findings, gov_signals, signals


def _analyze_csharp_config(filepath: Path, content: str) -> list[Finding]:
    """Look for hardcoded credentials in appsettings*.json / *.config.

    These files get deployed with the app, so any plaintext key here is as
    bad as hardcoding it in .cs source — arguably worse, because
    appsettings.Development.json and .user.config files routinely get
    committed alongside production secrets.
    """
    findings: list[Finding] = []
    str_path = str(filepath)

    if _CS_HARDCODED_KEY.search(content) or _CS_HARDCODED_TOKEN.search(content):
        pattern = (
            _CS_HARDCODED_KEY if _CS_HARDCODED_KEY.search(content)
            else _CS_HARDCODED_TOKEN
        )
        findings.append(Finding(
            layer=11, scanner="multilang_scanner",
            file=str_path, line=_find_line(content, pattern),
            severity=Severity.CRITICAL, dimension="D4",
            message="Hardcoded API key in .NET configuration file — "
                    "credentials live alongside deployable artifacts",
            remediation="Move the key to environment variables, Azure Key "
                        "Vault, AWS Secrets Manager, or HashiCorp Vault; "
                        "add the config file to .gitignore; rotate the key",
            compliance=ComplianceMapping(
                owasp_llm="LLM06",
                mitre_atlas="AML.T0024",
            ),
        ))

    return findings


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


def _calculate_csharp_dim_scores(
    file_signals: list[dict[str, bool]],
    ai_file_count: int,
) -> dict[str, int]:
    """Map aggregated C# per-file signals to raw dimension scores.

    C# / .NET is a primary AI agent stack (Semantic Kernel,
    Microsoft.Extensions.AI, MCP C# SDK), so it gets its own dimension
    mapping driven by project-wide signal aggregates. The contributions
    here are additive on top of the generic D1/D6 multilang bonus.

    Signals are aggregated with ``any()`` across files — one well-designed
    value-object file is enough to credit the pattern at the project
    level, same way the Python scanner credits a project for having a
    SECURITY.md anywhere in the tree.

    **Scoring philosophy.** A well-governed .NET project using Result<T,E>,
    ImmutableDictionary, readonly record struct, strict JSON schema
    enforcement, source-generated JSON contexts, and custom FSM guards
    (the VigIA archetype) should earn **~60% of the dim caps** it
    contributes to — enough to clear PARTIAL (≥60/100) but not GOVERNED
    (≥80/100), because PARTIAL is the honest answer for "strong
    engineering invariants but no ILogger audit trail and no formal
    tool-call gateway".

    Dimension caps (max contribution on top of existing layers):
      D1 tool inventory         — up to 12 / 25
      D3 policy coverage        — up to 14 / 20
      D4 credential management  — up to 12 / 20
      D5 log hygiene            — up to  6 / 10
      D7 kill switch / HITL     — up to 10 / 15
      D8 agent identity         — up to 10 / 15
      D11 cloud / platform      — up to  8 / 10
      D12 observability         — up to  6 / 10
      D14 compliance            — up to  6 / 10
      D17 adversarial resilience — up to  7 / 10

    If no AI files were detected, we return an empty dict — absence of
    SemanticKernel imports means "not an AI project", not "ungoverned".
    Layer 11 will simply stay at zero for C# and the absence-vs-coverage
    fix in scoring/engine.py handles the rest.
    """
    if ai_file_count == 0:
        return {}

    # Aggregate signals across all files.
    any_ilogger = any(s.get("has_ilogger") for s in file_signals)
    any_authz = any(s.get("has_authz_attr") for s in file_signals)
    any_kernel_fn = any(s.get("has_kernel_function") for s in file_signals)
    any_result_monad = any(s.get("has_result_monad") for s in file_signals)
    any_immutable = any(s.get("has_immutable") for s in file_signals)
    any_readonly_rec = any(s.get("has_readonly_record") for s in file_signals)
    any_json_source_gen = any(s.get("has_json_source_gen") for s in file_signals)
    any_strict_schema = any(s.get("has_strict_schema") for s in file_signals)
    any_temp_zero = any(s.get("has_temp_zero") for s in file_signals)
    any_fsm_guard = any(s.get("has_fsm_guard") for s in file_signals)
    any_cancellation = any(s.get("has_cancellation") for s in file_signals)
    any_direct_llm = any(s.get("has_direct_llm_client") for s in file_signals)
    any_direct_http = any(s.get("has_direct_http") for s in file_signals)
    any_hardcoded_key = any(s.get("has_hardcoded_key") for s in file_signals)
    any_ioptions = any(s.get("has_ioptions") for s in file_signals)
    any_iconfig = any(s.get("has_iconfiguration") for s in file_signals)
    any_secrets_ref = any(s.get("has_secrets_ref") for s in file_signals)
    any_chat_client = any(s.get("has_chat_client") for s in file_signals)
    any_invariant = any(s.get("has_invariant_enforcer") for s in file_signals)
    any_auth_policy = any(s.get("has_auth_policy") for s in file_signals)
    any_ext_hosting = any(s.get("has_extensions_hosting") for s in file_signals)
    any_azure_cloud = any(s.get("has_azure_cloud") for s in file_signals)
    any_http_factory = any(s.get("has_httpclient_factory") for s in file_signals)

    # Count how many AI files there are — more AI files = stronger signal.
    multi_ai = ai_file_count >= 3

    scores: dict[str, int] = {}

    # D1 — Tool Inventory. Strict schema enforcement + JSON source gen +
    # IChatClient / ChatClient is the strongest C# "tool inventory" signal.
    # [KernelFunction] / [McpServerTool] also contributes directly.
    d1 = 0
    if any_kernel_fn:
        d1 += 5
    if any_chat_client:
        d1 += 3
    if any_strict_schema:
        d1 += 3
    if any_json_source_gen:
        d1 += 2
    if multi_ai:
        d1 += 2
    if d1:
        scores["D1"] = min(d1, 12)

    # D3 — Policy Coverage. The VigIA archetype: InvariantEnforcer is
    # policy-as-code on LLM output; FSM guards are policy-as-state;
    # Result<T,E> is policy-on-errors; strict schema is policy-on-output;
    # ASP.NET Core AuthorizationPolicy is policy-on-callers. A project
    # that stacks 3+ of these is doing serious policy engineering even
    # without a central policy engine config file.
    d3 = 0
    if any_invariant:
        d3 += 6  # strongest single signal — declarative invariant enforcement
    if any_fsm_guard:
        d3 += 4  # state transition policy
    if any_strict_schema:
        d3 += 3  # LLM output policy
    if any_result_monad:
        d3 += 3  # error policy (never swallow failures)
    if any_auth_policy:
        d3 += 4  # ASP.NET Core authorization
    if d3:
        scores["D3"] = min(d3, 14)

    # D4 — Credential Management. IConfiguration / IOptions<T> /
    # AzureKeyVault references are clean credential injection. Plus a
    # baseline credit for not having hardcoded keys in any AI file.
    d4 = 0
    if not any_hardcoded_key:
        d4 += 4  # baseline "no hardcoded creds in source" credit
    if any_ioptions:
        d4 += 4
    if any_iconfig:
        d4 += 2
    if any_secrets_ref:
        d4 += 3
    if d4:
        scores["D4"] = min(d4, 12)

    # D5 — Log Hygiene. ILogger<T> is the canonical .NET audit signal.
    # Result<T,E> is a weaker but real substitute for projects that
    # intentionally avoid ILogger (VigIA archetype) — boost it when it
    # combines with FSM guards or InvariantEnforcer, because those
    # patterns guarantee every failure produces a structured audit
    # record even without a logger.
    d5 = 0
    if any_ilogger:
        d5 += 4
    elif any_result_monad:
        d5 += 3  # Result<T,E> as audit primitive
        if any_fsm_guard or any_invariant:
            d5 += 2  # combined with structured state/invariant enforcement
    if any_ilogger and any_authz:
        d5 += 2
    if d5:
        scores["D5"] = min(d5, 6)

    # D7 — kill switch / HITL controls. CancellationToken propagation is
    # the .NET-canonical "stop the agent mid-flight" signal. FSM
    # TransitionGuard / InvariantEnforcer is the VigIA hard-block pattern.
    d7 = 0
    if any_cancellation:
        d7 += 4
    if any_fsm_guard:
        d7 += 6
    if d7:
        scores["D7"] = min(d7, 10)

    # D8 — agent identity / state invariants. ImmutableDictionary +
    # readonly record struct + Result<T,E> is the gold standard of
    # invariant-driven agent design.
    d8 = 0
    if any_immutable:
        d8 += 4
    if any_readonly_rec:
        d8 += 3
    if any_result_monad:
        d8 += 3
    if d8:
        scores["D8"] = min(d8, 10)

    # D11 — Cloud / Platform. Microsoft.Extensions.Hosting + DI +
    # Azure.Identity + IHttpClientFactory is the cloud-native .NET
    # platform baseline. A project using the generic host is running
    # on a real platform substrate (ASP.NET Core, Worker Service, etc.)
    # rather than a bare-metal console app.
    d11 = 0
    if any_ext_hosting:
        d11 += 4
    if any_azure_cloud:
        d11 += 3
    if any_http_factory:
        d11 += 2
    if any_chat_client:
        d11 += 2  # Microsoft.Extensions.AI is a platform contract
    if d11:
        scores["D11"] = min(d11, 8)

    # D12 — observability. JSON source generation + ILogger gives
    # structured, machine-parseable, AOT-safe logs — the gold standard
    # for .NET observability in agent systems.
    d12 = 0
    if any_ilogger:
        d12 += 3
    if any_json_source_gen:
        d12 += 3
    if d12:
        scores["D12"] = min(d12, 6)

    # D14 — compliance. Result<T,E> monadic error handling is the .NET
    # equivalent of "never swallow exceptions" — a compliance must for
    # EU AI Act Article 12 (logging) and Article 14 (human oversight).
    d14 = 0
    if any_result_monad:
        d14 += 4
    if any_json_source_gen:
        d14 += 2  # AOT-safe structured payloads = compliance-grade evidence
    if any_result_monad and (any_ilogger or any_fsm_guard):
        d14 += 2
    if any_invariant:
        d14 += 2  # declarative invariants = auditable compliance posture
    if d14:
        scores["D14"] = min(d14, 8)

    # D17 — adversarial resilience. Strict JSON schema enforcement on
    # LLM output + deterministic judge config (Temperature=0) + compile-
    # time JSON source generation is the strongest prompt-injection /
    # trap-defense combination available in the .NET stack.
    d17 = 0
    if any_strict_schema:
        d17 += 3
    if any_temp_zero:
        d17 += 2
    if any_json_source_gen:
        d17 += 2
    if any_fsm_guard:
        d17 += 2  # state-machine guards = prompt-injection resistance
    if any_invariant:
        d17 += 2  # invariant enforcement blocks malformed LLM output
    if d17:
        scores["D17"] = min(d17, 8)

    # Penalties — if the project has direct LLM calls or hardcoded keys,
    # trim the C# dimension credit. We don't zero it out (the governance
    # patterns are still real), but we cap the top-line signal so a
    # project with `new OpenAIClient()` scattered around can't earn the
    # full bonus just because it also has a few Result<T,E> files.
    if any_direct_llm or any_direct_http:
        for dim in list(scores.keys()):
            scores[dim] = max(0, scores[dim] - 2)
    if any_hardcoded_key and "D4" in scores:
        scores["D4"] = max(0, scores["D4"] - 6)

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
