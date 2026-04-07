"""Layer 12: Cloud-Native AI Governance — AWS Bedrock, Azure AI, GCP Vertex AI."""

from __future__ import annotations

import os
import re
from pathlib import Path

from warden.models import ComplianceMapping, Finding, Severity
from warden.scanner._common import SKIP_DIRS

# --- File extensions to scan ---

_SOURCE_EXTS: frozenset[str] = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".java",
})

# ---------------------------------------------------------------------------
# AWS Bedrock patterns
# ---------------------------------------------------------------------------

_AWS_BEDROCK_IMPORT = re.compile(
    r"(?:import\s+boto3|from\s+boto3)"
)
_AWS_BEDROCK_CLIENT = re.compile(
    r"(?:bedrock-runtime|bedrock|BedrockRuntime)", re.IGNORECASE
)
_AWS_INVOKE_MODEL = re.compile(r"invoke_model")
_AWS_GUARDRAIL_ID = re.compile(r"guardrailIdentifier")
_AWS_GUARDRAIL_VER = re.compile(r"guardrailVersion")
_AWS_CONTENT_POLICY = re.compile(r"contentPolicy")
_AWS_FILTER_STRENGTH = re.compile(r"filterStrength")
_AWS_CLOUDWATCH = re.compile(r"(?:CloudWatch|put_metric|log_group|create_log_group)", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Azure AI patterns
# ---------------------------------------------------------------------------

_AZURE_AI_IMPORT = re.compile(
    r"(?:from\s+azure\.ai|azure\.ai\.inference|AzureOpenAI|ContentSafety)"
)
_AZURE_CONTENT_SAFETY = re.compile(r"ContentSafetyClient")
_AZURE_MANAGED_IDENTITY = re.compile(
    r"(?:DefaultAzureCredential|ManagedIdentityCredential)"
)
_AZURE_HARDCODED_KEY = re.compile(
    r"""(?:api_key|key)\s*=\s*["'][A-Za-z0-9+/=]{20,}["']"""
)

# ---------------------------------------------------------------------------
# GCP Vertex AI patterns
# ---------------------------------------------------------------------------

_GCP_VERTEX_IMPORT = re.compile(
    r"(?:from\s+google\.cloud\s+import\s+aiplatform|import\s+vertexai|GenerativeModel)"
)
_GCP_SAFETY_SETTINGS = re.compile(r"safety_settings")
_GCP_HARM_CATEGORY = re.compile(r"HarmCategory")
_GCP_HARM_BLOCK = re.compile(r"HarmBlockThreshold")
_GCP_SERVICE_ACCOUNT = re.compile(r"(?:service_account|credentials\s*=)")
_GCP_GENERATIVE_MODEL = re.compile(r"GenerativeModel\s*\(")

# ---------------------------------------------------------------------------
# Generic cloud AI patterns (any provider)
# ---------------------------------------------------------------------------

_HARDCODED_ENDPOINT = re.compile(
    r"""["']https?://(?:api\.openai\.com|api\.anthropic\.com|"""
    r"""generativelanguage\.googleapis\.com|"""
    r"""[a-z0-9-]+\.openai\.azure\.com|"""
    r"""bedrock-runtime\.[a-z0-9-]+\.amazonaws\.com)"""
    r"""[^"']*["']""",
    re.IGNORECASE,
)
_API_KEY_IN_SOURCE = re.compile(
    r"""(?:key|token|secret)\s*=\s*["'][A-Za-z0-9_\-]{20,}["']""",
    re.IGNORECASE,
)
_PROVIDER_URL_SAME_LINE_KEY = re.compile(
    r"""(?:openai\.com|anthropic\.com|azure\.com|googleapis\.com|amazonaws\.com)"""
    r""".*(?:key|token|secret)\s*=\s*["']"""
    r"""|"""
    r"""(?:key|token|secret)\s*=\s*["'].*"""
    r"""(?:openai\.com|anthropic\.com|azure\.com|googleapis\.com|amazonaws\.com)""",
    re.IGNORECASE,
)


def scan_cloud(target: Path) -> tuple[list[Finding], dict[str, int]]:
    """Layer 12: Scan source files for cloud AI governance patterns.

    Returns (findings, raw_dimension_scores).
    """
    findings: list[Finding] = []

    source_files = _find_source_files(target)

    providers_detected: set[str] = set()
    governance_signals = 0
    credential_signals = 0

    for src_file in source_files:
        try:
            content = src_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        file_findings, prov_set, gov_count, cred_count = _analyze_file(src_file, content)
        findings.extend(file_findings)
        providers_detected.update(prov_set)
        governance_signals += gov_count
        credential_signals += cred_count

    scores = _calculate_scores(findings, providers_detected, governance_signals, credential_signals)
    return findings, scores


def _find_source_files(target: Path) -> list[Path]:
    """Find source files (Python, JS/TS, Go, Rust, Java) using os.walk with SKIP_DIRS pruning."""
    results: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            if ext in _SOURCE_EXTS:
                results.append(Path(dirpath) / fname)
    return results


def _analyze_file(
    filepath: Path,
    content: str,
) -> tuple[list[Finding], set[str], int, int]:
    """Analyze a single source file for cloud AI governance patterns.

    Returns (findings, providers_detected, governance_signal_count, credential_signal_count).
    """
    findings: list[Finding] = []
    providers: set[str] = set()
    gov_signals = 0
    cred_signals = 0

    str_filepath = str(filepath)

    # Detect which cloud providers are used
    has_aws = bool(_AWS_BEDROCK_IMPORT.search(content)) and bool(_AWS_BEDROCK_CLIENT.search(content))
    has_azure = bool(_AZURE_AI_IMPORT.search(content))
    has_gcp = bool(_GCP_VERTEX_IMPORT.search(content))

    if has_aws:
        providers.add("aws_bedrock")
    if has_azure:
        providers.add("azure_ai")
    if has_gcp:
        providers.add("gcp_vertex")

    # --- AWS Bedrock checks ---
    if has_aws:
        has_invoke = bool(_AWS_INVOKE_MODEL.search(content))
        has_guardrail = bool(_AWS_GUARDRAIL_ID.search(content)) or bool(_AWS_GUARDRAIL_VER.search(content))
        has_content_filter = bool(_AWS_CONTENT_POLICY.search(content)) or bool(_AWS_FILTER_STRENGTH.search(content))
        has_cloudwatch = bool(_AWS_CLOUDWATCH.search(content))

        if has_guardrail:
            gov_signals += 2
        if has_content_filter:
            gov_signals += 1
        if has_cloudwatch:
            gov_signals += 1

        if has_invoke and not has_guardrail:
            findings.append(Finding(
                layer=12, scanner="cloud_scanner",
                file=str_filepath, line=_find_line(content, _AWS_INVOKE_MODEL),
                severity=Severity.HIGH, dimension="D11",
                message="AWS Bedrock invoke_model without guardrailIdentifier — no guardrail enforcement",
                remediation="Add guardrailIdentifier and guardrailVersion parameters to invoke_model calls",
                compliance=ComplianceMapping(eu_ai_act="Article 9", owasp_llm="LLM02"),
            ))

        if has_invoke and not has_content_filter:
            findings.append(Finding(
                layer=12, scanner="cloud_scanner",
                file=str_filepath, line=_find_line(content, _AWS_INVOKE_MODEL),
                severity=Severity.MEDIUM, dimension="D10",
                message="AWS Bedrock invoke_model without contentPolicy — no content filtering configured",
                remediation="Configure contentPolicy with filterStrength for input/output content moderation",
                compliance=ComplianceMapping(eu_ai_act="Article 15"),
            ))

    # --- Azure AI checks ---
    if has_azure:
        has_content_safety = bool(_AZURE_CONTENT_SAFETY.search(content))
        has_managed_id = bool(_AZURE_MANAGED_IDENTITY.search(content))
        has_hardcoded_key = bool(_AZURE_HARDCODED_KEY.search(content))

        if has_content_safety:
            gov_signals += 2
        if has_managed_id:
            cred_signals += 2

        if not has_content_safety:
            findings.append(Finding(
                layer=12, scanner="cloud_scanner",
                file=str_filepath, line=_find_line(content, _AZURE_AI_IMPORT),
                severity=Severity.HIGH, dimension="D10",
                message="Azure AI used without ContentSafetyClient — no content moderation",
                remediation="Add Azure ContentSafetyClient to analyse prompts/responses for harmful content",
                compliance=ComplianceMapping(eu_ai_act="Article 15", owasp_llm="LLM02"),
            ))

        if has_hardcoded_key and not has_managed_id:
            findings.append(Finding(
                layer=12, scanner="cloud_scanner",
                file=str_filepath, line=_find_line(content, _AZURE_HARDCODED_KEY),
                severity=Severity.HIGH, dimension="D4",
                message="Azure AI using hardcoded API key instead of managed identity",
                remediation="Use DefaultAzureCredential or ManagedIdentityCredential for keyless auth",
                compliance=ComplianceMapping(owasp_llm="LLM06"),
            ))

    # --- GCP Vertex AI checks ---
    if has_gcp:
        has_safety = bool(_GCP_SAFETY_SETTINGS.search(content))
        has_harm_cat = bool(_GCP_HARM_CATEGORY.search(content))
        has_harm_block = bool(_GCP_HARM_BLOCK.search(content))
        has_svc_acct = bool(_GCP_SERVICE_ACCOUNT.search(content))
        has_gen_model = bool(_GCP_GENERATIVE_MODEL.search(content))

        if has_safety:
            gov_signals += 1
        if has_harm_cat or has_harm_block:
            gov_signals += 1
        if has_svc_acct:
            cred_signals += 1

        if not has_svc_acct:
            findings.append(Finding(
                layer=12, scanner="cloud_scanner",
                file=str_filepath, line=_find_line(content, _GCP_VERTEX_IMPORT),
                severity=Severity.MEDIUM, dimension="D4",
                message="GCP Vertex AI without explicit service_account or credentials — relying on ambient auth",
                remediation="Pass service_account or credentials parameter for explicit IAM scoping",
                compliance=ComplianceMapping(owasp_llm="LLM06"),
            ))

        if has_gen_model and not has_safety:
            findings.append(Finding(
                layer=12, scanner="cloud_scanner",
                file=str_filepath, line=_find_line(content, _GCP_GENERATIVE_MODEL),
                severity=Severity.HIGH, dimension="D10",
                message="GCP GenerativeModel without safety_settings — no harm category filtering",
                remediation="Add safety_settings with HarmCategory and HarmBlockThreshold to GenerativeModel",
                compliance=ComplianceMapping(eu_ai_act="Article 15", owasp_llm="LLM02"),
            ))

    # --- Generic cloud AI checks (apply to any file) ---

    if _HARDCODED_ENDPOINT.search(content):
        findings.append(Finding(
            layer=12, scanner="cloud_scanner",
            file=str_filepath, line=_find_line(content, _HARDCODED_ENDPOINT),
            severity=Severity.MEDIUM, dimension="D1",
            message="Cloud AI endpoint URL hardcoded in source — hinders environment portability",
            remediation="Move AI service endpoints to environment variables or configuration files",
            compliance=ComplianceMapping(owasp_llm="LLM06"),
        ))

    if _PROVIDER_URL_SAME_LINE_KEY.search(content):
        findings.append(Finding(
            layer=12, scanner="cloud_scanner",
            file=str_filepath, line=_find_line(content, _PROVIDER_URL_SAME_LINE_KEY),
            severity=Severity.CRITICAL, dimension="D4",
            message="API key appears alongside cloud AI provider URL — credential in source code",
            remediation="Remove API keys from source; use secrets manager, env vars, or managed identity",
            compliance=ComplianceMapping(eu_ai_act="Article 15", owasp_llm="LLM06"),
        ))

    return findings, providers, gov_signals, cred_signals


def _find_line(content: str, pattern: re.Pattern[str]) -> int:
    """Find the line number of the first match, or 1 if not found."""
    match = pattern.search(content)
    if match:
        return content[: match.start()].count("\n") + 1
    return 1


def _calculate_scores(
    findings: list[Finding],
    providers_detected: set[str],
    governance_signals: int,
    credential_signals: int,
) -> dict[str, int]:
    """Score dimensions D4, D10, D11 based on cloud AI governance."""
    scores: dict[str, int] = {}

    if not providers_detected:
        return scores

    d4_deductions = sum(1 for f in findings if f.dimension == "D4")
    d10_deductions = sum(1 for f in findings if f.dimension == "D10")
    d11_deductions = sum(1 for f in findings if f.dimension == "D11")

    # D10: Prompt Security — max contribution 3
    # Content safety clients, guardrails, filtering
    d10_base = min(governance_signals, 4)
    d10 = min(d10_base, 3)
    d10 = max(0, d10 - d10_deductions)
    scores["D10"] = min(d10, 3)

    # D11: Cloud/Platform — max contribution 4
    # Provider coverage + governance signals
    d11_base = min(len(providers_detected), 2) + min(governance_signals, 3)
    d11 = min(d11_base, 4)
    d11 = max(0, d11 - d11_deductions)
    scores["D11"] = min(d11, 4)

    # D4: Credential Management — deductions for hardcoded keys, bonus for managed identity
    d4_base = min(credential_signals, 3)
    d4 = max(0, d4_base - d4_deductions)
    scores["D4"] = min(d4, 3)

    return scores
