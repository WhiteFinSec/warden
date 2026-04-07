"""Layer 9: Infrastructure as Code Security — Terraform file analysis."""

from __future__ import annotations

import os
import re
from pathlib import Path

from warden.models import ComplianceMapping, Finding, Severity
from warden.scanner._common import SKIP_DIRS

# --- Patterns ---

_S3_BUCKET = re.compile(r'resource\s+"aws_s3_bucket"\s+"(\w+)"')
_S3_ENCRYPTION = re.compile(r"server_side_encryption_configuration")
_SG_RESOURCE = re.compile(r'resource\s+"aws_security_group"\s+"(\w+)"')
_OPEN_INGRESS = re.compile(r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]')
_IAM_POLICY = re.compile(r'resource\s+"aws_iam_policy"\s+"(\w+)"')
_WILDCARD_ACTION = re.compile(r'"Action"\s*:\s*"\*"')
_BACKEND_BLOCK = re.compile(r'backend\s+"(s3|gcs|azurerm|consul|http)"')
_REQUIRED_PROVIDERS = re.compile(r"required_providers\s*\{")
_PROVIDER_VERSION = re.compile(r'version\s*=\s*"[~><=!]+')



def scan_iac(target: Path) -> tuple[list[Finding], dict[str, int]]:
    """Layer 9: Scan Infrastructure as Code (Terraform) for security issues.

    Returns (findings, raw_dimension_scores).
    """
    findings: list[Finding] = []

    tf_files = _find_tf_files(target)
    if not tf_files:
        return findings, {}

    # Concatenate all TF content for project-level checks
    all_content = ""
    for tf_file in tf_files:
        file_findings, content = _analyze_tf_file(tf_file)
        findings.extend(file_findings)
        all_content += content + "\n"

    # Project-level checks
    findings.extend(_check_project_level(target, tf_files, all_content))

    scores = _calculate_scores(findings, tf_files)
    return findings, scores


def _find_tf_files(target: Path) -> list[Path]:
    """Find Terraform (.tf) files using os.walk with skip_dirs pruning."""
    results: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            if fname.endswith(".tf"):
                results.append(Path(dirpath) / fname)
    return results


def _analyze_tf_file(filepath: Path) -> tuple[list[Finding], str]:
    """Analyze a single Terraform file. Returns (findings, content)."""
    findings: list[Finding] = []
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return findings, ""

    # Check: S3 buckets without encryption
    for match in _S3_BUCKET.finditer(content):
        bucket_name = match.group(1)
        # Look for encryption config in the same block (rough heuristic: next 30 lines)
        start_pos = match.start()
        block_end = _find_block_end(content, start_pos)
        block_text = content[start_pos:block_end]
        if not _S3_ENCRYPTION.search(block_text):
            line_num = content[:start_pos].count("\n") + 1
            findings.append(Finding(
                layer=9, scanner="iac_scanner",
                file=str(filepath), line=line_num,
                severity=Severity.HIGH, dimension="D4",
                message=f"S3 bucket '{bucket_name}' without server-side encryption",
                remediation="Add server_side_encryption_configuration block with AES256 or aws:kms",
                compliance=ComplianceMapping(
                    owasp_llm="LLM09",
                    eu_ai_act="Article 15",
                ),
            ))

    # Check: Security groups with open ingress (0.0.0.0/0)
    for match in _SG_RESOURCE.finditer(content):
        sg_name = match.group(1)
        start_pos = match.start()
        block_end = _find_block_end(content, start_pos)
        block_text = content[start_pos:block_end]
        if _OPEN_INGRESS.search(block_text):
            line_num = content[:start_pos].count("\n") + 1
            findings.append(Finding(
                layer=9, scanner="iac_scanner",
                file=str(filepath), line=line_num,
                severity=Severity.CRITICAL, dimension="D9",
                message=f"Security group '{sg_name}' allows ingress from 0.0.0.0/0",
                remediation="Restrict cidr_blocks to specific IP ranges or use VPC-internal CIDRs",
                compliance=ComplianceMapping(owasp_llm="LLM09", mitre_atlas="AML.T0024"),
            ))

    # Check: IAM policies with wildcard actions
    for match in _IAM_POLICY.finditer(content):
        policy_name = match.group(1)
        start_pos = match.start()
        block_end = _find_block_end(content, start_pos)
        block_text = content[start_pos:block_end]
        if _WILDCARD_ACTION.search(block_text):
            line_num = content[:start_pos].count("\n") + 1
            findings.append(Finding(
                layer=9, scanner="iac_scanner",
                file=str(filepath), line=line_num,
                severity=Severity.CRITICAL, dimension="D4",
                message=f"IAM policy '{policy_name}' grants wildcard Action: * — overly permissive",
                remediation="Follow least-privilege: specify exact actions needed (e.g., s3:GetObject)",
                compliance=ComplianceMapping(
                    owasp_llm="LLM09",
                    eu_ai_act="Article 15",
                ),
            ))

    return findings, content


def _check_project_level(
    target: Path,
    tf_files: list[Path],
    all_content: str,
) -> list[Finding]:
    """Project-level Terraform checks across all files."""
    findings: list[Finding] = []

    # Check: no remote backend (local state = security risk)
    if not _BACKEND_BLOCK.search(all_content):
        findings.append(Finding(
            layer=9, scanner="iac_scanner",
            file=str(tf_files[0]), line=1,
            severity=Severity.HIGH, dimension="D4",
            message="No remote backend configured — Terraform state stored locally",
            remediation='Add backend "s3" or backend "gcs" in a terraform {} block for shared state',
            compliance=ComplianceMapping(owasp_llm="LLM09"),
        ))

    # Check: no required_providers with version constraints
    if not _REQUIRED_PROVIDERS.search(all_content):
        findings.append(Finding(
            layer=9, scanner="iac_scanner",
            file=str(tf_files[0]), line=1,
            severity=Severity.MEDIUM, dimension="D9",
            message="No required_providers block — provider versions not pinned",
            remediation="Add required_providers with version constraints to prevent supply-chain drift",
        ))
    elif not _PROVIDER_VERSION.search(all_content):
        findings.append(Finding(
            layer=9, scanner="iac_scanner",
            file=str(tf_files[0]), line=1,
            severity=Severity.MEDIUM, dimension="D9",
            message="required_providers block exists but no version constraints set",
            remediation='Pin provider versions: version = "~> 5.0" to prevent unexpected upgrades',
        ))

    return findings


def _find_block_end(content: str, start: int) -> int:
    """Find the end of an HCL block starting at the first '{' after start.

    Simple brace-matching heuristic — sufficient for single-resource blocks.
    """
    depth = 0
    i = content.find("{", start)
    if i == -1:
        return min(start + 500, len(content))
    while i < len(content):
        if content[i] == "{":
            depth += 1
        elif content[i] == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(content)


def _calculate_scores(findings: list[Finding], tf_files: list[Path]) -> dict[str, int]:
    """Score dimensions D4 and D9 based on IaC governance signals."""
    scores: dict[str, int] = {}

    if not tf_files:
        return scores

    d4_deductions = sum(1 for f in findings if f.dimension == "D4")
    d9_deductions = sum(1 for f in findings if f.dimension == "D9")

    # D4: Credential Management — max contribution 3
    scores["D4"] = max(0, 3 - d4_deductions)

    # D9: Threat Detection — max contribution 3
    scores["D9"] = max(0, 3 - d9_deductions)

    return scores
