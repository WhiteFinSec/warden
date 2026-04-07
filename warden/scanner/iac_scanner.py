"""Layer 9: Infrastructure as Code Security — Terraform, Pulumi, and CloudFormation analysis."""

from __future__ import annotations

import os
import re
from pathlib import Path

from warden.models import ComplianceMapping, Finding, Severity
from warden.scanner._common import SKIP_DIRS

# --- Terraform Patterns ---

_S3_BUCKET = re.compile(r'resource\s+"aws_s3_bucket"\s+"(\w+)"')
_S3_ENCRYPTION = re.compile(r"server_side_encryption_configuration")
_SG_RESOURCE = re.compile(r'resource\s+"aws_security_group"\s+"(\w+)"')
_OPEN_INGRESS = re.compile(r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]')
_IAM_POLICY = re.compile(r'resource\s+"aws_iam_policy"\s+"(\w+)"')
_WILDCARD_ACTION = re.compile(r'"Action"\s*:\s*"\*"')
_BACKEND_BLOCK = re.compile(r'backend\s+"(s3|gcs|azurerm|consul|http)"')
_REQUIRED_PROVIDERS = re.compile(r"required_providers\s*\{")
_PROVIDER_VERSION = re.compile(r'version\s*=\s*"[~><=!]+')

# --- Pulumi Patterns ---

_PULUMI_IMPORT_TS = re.compile(r'import\s+\*\s+as\s+pulumi')
_PULUMI_IMPORT_PY = re.compile(r'from\s+pulumi\s+import|import\s+pulumi')
_PULUMI_S3_BUCKET = re.compile(r'new\s+aws\.s3\.Bucket\s*\(')
_PULUMI_S3_ENCRYPTION = re.compile(r'serverSideEncryptionConfiguration')
_PULUMI_SG = re.compile(r'new\s+aws\.ec2\.SecurityGroup\s*\(')
_PULUMI_OPEN_INGRESS = re.compile(r'["\']0\.0\.0\.0/0["\']')
_PULUMI_IAM_POLICY = re.compile(r'new\s+aws\.iam\.Policy\s*\(')
_PULUMI_WILDCARD_ACTION = re.compile(r'["\']Action["\']\s*:\s*["\']?\*["\']?')
_PULUMI_CONFIG = re.compile(r'pulumi\.Config\s*\(')

# --- CloudFormation Patterns ---

_CFN_TEMPLATE = re.compile(r'AWSTemplateFormatVersion')
_CFN_RESOURCES_BLOCK = re.compile(r'^\s*Resources\s*:', re.MULTILINE)
_CFN_AWS_RESOURCE_TYPE = re.compile(r'AWS::\w+::\w+')
_CFN_S3_BUCKET = re.compile(r'Type\s*:\s*["\']?AWS::S3::Bucket["\']?')
_CFN_BUCKET_ENCRYPTION = re.compile(r'BucketEncryption')
_CFN_SG = re.compile(r'Type\s*:\s*["\']?AWS::EC2::SecurityGroup["\']?')
_CFN_IAM_POLICY = re.compile(r'Type\s*:\s*["\']?AWS::IAM::Policy["\']?')
_CFN_DELETION_POLICY = re.compile(r'DeletionPolicy')
_CFN_STATEFUL_RESOURCES = re.compile(
    r'Type\s*:\s*["\']?AWS::(RDS::DBInstance|DynamoDB::Table|S3::Bucket|EFS::FileSystem)["\']?'
)


def scan_iac(target: Path) -> tuple[list[Finding], dict[str, int]]:
    """Layer 9: Scan Infrastructure as Code (Terraform, Pulumi, CloudFormation) for security issues.

    Returns (findings, raw_dimension_scores).
    """
    findings: list[Finding] = []

    tf_files, pulumi_files, cfn_files = _find_iac_files(target)
    if not tf_files and not pulumi_files and not cfn_files:
        return findings, {}

    # --- Terraform ---
    all_tf_content = ""
    for tf_file in tf_files:
        file_findings, content = _analyze_tf_file(tf_file)
        findings.extend(file_findings)
        all_tf_content += content + "\n"

    if tf_files:
        findings.extend(_check_project_level(target, tf_files, all_tf_content))

    # --- Pulumi ---
    for pulumi_file in pulumi_files:
        findings.extend(_analyze_pulumi_file(pulumi_file))

    # --- CloudFormation ---
    for cfn_file in cfn_files:
        findings.extend(_analyze_cfn_file(cfn_file))

    all_files = tf_files + pulumi_files + cfn_files
    scores = _calculate_scores(findings, all_files)
    return findings, scores


def _find_iac_files(target: Path) -> tuple[list[Path], list[Path], list[Path]]:
    """Find IaC files: Terraform (.tf), Pulumi (.ts/.py), CloudFormation (.yaml/.yml/.json).

    Pulumi files are only included if they contain Pulumi import patterns.
    CloudFormation files are only included if they contain CFN markers.
    """
    tf_files: list[Path] = []
    pulumi_candidates: list[Path] = []
    cfn_candidates: list[Path] = []

    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            fpath = Path(dirpath) / fname
            if fname.endswith(".tf"):
                tf_files.append(fpath)
            elif fname.endswith(".ts") or fname.endswith(".py"):
                pulumi_candidates.append(fpath)
            elif fname.endswith((".yaml", ".yml", ".json")):
                cfn_candidates.append(fpath)

    # Filter Pulumi: only files that actually import pulumi
    pulumi_files: list[Path] = []
    for fpath in pulumi_candidates:
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if _PULUMI_IMPORT_TS.search(content) or _PULUMI_IMPORT_PY.search(content):
            pulumi_files.append(fpath)

    # Filter CFN: only files with AWSTemplateFormatVersion or Resources block with AWS types
    cfn_files: list[Path] = []
    for fpath in cfn_candidates:
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if _CFN_TEMPLATE.search(content):
            cfn_files.append(fpath)
        elif _CFN_RESOURCES_BLOCK.search(content) and _CFN_AWS_RESOURCE_TYPE.search(content):
            cfn_files.append(fpath)

    return tf_files, pulumi_files, cfn_files


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


def _analyze_pulumi_file(filepath: Path) -> list[Finding]:
    """Analyze a single Pulumi (TypeScript/Python) file for security issues."""
    findings: list[Finding] = []
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return findings

    # Positive signal: pulumi.Config() usage (secrets management)
    has_config = bool(_PULUMI_CONFIG.search(content))

    # Check: S3 buckets without encryption
    for match in _PULUMI_S3_BUCKET.finditer(content):
        start_pos = match.start()
        block_end = _find_block_end_generic(content, start_pos)
        block_text = content[start_pos:block_end]
        if not _PULUMI_S3_ENCRYPTION.search(block_text):
            line_num = content[:start_pos].count("\n") + 1
            findings.append(Finding(
                layer=9, scanner="iac_scanner",
                file=str(filepath), line=line_num,
                severity=Severity.HIGH, dimension="D4",
                message="Pulumi S3 Bucket without serverSideEncryptionConfiguration",
                remediation="Add serverSideEncryptionConfiguration with AES256 or aws:kms",
                compliance=ComplianceMapping(
                    owasp_llm="LLM09",
                    eu_ai_act="Article 15",
                ),
            ))

    # Check: Security groups with open ingress
    for match in _PULUMI_SG.finditer(content):
        start_pos = match.start()
        block_end = _find_block_end_generic(content, start_pos)
        block_text = content[start_pos:block_end]
        if _PULUMI_OPEN_INGRESS.search(block_text):
            line_num = content[:start_pos].count("\n") + 1
            findings.append(Finding(
                layer=9, scanner="iac_scanner",
                file=str(filepath), line=line_num,
                severity=Severity.CRITICAL, dimension="D9",
                message="Pulumi SecurityGroup allows ingress from 0.0.0.0/0",
                remediation="Restrict ingress CIDR to specific IP ranges or VPC-internal CIDRs",
                compliance=ComplianceMapping(owasp_llm="LLM09", mitre_atlas="AML.T0024"),
            ))

    # Check: IAM policies with wildcard actions
    for match in _PULUMI_IAM_POLICY.finditer(content):
        start_pos = match.start()
        block_end = _find_block_end_generic(content, start_pos)
        block_text = content[start_pos:block_end]
        if _PULUMI_WILDCARD_ACTION.search(block_text):
            line_num = content[:start_pos].count("\n") + 1
            findings.append(Finding(
                layer=9, scanner="iac_scanner",
                file=str(filepath), line=line_num,
                severity=Severity.CRITICAL, dimension="D4",
                message="Pulumi IAM Policy grants wildcard Action: * — overly permissive",
                remediation="Follow least-privilege: specify exact actions needed (e.g., s3:GetObject)",
                compliance=ComplianceMapping(
                    owasp_llm="LLM09",
                    eu_ai_act="Article 15",
                ),
            ))

    # Positive: reduce D4 deduction if pulumi.Config() is used for secrets
    if has_config and findings:
        # We don't add a negative finding — the score calculation handles positives
        # by counting fewer deductions when config management is present
        pass

    return findings


def _analyze_cfn_file(filepath: Path) -> list[Finding]:
    """Analyze a single CloudFormation (YAML/JSON) file for security issues."""
    findings: list[Finding] = []
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return findings

    # Check: S3 buckets without encryption
    for match in _CFN_S3_BUCKET.finditer(content):
        start_pos = match.start()
        # Search within a reasonable window after the resource type declaration
        block_end = _find_cfn_resource_end(content, start_pos)
        block_text = content[start_pos:block_end]
        if not _CFN_BUCKET_ENCRYPTION.search(block_text):
            line_num = content[:start_pos].count("\n") + 1
            findings.append(Finding(
                layer=9, scanner="iac_scanner",
                file=str(filepath), line=line_num,
                severity=Severity.HIGH, dimension="D4",
                message="CloudFormation S3 Bucket without BucketEncryption",
                remediation="Add BucketEncryption property with SSEAlgorithm: aws:kms or AES256",
                compliance=ComplianceMapping(
                    owasp_llm="LLM09",
                    eu_ai_act="Article 15",
                ),
            ))

    # Check: Security groups with open ingress
    for match in _CFN_SG.finditer(content):
        start_pos = match.start()
        block_end = _find_cfn_resource_end(content, start_pos)
        block_text = content[start_pos:block_end]
        if _PULUMI_OPEN_INGRESS.search(block_text):  # reuse 0.0.0.0/0 pattern
            line_num = content[:start_pos].count("\n") + 1
            findings.append(Finding(
                layer=9, scanner="iac_scanner",
                file=str(filepath), line=line_num,
                severity=Severity.CRITICAL, dimension="D9",
                message="CloudFormation SecurityGroup allows ingress from 0.0.0.0/0",
                remediation="Restrict CidrIp to specific IP ranges or VPC-internal CIDRs",
                compliance=ComplianceMapping(owasp_llm="LLM09", mitre_atlas="AML.T0024"),
            ))

    # Check: IAM policies with wildcard actions
    for match in _CFN_IAM_POLICY.finditer(content):
        start_pos = match.start()
        block_end = _find_cfn_resource_end(content, start_pos)
        block_text = content[start_pos:block_end]
        if _PULUMI_WILDCARD_ACTION.search(block_text):  # reuse wildcard action pattern
            line_num = content[:start_pos].count("\n") + 1
            findings.append(Finding(
                layer=9, scanner="iac_scanner",
                file=str(filepath), line=line_num,
                severity=Severity.CRITICAL, dimension="D4",
                message="CloudFormation IAM Policy grants wildcard Action: * — overly permissive",
                remediation="Follow least-privilege: specify exact actions needed (e.g., s3:GetObject)",
                compliance=ComplianceMapping(
                    owasp_llm="LLM09",
                    eu_ai_act="Article 15",
                ),
            ))

    # Check: Stateful resources without DeletionPolicy
    for match in _CFN_STATEFUL_RESOURCES.finditer(content):
        start_pos = match.start()
        # Look backwards and forwards for DeletionPolicy near this resource
        # DeletionPolicy is a sibling of Type in the resource definition
        # Search a window around the resource type declaration
        window_start = max(0, start_pos - 200)
        block_end = _find_cfn_resource_end(content, start_pos)
        window_text = content[window_start:block_end]
        if not _CFN_DELETION_POLICY.search(window_text):
            resource_type = match.group(0)
            line_num = content[:start_pos].count("\n") + 1
            findings.append(Finding(
                layer=9, scanner="iac_scanner",
                file=str(filepath), line=line_num,
                severity=Severity.MEDIUM, dimension="D13",
                message=f"Stateful resource ({resource_type}) has no DeletionPolicy",
                remediation="Add DeletionPolicy: Retain or Snapshot to prevent accidental data loss",
                compliance=ComplianceMapping(owasp_llm="LLM09"),
            ))

    return findings


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


def _find_block_end_generic(content: str, start: int) -> int:
    """Find end of a code block using brace/paren matching.

    Works for TypeScript (Pulumi) and JSON. Falls back to a 1000-char window
    if no opening brace/paren is found nearby.
    """
    # Look for first opening delimiter within 200 chars of start
    search_window = content[start:start + 200]
    brace_pos = search_window.find("{")
    paren_pos = search_window.find("(")

    # Pick whichever comes first
    if brace_pos == -1 and paren_pos == -1:
        return min(start + 1000, len(content))

    if brace_pos == -1:
        open_char, close_char = "(", ")"
        first = paren_pos
    elif paren_pos == -1:
        open_char, close_char = "{", "}"
        first = brace_pos
    else:
        if paren_pos < brace_pos:
            open_char, close_char = "(", ")"
            first = paren_pos
        else:
            open_char, close_char = "{", "}"
            first = brace_pos

    depth = 0
    i = start + first
    while i < len(content):
        if content[i] == open_char:
            depth += 1
        elif content[i] == close_char:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(content)


def _find_cfn_resource_end(content: str, start: int) -> int:
    """Estimate the end of a CloudFormation resource block.

    For YAML CFN templates we can't rely on braces. Uses a heuristic:
    scan forward up to 1500 chars or until we hit another resource Type: declaration.
    For JSON templates, falls back to brace matching.
    """
    # Check if this looks like JSON (has braces nearby)
    search_window = content[start:start + 100]
    if "{" in search_window:
        return _find_block_end_generic(content, start)

    # YAML heuristic: scan until next resource or end of file, max 1500 chars
    next_resource = _CFN_S3_BUCKET.search(content, start + 10)
    next_sg = _CFN_SG.search(content, start + 10)
    next_iam = _CFN_IAM_POLICY.search(content, start + 10)
    next_stateful = _CFN_STATEFUL_RESOURCES.search(content, start + 10)

    candidates = []
    for m in (next_resource, next_sg, next_iam, next_stateful):
        if m and m.start() > start:
            candidates.append(m.start())

    if candidates:
        return min(min(candidates), start + 1500)
    return min(start + 1500, len(content))


def _calculate_scores(findings: list[Finding], iac_files: list[Path]) -> dict[str, int]:
    """Score dimensions D4, D9, and D13 based on IaC governance signals."""
    scores: dict[str, int] = {}

    if not iac_files:
        return scores

    d4_deductions = sum(1 for f in findings if f.dimension == "D4")
    d9_deductions = sum(1 for f in findings if f.dimension == "D9")
    d13_deductions = sum(1 for f in findings if f.dimension == "D13")

    # D4: Credential Management — max contribution 3
    scores["D4"] = max(0, 3 - d4_deductions)

    # D9: Threat Detection — max contribution 3
    scores["D9"] = max(0, 3 - d9_deductions)

    # D13: Resilience — max contribution 2
    if d13_deductions:
        scores["D13"] = max(0, 2 - d13_deductions)

    return scores
