"""Layer 4: Secrets & credential detection.

CRITICAL: Values are NEVER stored. Only file, line number, pattern name,
and preview (first 3 + last 4 chars of the match).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from warden.models import ComplianceMapping, Finding, SecretMatch, Severity
from warden.scanner._common import SKIP_DIRS


@dataclass(frozen=True)
class SecretPattern:
    name: str
    regex: re.Pattern[str]
    severity: Severity

    def __init__(self, name: str, pattern: str, severity: str):
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "regex", re.compile(pattern))
        object.__setattr__(self, "severity", Severity(severity))


SECRET_PATTERNS = [
    SecretPattern("OpenAI API Key",      r"sk-[a-zA-Z0-9]{20,}",                          "CRITICAL"),
    SecretPattern("Anthropic API Key",   r"sk-ant-[a-zA-Z0-9\-]{20,}",                    "CRITICAL"),
    SecretPattern("Google API Key",      r"AIza[0-9A-Za-z\-_]{35}",                        "CRITICAL"),
    SecretPattern("AWS Access Key",      r"AKIA[0-9A-Z]{16}",                              "CRITICAL"),
    SecretPattern(
        "AWS Secret Key",
        r"(?:aws_secret|AWS_SECRET|secret_access_key)\s*[=:]\s*['\"]?[0-9a-zA-Z/+]{40}",
        "HIGH",
    ),
    SecretPattern("GitHub Token",        r"gh[ps]_[A-Za-z0-9_]{36,}",                      "HIGH"),
    SecretPattern("Groq API Key",        r"gsk_[a-zA-Z0-9]{20,}",                          "CRITICAL"),
    SecretPattern("HuggingFace Token",   r"hf_[a-zA-Z0-9]{20,}",                           "HIGH"),
    SecretPattern("Slack Token",         r"xox[bpors]-[0-9a-zA-Z\-]+",                     "HIGH"),
    SecretPattern(
        "Database URL with credentials",
        r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:/@\s]+:[^/@\s]+@[^\s\"']+",
        "CRITICAL",
    ),
    SecretPattern(
        "Database URL (no credentials)",
        r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://(?![^:/@\s]+:[^/@\s]+@)[^\s\"']+",
        "MEDIUM",
    ),
    SecretPattern("Private Key",         r"-----BEGIN (?:RSA|EC|OPENSSH) PRIVATE KEY-----", "CRITICAL"),
    SecretPattern("JWT Secret",          r"(?:jwt[_\-]?secret|JWT_SECRET)\s*[=:]\s*['\"][^'\"]+", "HIGH"),
    SecretPattern("Stripe Key",          r"sk_live_[0-9a-zA-Z]{24,}",                      "CRITICAL"),
    SecretPattern("SendGrid Key",        r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}",   "HIGH"),
    SecretPattern("Generic Secret",      r"(?:secret|password|token|api_key)\s*[=:]\s*['\"][^'\"]{8,}", "MEDIUM"),
]

# File extensions to scan
SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".yaml", ".yml",
    ".json", ".env", ".cfg", ".conf", ".ini", ".toml",
    ".sh", ".bash", ".zsh", ".ps1", ".md", ".txt",
}

# Files to always scan regardless of extension
ALWAYS_SCAN = {
    ".env", ".env.local", ".env.production", ".env.development",
    ".env.staging", ".env.test",
}

# Files to never scan
NEVER_SCAN_DIRS = SKIP_DIRS

# Files that commonly contain false-positive secret patterns
SKIP_FILENAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "poetry.lock", "Pipfile.lock", "pdm.lock", "uv.lock",
}

TEST_INDICATORS = {"test_", "_test.", ".test.", ".spec.", "fixture", "mock"}


def _mask_secret(value: str) -> str:
    """Create masked preview: first 3 + last 4 chars.

    CRITICAL: This is the ONLY representation of the secret value
    that Warden stores. The full value is never stored anywhere.
    """
    if len(value) <= 7:
        return value[:2] + "..." + value[-2:]
    return value[:3] + "..." + value[-4:]


def scan_secrets(
    target: Path,
    on_file: object = None,
) -> tuple[list[Finding], dict[str, int]]:
    """Layer 4: Scan for exposed secrets and credentials.

    Returns (findings, raw_dimension_scores).
    on_file: optional callable invoked per file scanned (for progress).
    """
    findings: list[Finding] = []
    secrets: list[SecretMatch] = []
    _progress = on_file if callable(on_file) else None

    # Build file list once, then check gitignore status.
    # Secrets in gitignored files (e.g. .env) won't leak via git — still
    # flagged but as INFO instead of CRITICAL/HIGH.
    all_files = _iter_scannable_files(target)
    gitignored = _get_gitignored_files(target, all_files)

    for filepath in all_files:
        # Skip test files — they legitimately contain fake secret patterns
        name_lower = filepath.name.lower()
        if any(ind in name_lower for ind in TEST_INDICATORS):
            continue
        parts_lower = {p.lower() for p in filepath.parts}
        if {"tests", "test", "__tests__", "fixtures"}.intersection(parts_lower):
            continue
        if filepath.name in SKIP_FILENAMES:
            continue

        file_findings, file_secrets = _scan_file(filepath)

        # Downgrade gitignored file findings to INFO — these secrets
        # exist locally but won't leak via version control.
        # Normalize path separators for cross-platform matching.
        filepath_str = str(filepath).replace("\\", "/")
        if filepath_str in gitignored or str(filepath) in gitignored:
            for f in file_findings:
                f.severity = Severity.INFO
                f.message += " (gitignored — local only, not in VCS)"
            for s in file_secrets:
                s.severity = Severity.INFO

        findings.extend(file_findings)
        secrets.extend(file_secrets)
        if _progress:
            _progress()

    scores: dict[str, int] = {}

    # D4: Credential Management — reward positive practices, not just absence.
    # "No secrets found" could mean great hygiene OR nothing to scan.
    critical_secrets = sum(1 for s in secrets if s.severity == Severity.CRITICAL)

    if critical_secrets == 0 and len(secrets) == 0:
        # Truly clean — but only modest credit; real D4 points come from
        # code_analyzer (secrets manager, key rotation, KMS patterns).
        scores["D4"] = 3
    elif critical_secrets == 0:
        scores["D4"] = 2   # Some findings but no critical exposure
    else:
        scores["D4"] = 0   # Critical secrets exposed

    return findings, scores


def _get_gitignored_files(target: Path, file_list: list[Path]) -> set[str]:
    """Check which files from file_list are gitignored.

    Uses `git check-ignore` for accuracy. Returns empty set if not a git repo
    or git is unavailable — graceful degradation, no crash.
    """
    import subprocess

    if not file_list:
        return set()

    try:
        # First check if target is in a git repo
        result = subprocess.run(
            ["git", "-C", str(target), "rev-parse", "--git-dir"],
            capture_output=True, timeout=5,
        )
        if result.returncode != 0:
            return set()

        # Batch check — git check-ignore can take multiple paths at once.
        # Process in chunks to avoid command-line length limits.
        ignored: set[str] = set()
        chunk_size = 200
        for i in range(0, len(file_list), chunk_size):
            chunk = file_list[i:i + chunk_size]
            result = subprocess.run(
                ["git", "-C", str(target), "check-ignore", "--no-index"]
                + [str(f) for f in chunk],
                capture_output=True, text=True, timeout=30,
            )
            # git check-ignore outputs one ignored path per line.
            # Normalize separators for cross-platform matching.
            for line in result.stdout.strip().splitlines():
                if line:
                    normalized = line.strip().replace("\\", "/")
                    ignored.add(normalized)
        return ignored
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return set()


def _iter_scannable_files(target: Path) -> list[Path]:
    """Iterate over files that should be scanned for secrets."""
    import os

    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in NEVER_SCAN_DIRS]
        for fname in filenames:
            if fname in SKIP_FILENAMES:
                continue
            if fname in ALWAYS_SCAN:
                files.append(Path(dirpath) / fname)
            elif Path(fname).suffix.lower() in SCAN_EXTENSIONS:
                files.append(Path(dirpath) / fname)
    return files


def _is_regex_definition(line: str, matched_value: str) -> bool:
    """Check if a matched value appears inside a regex pattern definition.

    Catches cases like:  r"postgres://\\S+"  or  re.compile("redis://.*")
    which are pattern definitions for detecting DB URLs, not actual secrets.
    """
    # Common indicators the line is defining a regex, not containing a secret
    regex_indicators = [
        r"\S+", r"\s+", r"[^", r".*", r".+", r"(?:", r"\w+",
        "re.compile", "re.search", "re.match", "re.findall",
        "Pattern(", "SecretPattern(",
    ]
    for indicator in regex_indicators:
        if indicator in line:
            return True
    return False


def _scan_file(filepath: Path) -> tuple[list[Finding], list[SecretMatch]]:
    """Scan a single file for secrets."""
    findings: list[Finding] = []
    secrets: list[SecretMatch] = []

    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return findings, secrets

    # Skip binary-looking files
    if "\x00" in content[:1000]:
        return findings, secrets

    lines = content.splitlines()
    for line_num, line in enumerate(lines, 1):
        # Skip comments
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue

        for pattern in SECRET_PATTERNS:
            match = pattern.regex.search(line)
            if match:
                matched_value = match.group(0)
                # Skip regex pattern definitions (contain regex metacharacters
                # around the matched value — these define detection rules, not secrets)
                if _is_regex_definition(line, matched_value):
                    continue
                preview = _mask_secret(matched_value)

                secret = SecretMatch(
                    file=str(filepath),
                    line=line_num,
                    pattern_name=pattern.name,
                    preview=preview,
                    severity=pattern.severity,
                )
                secrets.append(secret)

                findings.append(Finding(
                    layer=4, scanner="secrets_scanner",
                    file=str(filepath), line=line_num,
                    severity=pattern.severity, dimension="D4",
                    message=f"Exposed {pattern.name}: {preview}",
                    remediation="Move to secrets manager or .env file (excluded from VCS)",
                    compliance=ComplianceMapping(
                        eu_ai_act="Article 15",
                        owasp_llm="LLM09",
                    ),
                ))
                break  # One finding per line

    return findings, secrets


def _should_skip(filepath: Path) -> bool:
    parts = set(filepath.parts)
    return bool(NEVER_SCAN_DIRS.intersection(parts))
