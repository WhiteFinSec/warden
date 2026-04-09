"""Layer 6: Supply chain / dependency analysis."""

from __future__ import annotations

import json
import re
from pathlib import Path

from warden.models import ComplianceMapping, Finding, Severity
from warden.scanner._common import SKIP_DIRS

# Known typosquat targets (popular AI packages)
POPULAR_PACKAGES = {
    "openai", "anthropic", "langchain", "langchain-core", "langchain-community",
    "autogen", "crewai", "llamaindex", "llama-index", "transformers",
    "torch", "tensorflow", "keras", "numpy", "pandas", "scikit-learn",
    "fastapi", "flask", "django", "requests", "httpx", "aiohttp",
    "pydantic", "sqlalchemy", "celery", "redis", "boto3",
}

# Cloud-based PII services (data leaves the machine)
CLOUD_PII_PACKAGES = {
    "nightfall": "Nightfall (cloud PII detection)",
    "private-ai": "Private AI (cloud PII detection)",
    "presidio-analyzer": "Microsoft Presidio (can use cloud models)",
}


def scan_dependencies(target: Path) -> tuple[list[Finding], dict[str, int]]:
    """Layer 6: Scan dependency files for supply chain risks.

    Returns (findings, raw_dimension_scores).
    """
    findings: list[Finding] = []

    # Python: requirements.txt, setup.py, pyproject.toml, Pipfile
    for req_file in _find_requirement_files(target):
        findings.extend(_analyze_requirements(req_file))

    # Python: lockfiles
    for lock_file in _find_lockfiles(target):
        findings.extend(_analyze_lockfile(lock_file))

    # Node: package.json
    for pkg_json in _find_files_by_name(target, "package.json"):
        findings.extend(_analyze_package_json(pkg_json))

    scores = _calculate_scores(findings, target)
    return findings, scores


def _find_files_by_name(target: Path, *names: str) -> list[Path]:
    """Walk tree once, collect files matching any of the given names."""
    import os

    name_set = set(names)
    results: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            if fname in name_set:
                results.append(Path(dirpath) / fname)
    return results


def _find_requirement_files(target: Path) -> list[Path]:
    return _find_files_by_name(
        target,
        "requirements.txt", "requirements-dev.txt", "requirements-prod.txt",
        "pyproject.toml",
    )


def _find_lockfiles(target: Path) -> list[Path]:
    return _find_files_by_name(
        target,
        "Pipfile.lock", "poetry.lock", "pdm.lock", "uv.lock",
        "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    )


def _analyze_requirements(filepath: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return findings

    if filepath.name == "pyproject.toml":
        # Parse dependencies from pyproject.toml
        deps = re.findall(r'"([a-zA-Z0-9_\-]+)(?:[><=!~].*?)?"', content)
    else:
        # requirements.txt format
        deps = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            match = re.match(r"([a-zA-Z0-9_\-]+)", line)
            if match:
                deps.append(match.group(1))

    ai_packages = {"openai", "anthropic", "langchain", "autogen", "crewai",
                   "llama-index", "llamaindex", "litellm", "together"}

    for i, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # Check for unpinned AI dependencies
        for pkg in ai_packages:
            if pkg in stripped.lower():
                if not re.search(r"[><=!~]=", stripped):
                    findings.append(Finding(
                        layer=6, scanner="dependency_scanner",
                        file=str(filepath), line=i,
                        severity=Severity.MEDIUM, dimension="D14",
                        message=f"Unpinned AI dependency: {pkg}",
                        remediation=f"Pin version: {pkg}==<specific_version>",
                    ))

    # Check for cloud PII services
    for dep in deps:
        dep_lower = dep.lower()
        if dep_lower in CLOUD_PII_PACKAGES:
            findings.append(Finding(
                layer=6, scanner="dependency_scanner",
                file=str(filepath), line=1,
                severity=Severity.MEDIUM, dimension="D5",
                message=f"Cloud-based PII service: {CLOUD_PII_PACKAGES[dep_lower]}",
                remediation="Consider local PII detection to keep data on-premise",
            ))

    # Check for typosquats
    for dep in deps:
        dep_lower = dep.lower()
        if dep_lower not in POPULAR_PACKAGES:
            for popular in POPULAR_PACKAGES:
                if _levenshtein_distance(dep_lower, popular) == 1:
                    findings.append(Finding(
                        layer=6, scanner="dependency_scanner",
                        file=str(filepath), line=1,
                        severity=Severity.CRITICAL, dimension="D4",
                        message=f"Possible typosquat: '{dep}' is 1 edit from '{popular}'",
                        remediation=f"Verify this is the intended package, not a typosquat of '{popular}'",
                        compliance=ComplianceMapping(mitre_atlas="AML.T0010"),
                    ))

    return findings


def _analyze_lockfile(filepath: Path) -> list[Finding]:
    """Analyze lockfiles for known issues."""
    # Lightweight check — full CVE scanning would require a database
    return []


def _analyze_package_json(filepath: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        content = filepath.read_text(encoding="utf-8")
        pkg = json.loads(content)
    except (json.JSONDecodeError, OSError):
        return findings

    all_deps = {}
    all_deps.update(pkg.get("dependencies", {}))
    all_deps.update(pkg.get("devDependencies", {}))

    ai_packages = {"openai", "@anthropic-ai/sdk", "langchain", "@langchain/core"}

    for dep, version in all_deps.items():
        # Unpinned AI deps
        if dep in ai_packages and version.startswith("^"):
            findings.append(Finding(
                layer=6, scanner="dependency_scanner",
                file=str(filepath), line=1,
                severity=Severity.MEDIUM, dimension="D14",
                message=f"Unpinned AI dependency: {dep}@{version}",
                remediation=f"Pin to exact version: {dep}@<exact_version>",
            ))

    return findings


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Simple Levenshtein distance for typosquat detection."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            cost = 0 if c1 == c2 else 1
            curr_row.append(min(
                curr_row[j] + 1,
                prev_row[j + 1] + 1,
                prev_row[j] + cost,
            ))
        prev_row = curr_row

    return prev_row[-1]


def _calculate_scores(findings: list[Finding], target: Path) -> dict[str, int]:
    scores: dict[str, int] = {}

    # D14: Compliance Maturity — reward positive supply-chain practices,
    # not merely "no vulnerabilities found" (absence ≠ compliance).
    d14 = 0
    has_lockfile = bool(_find_lockfiles(target))
    has_critical = any(f.severity == Severity.CRITICAL for f in findings)

    if has_lockfile and not has_critical:
        d14 = 1  # Lockfile present + no critical supply chain issues

    scores["D14"] = d14
    return scores


def _should_skip(filepath: Path) -> bool:
    parts = filepath.parts
    return bool(SKIP_DIRS.intersection(parts))
