"""Layer 3: Infrastructure analysis (Dockerfile, docker-compose, K8s manifests)."""

from __future__ import annotations

import re
from pathlib import Path

from warden.models import ComplianceMapping, Finding, Severity

API_KEY_PATTERN = re.compile(
    r"(API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY)\s*[=:]\s*\S+",
    re.IGNORECASE,
)


def scan_infra(target: Path) -> tuple[list[Finding], dict[str, int]]:
    """Layer 3: Scan infrastructure configs.

    Returns (findings, raw_dimension_scores).
    """
    findings: list[Finding] = []

    # Scan Dockerfiles
    for dockerfile in _find_files(target, ["Dockerfile", "Dockerfile.*", "*.dockerfile"]):
        findings.extend(_analyze_dockerfile(dockerfile))

    # Scan docker-compose files
    for compose in _find_files(target, ["docker-compose.yml", "docker-compose.yaml",
                                         "docker-compose.*.yml", "docker-compose.*.yaml",
                                         "compose.yml", "compose.yaml"]):
        findings.extend(_analyze_compose(compose))

    # Scan K8s manifests
    for k8s in _find_k8s_manifests(target):
        findings.extend(_analyze_k8s(k8s))

    scores = _calculate_scores(findings, target)
    return findings, scores


def _find_files(target: Path, patterns: list[str]) -> list[Path]:
    import fnmatch
    import os

    skip_dirs = {
        ".venv", "venv", "node_modules", ".git", "__pycache__",
        "dist", "build", "site-packages", "out", ".next", ".omc", ".claude",
    }
    results: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fname in filenames:
            for pattern in patterns:
                if "*" in pattern:
                    if fnmatch.fnmatch(fname, pattern):
                        results.append(Path(dirpath) / fname)
                        break
                elif fname == pattern:
                    results.append(Path(dirpath) / fname)
                    break
    return results


def _find_k8s_manifests(target: Path) -> list[Path]:
    import os

    skip_dirs = {
        ".venv", "venv", "node_modules", ".git", "__pycache__",
        "dist", "build", "site-packages", "out", ".next", ".omc", ".claude",
    }
    results: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fname in filenames:
            if not (fname.endswith(".yml") or fname.endswith(".yaml")):
                continue
            fpath = Path(dirpath) / fname
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")[:500]
                if "apiVersion:" in content and "kind:" in content:
                    results.append(fpath)
            except OSError:
                pass
    return results


def _analyze_dockerfile(filepath: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return findings

    lines = content.splitlines()

    # Check for USER directive
    has_user = any(line.strip().upper().startswith("USER ") for line in lines
                   if not line.strip().startswith("#"))
    if not has_user:
        findings.append(Finding(
            layer=3, scanner="infra_analyzer",
            file=str(filepath), line=1,
            severity=Severity.HIGH, dimension="D4",
            message="Container runs as root — no USER directive in Dockerfile",
            remediation="Add USER directive to run as non-root user",
            compliance=ComplianceMapping(owasp_llm="LLM09"),
        ))

    # Check for secrets in ENV/ARG
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if (stripped.upper().startswith("ENV ") or stripped.upper().startswith("ARG ")) and \
           API_KEY_PATTERN.search(stripped):
            findings.append(Finding(
                layer=3, scanner="infra_analyzer",
                file=str(filepath), line=i,
                severity=Severity.CRITICAL, dimension="D4",
                message="Secret value in Dockerfile ENV/ARG",
                remediation="Use Docker secrets or environment injection at runtime",
            ))

    return findings


def _analyze_compose(filepath: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return findings

    lines = content.splitlines()

    # Check for secrets in environment
    for i, line in enumerate(lines, 1):
        if API_KEY_PATTERN.search(line) and "environment" not in line.lower():
            # Only flag if it looks like a value assignment, not a reference
            if "=${" not in line and "$" not in line.split("=", 1)[-1] if "=" in line else True:
                findings.append(Finding(
                    layer=3, scanner="infra_analyzer",
                    file=str(filepath), line=i,
                    severity=Severity.CRITICAL, dimension="D4",
                    message="Secret value in docker-compose environment",
                    remediation="Use .env file or Docker secrets, not inline values",
                ))

    # Check for custom networks
    has_networks = "networks:" in content
    if not has_networks and "services:" in content:
        findings.append(Finding(
            layer=3, scanner="infra_analyzer",
            file=str(filepath), line=1,
            severity=Severity.HIGH, dimension="D4",
            message="No custom network — all services on default bridge network",
            remediation="Define custom networks to isolate services",
        ))

    # Check for healthchecks
    if "services:" in content and "healthcheck:" not in content:
        findings.append(Finding(
            layer=3, scanner="infra_analyzer",
            file=str(filepath), line=1,
            severity=Severity.MEDIUM, dimension="D9",
            message="No healthcheck defined for any service",
            remediation="Add healthcheck sections to critical services",
        ))

    # Check for resource limits
    if "services:" in content and not any(k in content for k in ("mem_limit", "cpus:", "resources:", "deploy:")):
        findings.append(Finding(
            layer=3, scanner="infra_analyzer",
            file=str(filepath), line=1,
            severity=Severity.MEDIUM, dimension="D9",
            message="No resource limits defined — services can consume unlimited resources",
            remediation="Add CPU/memory limits to services",
        ))

    return findings


def _analyze_k8s(filepath: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return findings

    # Check for resource limits in K8s
    if "kind: Deployment" in content or "kind: Pod" in content:
        if "resources:" not in content:
            findings.append(Finding(
                layer=3, scanner="infra_analyzer",
                file=str(filepath), line=1,
                severity=Severity.MEDIUM, dimension="D9",
                message="Kubernetes deployment without resource limits",
                remediation="Add resources.limits and resources.requests",
            ))

        if "securityContext:" not in content:
            findings.append(Finding(
                layer=3, scanner="infra_analyzer",
                file=str(filepath), line=1,
                severity=Severity.HIGH, dimension="D4",
                message="Kubernetes deployment without securityContext",
                remediation="Add securityContext with runAsNonRoot: true",
            ))

    return findings


def _calculate_scores(findings: list[Finding], target: Path) -> dict[str, int]:
    scores: dict[str, int] = {}

    # Check for infra governance signals
    has_dockerfile = bool(_find_files(target, ["Dockerfile"]))
    has_compose = bool(_find_files(target, ["docker-compose.yml", "compose.yml"]))
    has_k8s = bool(_find_k8s_manifests(target))

    d4_deductions = sum(1 for f in findings if f.dimension == "D4")
    d9_deductions = sum(1 for f in findings if f.dimension == "D9")

    if has_dockerfile or has_compose or has_k8s:
        scores["D4"] = max(0, 6 - d4_deductions * 2)
        scores["D9"] = max(0, 4 - d9_deductions)

    return scores


def _should_skip(filepath: Path) -> bool:
    parts = filepath.parts
    skip_dirs = {
        ".venv", "venv", "node_modules", ".git", "__pycache__",
        "dist", "build", "site-packages", "out", ".next", ".omc", ".claude",
    }
    return bool(skip_dirs.intersection(parts))
