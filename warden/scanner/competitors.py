"""Competitor detection registry — 17 tools across 5 signal layers.

Detection requires 2+ signals from different layers to classify as "present."
Single-signal matches are confidence: "low" and do NOT trigger GTM routing.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from warden.scanner._common import SKIP_DIRS

from warden.models import CompetitorMatch


@dataclass(frozen=True)
class CompetitorProfile:
    id: str
    display_name: str
    category: str
    env_vars: list[str] = field(default_factory=list)
    packages: list[str] = field(default_factory=list)
    processes: list[str] = field(default_factory=list)
    docker_images: list[str] = field(default_factory=list)
    config_files: list[str] = field(default_factory=list)
    code_patterns: list[str] = field(default_factory=list)
    warden_score: int = 0
    strengths: list[str] = field(default_factory=list)
    weaknesses: list[str] = field(default_factory=list)
    gtm_signal: str = ""


COMPETITORS: dict[str, CompetitorProfile] = {
    "sharkrouter": CompetitorProfile(
        id="sharkrouter", display_name="SharkRouter", category="TOOL_CALL_GATEWAY",
        env_vars=["SHARK_API_KEY", "SHARKROUTER_URL", "SHARK_ADMIN_KEY"],
        packages=["sharkrouter-sdk"],
        processes=["sharkrouter-server", "shark-proxy"],
        docker_images=["sharkrouter/gateway"],
        config_files=["sharkrouter.yaml", ".sharkrc"],
        code_patterns=[r"base_url.*sharkrouter", r"shark.*proxy"],
        warden_score=91,
        strengths=["Inline tool-call enforcement", "Agent Passport", "Dry-Run Preview",
                   "Post-exec verification", "Trap defense"],
        gtm_signal="existing_customer",
    ),
    "zenity": CompetitorProfile(
        id="zenity", display_name="Zenity", category="AI_SECURITY_POSTURE",
        env_vars=["ZENITY_API_KEY", "ZENITY_TOKEN"],
        packages=["zenity-sdk"], processes=["zenity-agent"],
        docker_images=["zenity/scanner"], config_files=[".zenity.yaml"],
        code_patterns=[r"zenity\.observe", r"zenity\.govern"],
        warden_score=48,
        strengths=["Shadow AI discovery", "Endpoint observability", "Posture management"],
        weaknesses=["Out-of-band (cannot block)", "No tool call enforcement"],
        gtm_signal="warm_governance_aware",
    ),
    "oasis": CompetitorProfile(
        id="oasis", display_name="Oasis Security", category="NHI_LIFECYCLE",
        env_vars=["OASIS_API_KEY", "OASIS_TOKEN"],
        packages=["oasis-security"], processes=["oasis-agent"],
        docker_images=["oasis/scanner"], config_files=[".oasis.yaml"],
        code_patterns=[r"oasis\.access", r"oasis\.nhi"],
        warden_score=38,
        strengths=["NHI lifecycle management", "JIT access for identities"],
        weaknesses=["Pre-call only (no runtime governance)", "No tool call inspection"],
        gtm_signal="warm_jit_aware",
    ),
    "wiz": CompetitorProfile(
        id="wiz", display_name="Wiz", category="CLOUD_SECURITY",
        env_vars=["WIZ_API_KEY", "WIZ_CLIENT_ID"],
        packages=["wiz-sdk"], processes=["wiz-sensor"],
        docker_images=["wizsecurity/sensor"],
        code_patterns=[r"wiz\.security", r"wizcli"],
        warden_score=41,
        strengths=["Cloud posture", "AI-SPM", "Security Graph", "Container scanning"],
        weaknesses=["Scan-time only (no runtime)", "No tool call governance"],
        gtm_signal="warm_cloud_security",
    ),
    "portkey": CompetitorProfile(
        id="portkey", display_name="Portkey", category="LLM_GATEWAY",
        env_vars=["PORTKEY_API_KEY", "PORTKEY_VIRTUAL_KEY"],
        packages=["portkey-ai"], processes=["portkey-gateway"],
        docker_images=["portkeyai/gateway"],
        config_files=["portkey.yaml", ".portkey"],
        code_patterns=[r"portkey\.ai", r"PORTKEY_GATEWAY"],
        warden_score=24,
        strengths=["200+ model routing", "Cost observability", "Rate limiting", "Caching"],
        weaknesses=["No security enforcement", "No tool call governance", "Routing layer only"],
        gtm_signal="warm_gateway_user",
    ),
    "lakera": CompetitorProfile(
        id="lakera", display_name="Lakera", category="PROMPT_SECURITY",
        env_vars=["LAKERA_API_KEY", "LAKERA_GUARD_KEY"],
        packages=["lakera-guard"],
        code_patterns=[r"lakera\.guard", r"lakera\.api"],
        warden_score=13,
        strengths=["Prompt injection detection (80M+ trained)", "Sub-50ms latency"],
        weaknesses=["Prompt-level only", "No tool call governance", "Cloud API required"],
        gtm_signal="warm_prompt_security",
    ),
    "prompt_security": CompetitorProfile(
        id="prompt_security", display_name="Prompt Security", category="PROMPT_SECURITY",
        env_vars=["PROMPT_SECURITY_KEY"],
        packages=["prompt-security"],
        code_patterns=[r"promptsecurity", r"prompt\.security"],
        warden_score=21,
        strengths=["Input/output scanning", "SentinelOne integration"],
        weaknesses=["Prompt-level only", "No tool call enforcement"],
        gtm_signal="warm_prompt_security",
    ),
    "pangea": CompetitorProfile(
        id="pangea", display_name="Pangea / CrowdStrike", category="AI_GUARD",
        env_vars=["PANGEA_TOKEN", "PANGEA_DOMAIN"],
        packages=["pangea-sdk"],
        code_patterns=[r"pangea\.cloud", r"pangea_sdk"],
        warden_score=23,
        strengths=["AI Guard (125M param model)", "CrowdStrike EDR integration"],
        weaknesses=["Guard only (no gateway)", "No agent governance"],
        gtm_signal="warm_security_vendor",
    ),
    "noma": CompetitorProfile(
        id="noma", display_name="Noma Security", category="AI_SECURITY_POSTURE",
        env_vars=["NOMA_API_KEY"],
        packages=["noma-security"], processes=["noma-agent"],
        code_patterns=[r"noma\.security"],
        warden_score=30,
        strengths=["AI pipeline security", "Data lineage tracking"],
        weaknesses=["Posture management only", "No inline enforcement"],
        gtm_signal="warm_governance_aware",
    ),
    "kong": CompetitorProfile(
        id="kong", display_name="Kong", category="API_GATEWAY",
        env_vars=["KONG_ADMIN_TOKEN"],
        packages=["kong-pongo"], processes=["kong"],
        docker_images=["kong/kong-gateway", "kong"],
        config_files=["kong.yml", "kong.conf"],
        code_patterns=[r"kong\.service", r"kong\.plugins"],
        warden_score=27,
        strengths=["API gateway at scale", "Plugin ecosystem"],
        weaknesses=["Not AI-specific", "No tool call awareness", "No agent governance"],
        gtm_signal="warm_gateway_user",
    ),
    "knostic": CompetitorProfile(
        id="knostic", display_name="Knostic", category="AI_ACCESS_CONTROL",
        env_vars=["KNOSTIC_API_KEY"],
        code_patterns=[r"knostic"],
        warden_score=22,
        strengths=["Need-to-know access for LLMs"],
        weaknesses=["Access control only", "No tool call governance"],
        gtm_signal="warm_governance_aware",
    ),
    "robust_intel": CompetitorProfile(
        id="robust_intel", display_name="Robust Intelligence / Cisco", category="AI_VALIDATION",
        env_vars=["ROBUST_API_KEY", "RIME_API_KEY"],
        packages=["rime-sdk"],
        code_patterns=[r"robust\.ai", r"rime\."],
        warden_score=26,
        strengths=["Model validation", "AI firewall (Cisco)"],
        weaknesses=["Model-level only", "No agent governance"],
        gtm_signal="warm_security_vendor",
    ),
    "cloudflare_ai_gw": CompetitorProfile(
        id="cloudflare_ai_gw", display_name="Cloudflare AI Gateway / Envoy", category="LLM_GATEWAY",
        env_vars=["CF_AI_GATEWAY_ID", "CLOUDFLARE_AI_GATEWAY"],
        code_patterns=[r"gateway\.ai\.cloudflare", r"cf-aig-"],
        warden_score=20,
        strengths=["CDN-level caching", "Rate limiting", "Global edge"],
        weaknesses=["No security enforcement", "No tool call governance"],
        gtm_signal="warm_gateway_user",
    ),
    "neuraltrust": CompetitorProfile(
        id="neuraltrust", display_name="NeuralTrust", category="AI_SECURITY",
        env_vars=["NEURALTRUST_KEY"],
        packages=["neuraltrust"],
        code_patterns=[r"neuraltrust"],
        warden_score=23,
        strengths=["Red teaming", "AI security testing"],
        weaknesses=["Testing only", "No runtime governance"],
        gtm_signal="warm_security_vendor",
    ),
    "lasso": CompetitorProfile(
        id="lasso", display_name="Lasso / Intent Security", category="AI_SECURITY",
        env_vars=["LASSO_API_KEY", "INTENT_API_KEY"],
        code_patterns=[r"lasso\.security", r"intent\.security"],
        warden_score=30,
        strengths=["Agent security monitoring"],
        weaknesses=["Monitoring only", "No inline enforcement"],
        gtm_signal="warm_governance_aware",
    ),
    "mcp_scan": CompetitorProfile(
        id="mcp_scan", display_name="mcp-scan / Snyk", category="SCANNER",
        env_vars=["SNYK_TOKEN"],
        packages=["mcp-scan", "snyk"], processes=["snyk"],
        config_files=[".snyk"],
        code_patterns=[r"mcp-scan", r"snyk\.io"],
        warden_score=18,
        strengths=["MCP vulnerability scanning", "Dependency analysis"],
        weaknesses=["Scan-time only", "No runtime", "No agent governance"],
        gtm_signal="warm_scanner_user",
    ),
    "aifwall": CompetitorProfile(
        id="aifwall", display_name="aiFWall", category="AI_FIREWALL",
        env_vars=["AIFWALL_KEY"],
        code_patterns=[r"aifwall"],
        warden_score=11,
        strengths=["AI firewall concept"],
        weaknesses=["Early stage", "Limited features"],
        gtm_signal="warm_security_vendor",
    ),
    "rubrik": CompetitorProfile(
        id="rubrik", display_name="Rubrik", category="DATA_RECOVERY",
        env_vars=["RUBRIK_TOKEN", "RUBRIK_API_KEY"],
        packages=["rubrik-polaris"], processes=["rubrik-agent"],
        docker_images=["rubrik/cdm"],
        code_patterns=[r"rubrik\.polaris", r"rubrik_cdm"],
        warden_score=26,
        strengths=["Data recovery", "Ransomware protection", "Backup compliance"],
        weaknesses=["Data-focused only", "No agent governance"],
        gtm_signal="warm_cloud_security",
    ),
}


def detect_competitors(target: Path) -> tuple[list[CompetitorMatch], str]:
    """Detect governance tools across 5 signal layers.

    Returns (matches, primary_gtm_signal).
    """
    matches: list[CompetitorMatch] = []
    primary_gtm = ""

    # Collect source for code pattern matching
    all_source = _collect_source(target)

    # Collect installed packages
    installed_packages = _get_installed_packages(target)

    for comp_id, profile in COMPETITORS.items():
        signals: list[str] = []
        layers: list[str] = []

        # Layer 1: Environment variables
        for env_var in profile.env_vars:
            if os.environ.get(env_var):
                signals.append(f"env:{env_var}")
                if "env_vars" not in layers:
                    layers.append("env_vars")

        # Layer 2: Running processes (best-effort, non-blocking)
        if profile.processes:
            running = _check_processes(profile.processes)
            if running:
                signals.extend(f"process:{p}" for p in running)
                layers.append("processes")

        # Layer 3: Config files
        for config_file in profile.config_files:
            if (target / config_file).exists():
                signals.append(f"config:{config_file}")
                if "config_files" not in layers:
                    layers.append("config_files")

        # Layer 4: Installed packages
        for pkg in profile.packages:
            if pkg in installed_packages:
                signals.append(f"package:{pkg}")
                if "packages" not in layers:
                    layers.append("packages")

        # Layer 5: Code patterns
        for pattern in profile.code_patterns:
            if re.search(pattern, all_source, re.IGNORECASE):
                signals.append(f"code:{pattern}")
                if "code_patterns" not in layers:
                    layers.append("code_patterns")
                break  # One code match is enough

        if not signals:
            continue

        # Confidence based on unique layers
        unique_layers = len(set(layers))
        if unique_layers >= 3:
            confidence = "high"
        elif unique_layers >= 2:
            confidence = "medium"
        else:
            confidence = "low"

        match = CompetitorMatch(
            id=comp_id,
            display_name=profile.display_name,
            category=profile.category,
            confidence=confidence,
            signals=signals,
            signal_layers=layers,
            warden_score=profile.warden_score,
            strengths=list(profile.strengths),
            weaknesses=list(profile.weaknesses),
            gtm_signal=profile.gtm_signal,
        )
        matches.append(match)

        # Primary GTM signal: highest-confidence non-existing-customer match
        if confidence != "low" and profile.gtm_signal != "existing_customer":
            if not primary_gtm:
                primary_gtm = profile.gtm_signal

    return matches, primary_gtm


def _collect_source(target: Path) -> str:
    import os

    scan_exts = {".py", ".js", ".ts", ".yaml", ".yml", ".json", ".toml"}
    sources: list[str] = []
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            if Path(fname).suffix.lower() in scan_exts:
                try:
                    sources.append(
                        (Path(dirpath) / fname).read_text(
                            encoding="utf-8", errors="ignore"
                        )
                    )
                except OSError:
                    continue
    return "\n".join(sources)


def _get_installed_packages(target: Path) -> set[str]:
    """Get installed packages from requirements files and lockfiles."""
    import os

    packages: set[str] = set()

    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            fpath = Path(dirpath) / fname
            if fname.startswith("requirements") and fname.endswith(".txt"):
                try:
                    for line in fpath.read_text(
                        encoding="utf-8", errors="ignore"
                    ).splitlines():
                        line = line.strip()
                        if line and not line.startswith("#") and not line.startswith("-"):
                            pkg = re.match(r"([a-zA-Z0-9_\-]+)", line)
                            if pkg:
                                packages.add(pkg.group(1).lower())
                except OSError:
                    continue
            elif fname == "package.json":
                try:
                    data = json.loads(fpath.read_text(encoding="utf-8"))
                    for dep_type in ("dependencies", "devDependencies"):
                        packages.update(d.lower() for d in data.get(dep_type, {}))
                except (json.JSONDecodeError, OSError):
                    continue

    return packages


def _check_processes(process_names: list[str]) -> list[str]:
    """Check for running processes. Best-effort, never fails."""
    try:
        result = subprocess.run(
            ["tasklist" if os.name == "nt" else "ps", "aux"] if os.name != "nt" else ["tasklist"],
            capture_output=True, text=True, timeout=5,
        )
        output = result.stdout.lower()
        return [p for p in process_names if p.lower() in output]
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return []


def _should_skip(filepath: Path) -> bool:
    parts = filepath.parts
    return bool(SKIP_DIRS.intersection(parts))
