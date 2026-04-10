"""Competitor detection registry — 19 tools across 5 signal layers.

Detection requires 2+ signals from different layers to classify as "present."
Single-signal matches are confidence: "low" and do NOT trigger GTM routing.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from warden.models import CompetitorMatch
from warden.scanner._common import SKIP_DIRS


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
        code_patterns=[
            r"base_url.*sharkrouter", r"shark.*proxy", r"sharkrouter\.ai",
            r"SHARK_API_KEY", r"shark.?router",
        ],
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
        warden_score=55,
        strengths=[
            "Shadow AI discovery",
            "Endpoint observability",
            "Posture management",
            "Inline enforcement on Foundry/AgentKit (GA 2026)",
        ],
        weaknesses=[
            "Platform-specific enforcement only (Foundry, AgentKit, endpoints), not a universal gateway",
            "No agent passport / cryptographic identity",
            "No post-exec verification or trap defense",
        ],
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
        warden_score=32,
        strengths=[
            "1600+ model routing",
            "MCP Gateway with access control and audit logging",
            "60+ guardrails (input + output), PII redaction",
            "SOC2/ISO27001/HIPAA certified",
            "Virtual keys, budget limits, regional residency",
        ],
        weaknesses=[
            "No agent identity / passport",
            "No behavioral baseline or anomaly detection",
            "No tool-call semantic analysis",
            "No Dry-Run Preview or Kill Switch",
        ],
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
        warden_score=40,
        strengths=[
            "Runtime guardrails block unauthorized actions before execution",
            "Agentic Risk Map (blast radius per agent)",
            "80+ integrations (MLOps, SaaS, cloud, code repos)",
            "Red teaming + AISPM + compliance (SOC2 Type II, HIPAA)",
            "$132M funding, 1300% ARR growth",
        ],
        weaknesses=[
            "Platform-specific integrations, not a universal gateway",
            "No cryptographic agent identity",
            "No Dry-Run Preview or Causal Chain",
            "No Trap Defense (D17)",
        ],
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
    "protect_ai": CompetitorProfile(
        id="protect_ai", display_name="Protect AI (Palo Alto Networks)", category="ML_SECURITY",
        env_vars=["PROTECTAI_API_KEY", "PROTECT_AI_TOKEN", "MODELSCAN_API_KEY"],
        packages=["protectai", "modelscan", "nbdefense", "llm-guard"],
        processes=["modelscan"],
        config_files=[".modelscan.yaml", ".protectai.yaml"],
        code_patterns=[
            r"protectai", r"protect_ai", r"modelscan", r"nb_defense", r"llm[_\-]guard",
        ],
        warden_score=32,
        strengths=[
            "ModelScan — open-source unsafe-serialization detection (pickle, H5, ONNX)",
            "NB Defense for Jupyter notebook security",
            "LLM Guard — input/output scanners (prompt injection, toxicity, PII)",
            "Huntr AI/ML bug bounty + vulnerability DB (Sightline)",
            "Backed by Palo Alto Networks (July 2024 acquisition)",
        ],
        weaknesses=[
            "Model/supply-chain focus — no agent tool-call gateway",
            "Scan-time + prompt-level only, no cryptographic agent identity",
            "No Dry-Run Preview, no post-exec verification, no Kill Switch",
            "LLM Guard runs in-process; no centralized enforcement or audit chain",
        ],
        gtm_signal="warm_ml_security",
    ),
    "hiddenlayer": CompetitorProfile(
        id="hiddenlayer", display_name="HiddenLayer", category="ML_SECURITY",
        env_vars=["HIDDENLAYER_API_KEY", "HIDDENLAYER_CLIENT_ID", "HIDDENLAYER_TOKEN"],
        packages=["hiddenlayer", "hiddenlayer-sdk", "hiddenlayer-ml"],
        processes=["hiddenlayer-agent"],
        config_files=[".hiddenlayer.yaml", "hiddenlayer.yml"],
        code_patterns=[
            r"hiddenlayer", r"HiddenLayer", r"hiddenlayer\.ai", r"hl_sdk",
        ],
        warden_score=34,
        strengths=[
            "AISec Platform — inference-time MLDR (Machine Learning Detection & Response)",
            "Model Scanner — detects malicious models in supply chain",
            "Automated Red Teaming for LLMs and classical ML",
            "Adversarial ML expertise (founded by Tanium / Cylance alums)",
            "Threat intel feed specifically for AI attacks",
        ],
        weaknesses=[
            "Model-inference focus, not agent tool-call governance",
            "No agent passport / cryptographic identity",
            "No Dry-Run Preview or Causal Chain across tool calls",
            "No Trap Defense (D17) for agent-loop attacks",
        ],
        gtm_signal="warm_ml_security",
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

    # Build compiled patterns for per-file matching
    all_patterns: dict[str, list[re.Pattern[str]]] = {}
    for cid, prof in COMPETITORS.items():
        if prof.code_patterns:
            all_patterns[cid] = [re.compile(p, re.IGNORECASE) for p in prof.code_patterns]

    # Per-file code pattern matching (memory-efficient, early exit)
    code_matches = _match_code_patterns(target, all_patterns)

    # Collect installed packages
    installed_packages = _get_installed_packages(target)

    # Collect env var references from project files (.env, docker-compose, etc.)
    env_file_contents = _collect_env_file_contents(target)

    # Collect docker-compose service images
    docker_images = _collect_docker_images(target)

    for comp_id, profile in COMPETITORS.items():
        signals: list[str] = []
        layers: list[str] = []

        # Layer 1: Environment variables — check project files AND runtime env
        for env_var in profile.env_vars:
            # Check .env files, docker-compose.yml, etc.
            if any(env_var in content for content in env_file_contents):
                signals.append(f"env_file:{env_var}")
                if "env_vars" not in layers:
                    layers.append("env_vars")
            # Also check runtime (less common but still valid)
            elif os.environ.get(env_var):
                signals.append(f"env:{env_var}")
                if "env_vars" not in layers:
                    layers.append("env_vars")

        # Layer 2: Docker images (from docker-compose files)
        for img in profile.docker_images:
            if any(img.lower() in di.lower() for di in docker_images):
                signals.append(f"docker:{img}")
                if "docker_images" not in layers:
                    layers.append("docker_images")

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

        # Layer 5: Code patterns (pre-computed per-file matching)
        matched_patterns = code_matches.get(comp_id, set())
        code_match_count = len(matched_patterns)
        if matched_patterns:
            layers.append("code_patterns")
            for pat_str in matched_patterns:
                signals.append(f"code:{pat_str}")

        if not signals:
            continue

        # Confidence: layers + signal density
        unique_layers = len(set(layers))
        total_patterns = len(profile.code_patterns) or 1
        code_ratio = code_match_count / total_patterns

        if unique_layers >= 3:
            confidence = "high"
        elif unique_layers >= 2 and code_ratio >= 0.8:
            # 2+ layers AND nearly all code patterns match = own codebase
            confidence = "high"
        elif unique_layers >= 2:
            confidence = "medium"
        elif code_match_count >= 3:
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


def _collect_env_file_contents(target: Path) -> list[str]:
    """Read .env files, docker-compose files, and similar config that may contain env var names."""
    env_patterns = {".env", ".env.local", ".env.production", ".env.example",
                    "docker-compose.yml", "docker-compose.yaml",
                    "docker-compose.prod.yml", "docker-compose.override.yml"}
    contents: list[str] = []
    # Check root and one level deep
    for candidate in env_patterns:
        fpath = target / candidate
        if fpath.is_file():
            try:
                contents.append(fpath.read_text(encoding="utf-8", errors="ignore"))
            except OSError:
                continue
    return contents


def _collect_docker_images(target: Path) -> list[str]:
    """Extract image names from docker-compose files."""
    images: list[str] = []
    for name in ("docker-compose.yml", "docker-compose.yaml",
                 "docker-compose.prod.yml", "docker-compose.override.yml"):
        fpath = target / name
        if fpath.is_file():
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                for match in re.finditer(r'image:\s*["\']?([^\s"\']+)', content):
                    images.append(match.group(1))
            except OSError:
                continue
    return images


def _match_code_patterns(
    target: Path,
    all_patterns: dict[str, list[re.Pattern[str]]],
) -> dict[str, set[str]]:
    """Per-file code pattern matching with early exit.

    Returns {competitor_id: {matched_pattern_str, ...}} for each competitor.
    Stops checking a competitor's patterns once all are found.
    Much more memory-efficient than concatenating all source into one string.
    """
    import os

    scan_exts = {".py", ".js", ".ts", ".yaml", ".yml", ".json", ".toml"}
    max_file_size = 2_000_000

    # Track which patterns still need matching per competitor
    remaining: dict[str, list[re.Pattern[str]]] = {
        cid: list(patterns) for cid, patterns in all_patterns.items()
    }
    matched: dict[str, set[str]] = {cid: set() for cid in all_patterns}

    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

        # Stop walking if every competitor's patterns are fully matched
        if not any(remaining.values()):
            break

        for fname in filenames:
            if Path(fname).suffix.lower() not in scan_exts:
                continue
            filepath = Path(dirpath) / fname
            try:
                if filepath.stat().st_size > max_file_size:
                    continue
                content = filepath.read_text(encoding="utf-8", errors="ignore")
            except (OSError, MemoryError):
                continue

            for cid in list(remaining):
                still_needed = []
                for pat in remaining[cid]:
                    if pat.search(content):
                        matched[cid].add(pat.pattern)
                    else:
                        still_needed.append(pat)
                remaining[cid] = still_needed
                if not still_needed:
                    del remaining[cid]  # all patterns found, stop checking

            if not remaining:
                break

    return matched


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



def _should_skip(filepath: Path) -> bool:
    parts = filepath.parts
    return bool(SKIP_DIRS.intersection(parts))
