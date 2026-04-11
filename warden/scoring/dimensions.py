"""17 governance dimensions with weights and max values.

Total raw: 235 points across 4 groups.
Normalized to /100.

Each dimension declares ``supported_langs`` — the set of language codes
whose scanners can meaningfully contribute to it. ``None`` means the
dimension is language-agnostic (config files, dep files, secrets, etc.).
The scoring engine uses this to implement coverage gating: if a project
has zero files in any supported language for a dimension, that dimension
is marked "not scanned" and dropped from the normalization denominator.
Without this, a pure .NET project gets punished for not having Python
files because Python-only dimensions score 0 and drag the /100 down —
the 2/100 VigIA foot-gun from 2026-04-10.

Language codes: ``python``, ``js``, ``go``, ``rust``, ``java``,
``csharp``. These match ``ScanResult.file_counts`` keys set by
``cli.py``.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Dimension:
    id: str
    name: str
    group: str
    max_score: int
    description: str
    supported_langs: frozenset[str] | None = field(default=None)


# Language coverage sets — which languages a dimension's scanners can
# meaningfully look at. ``None`` (the default) means the dimension is
# language-agnostic (configs, deps, secrets, gitignore, dockerfiles, CI
# yaml, IaC). A missing language in ``file_counts`` for a dim with a
# non-None set means "we didn't look" and the dim is excluded from the
# normalization denominator.
_PY_ONLY = frozenset({"python"})
_PY_CS = frozenset({"python", "csharp"})
_PY_JS_CS = frozenset({"python", "js", "csharp"})


# Group 1: Core Governance (100 pts)
D1 = Dimension("D1", "Tool Inventory", "Core Governance", 25,
               "MCP tool discovery, live catalog, schema completeness, auto-discovery",
               None)  # secrets / generic + multilang → language-agnostic
D2 = Dimension("D2", "Risk Detection", "Core Governance", 20,
               "Risk classification, semantic analysis, intent-parameter consistency",
               frozenset({"python", "js"}))  # MCP + trap_defense are py/js only
D3 = Dimension("D3", "Policy Coverage", "Core Governance", 20,
               "Policy engine, allow/deny/audit modes, signed policies, deny-by-default",
               None)  # config / IaC / deps → language-agnostic
D4 = Dimension("D4", "Credential Management", "Core Governance", 20,
               "Env var exposure, secrets manager, key rotation, NHI credential lifecycle",
               None)  # secrets_scanner walks all files
D5 = Dimension("D5", "Log Hygiene", "Core Governance", 10,
               "PII in logs, WORM/immutable storage, hash chain integrity, retention policy",
               _PY_JS_CS)
D6 = Dimension("D6", "Framework Coverage", "Core Governance", 5,
               "LangChain/AutoGen/CrewAI/custom framework detection",
               None)  # multilang + agent_arch + dep → language-agnostic

# Group 2: Advanced Controls (50 pts)
D7 = Dimension("D7", "Human-in-the-Loop", "Advanced Controls", 15,
               "Approval gates, dry-run preview, plan-execute separation",
               _PY_JS_CS)
D8 = Dimension("D8", "Agent Identity", "Advanced Controls", 15,
               "Agent registry, identity tokens, delegation chains, lifecycle states",
               _PY_JS_CS)
D9 = Dimension("D9", "Threat Detection", "Advanced Controls", 20,
               "Behavioral baselines, anomaly detection, cross-session tracking, kill switch",
               _PY_ONLY)  # trap_defense is Python-only

# Group 3: Ecosystem (55 pts)
D10 = Dimension("D10", "Prompt Security", "Ecosystem", 15,
                "Prompt injection detection, jailbreak prevention, content filtering",
                _PY_ONLY)
D11 = Dimension("D11", "Cloud / Platform", "Ecosystem", 10,
                "Multi-cloud, marketplace, SSO/IdP, SIEM integration",
                None)  # infra_analyzer is language-agnostic
D12 = Dimension("D12", "LLM Observability", "Ecosystem", 10,
                "Cost tracking, latency monitoring, model analytics",
                _PY_CS)
D13 = Dimension("D13", "Data Recovery", "Ecosystem", 10,
                "Rollback, undo, point-in-time recovery for agent actions",
                _PY_ONLY)
D14 = Dimension("D14", "Compliance Maturity", "Ecosystem", 10,
                "SOC2/ISO evidence, compliance reports, regulatory mapping",
                _PY_CS)

# Group 4: Unique Capabilities (30 pts)
D15 = Dimension("D15", "Post-Exec Verification", "Unique Capabilities", 10,
                "Result validation, PASS/FAIL verdicts, failure fingerprinting",
                _PY_ONLY)
D16 = Dimension("D16", "Data Flow Governance", "Unique Capabilities", 10,
                "Taint labels, data classification, cross-tool leakage prevention",
                _PY_ONLY)
D17 = Dimension("D17", "Adversarial Resilience", "Unique Capabilities", 10,
                "Trap defense + adversarial testing (DeepMind AI Agent Traps)",
                _PY_CS)


ALL_DIMENSIONS: list[Dimension] = [
    D1, D2, D3, D4, D5, D6,
    D7, D8, D9,
    D10, D11, D12, D13, D14,
    D15, D16, D17,
]

DIMENSIONS_BY_ID: dict[str, Dimension] = {d.id: d for d in ALL_DIMENSIONS}

TOTAL_RAW_MAX: int = sum(d.max_score for d in ALL_DIMENSIONS)  # 235

GROUPS = {
    "Core Governance": [D1, D2, D3, D4, D5, D6],
    "Advanced Controls": [D7, D8, D9],
    "Ecosystem": [D10, D11, D12, D13, D14],
    "Unique Capabilities": [D15, D16, D17],
}

# Sanity check
assert TOTAL_RAW_MAX == 235, f"Expected 235, got {TOTAL_RAW_MAX}"
assert len(ALL_DIMENSIONS) == 17, f"Expected 17 dimensions, got {len(ALL_DIMENSIONS)}"
