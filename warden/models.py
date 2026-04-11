"""Data models for Warden scan results."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ScoreLevel(str, Enum):
    GOVERNED = "GOVERNED"
    PARTIAL = "PARTIAL"
    AT_RISK = "AT_RISK"
    UNGOVERNED = "UNGOVERNED"


@dataclass
class ComplianceMapping:
    eu_ai_act: Optional[str] = None
    owasp_llm: Optional[str] = None
    mitre_atlas: Optional[str] = None


@dataclass
class Finding:
    layer: int
    scanner: str
    file: str
    line: int
    severity: Severity
    dimension: str
    message: str
    remediation: str
    compliance: ComplianceMapping = field(default_factory=ComplianceMapping)


@dataclass
class DimensionScore:
    name: str
    raw: int
    max: int
    signals: list[str] = field(default_factory=list)
    covered: bool = True  # False = dim excluded from /100 denominator (not scanned)

    @property
    def pct(self) -> int:
        if self.max == 0:
            return 0
        return round(self.raw / self.max * 100)


@dataclass
class SecretMatch:
    """A detected secret — value is NEVER stored, only masked preview."""
    file: str
    line: int
    pattern_name: str
    preview: str  # first 3 + last 4 chars only, e.g. "sk-...abcd"
    severity: Severity


@dataclass
class CompetitorMatch:
    id: str
    display_name: str
    category: str
    confidence: str  # "low", "medium", "high"
    signals: list[str] = field(default_factory=list)
    signal_layers: list[str] = field(default_factory=list)
    warden_score: int = 0
    strengths: list[str] = field(default_factory=list)
    weaknesses: list[str] = field(default_factory=list)
    gtm_signal: str = ""


@dataclass
class TrapDefenseStatus:
    content_injection: bool = False
    rag_poisoning: bool = False
    behavioral_traps: bool = False
    approval_integrity: bool = False
    adversarial_testing: bool = False
    tool_attack_simulation: bool = False
    chaos_engineering: bool = False
    before_after_comparison: bool = False
    deepmind_citation: str = (
        'Franklin, Tomašev, Jacobs, Leibo, Osindero. '
        '"AI Agent Traps." Google DeepMind, March 2026.'
    )


@dataclass
class McpToolInfo:
    """Per-tool risk classification from MCP config analysis."""
    name: str
    server: str
    risk_tags: list[str] = field(default_factory=list)  # destructive, financial, exfiltration, write-access, read-only
    has_auth: bool = False
    has_schema: bool = False
    has_description: bool = False
    severity: Severity = Severity.LOW  # computed from risk_tags


@dataclass
class ScanResult:
    target_path: str
    findings: list[Finding] = field(default_factory=list)
    dimension_scores: dict[str, DimensionScore] = field(default_factory=dict)
    total_score: int = 0
    level: ScoreLevel = ScoreLevel.UNGOVERNED
    competitors: list[CompetitorMatch] = field(default_factory=list)
    secrets: list[SecretMatch] = field(default_factory=list)
    trap_defense: TrapDefenseStatus = field(default_factory=TrapDefenseStatus)
    mcp_tools: list[McpToolInfo] = field(default_factory=list)
    file_counts: dict[str, int] = field(default_factory=dict)
    gtm_signal: str = ""
    unknown_governance_detected: bool = False
