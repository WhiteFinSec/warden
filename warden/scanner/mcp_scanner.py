"""Layer 2: MCP server configuration analysis."""

from __future__ import annotations

import json
from pathlib import Path

from warden.models import ComplianceMapping, Finding, McpToolInfo, Severity
from warden.scanner._common import SKIP_DIRS

# Risk classification keywords
_RISK_KEYWORDS: dict[str, list[str]] = {
    "destructive": ["delete", "remove", "drop", "destroy", "reset", "overwrite", "truncate", "wipe", "purge", "kill"],
    "financial": ["payment", "fund", "transfer", "billing", "invoice", "charge", "refund", "payout", "stripe", "price"],
    "exfiltration": ["email", "send", "upload", "post", "notify", "message", "webhook", "export", "slack", "sms"],
    "write-access": ["write", "create", "insert", "update", "modify", "execute", "run", "put", "patch", "set"],
    "read-only": ["read", "get", "list", "search", "query", "fetch", "describe", "show", "find", "view"],
}

MCP_CONFIG_FILENAMES = [
    "mcp.json",
    "mcp_config.json",
    ".mcp.json",
    "claude_desktop_config.json",
    "settings.json",
]

MCP_CONFIG_DIRS = [
    ".config/claude",
    ".claude",
]


def scan_mcp(target: Path) -> tuple[list[Finding], dict[str, int], list[McpToolInfo]]:
    """Layer 2: Scan MCP server configurations.

    Returns (findings, raw_dimension_scores, mcp_tools).
    """
    findings: list[Finding] = []
    mcp_tools: list[McpToolInfo] = []
    configs_found = 0

    # Search for MCP config files
    for config_file in _find_mcp_configs(target):
        configs_found += 1
        file_findings, file_tools = _analyze_mcp_config(config_file)
        findings.extend(file_findings)
        mcp_tools.extend(file_tools)

    scores: dict[str, int] = {}

    if configs_found > 0:
        # MCP configs exist = some tool inventory
        scores["D1"] = min(configs_found * 5, 15)

        # Check for schema validation
        schema_findings = [f for f in findings if "schema" in f.message.lower()]
        if not schema_findings:
            scores["D2"] = 4  # No schema issues = basic risk detection

        # Check for auth
        auth_findings = [f for f in findings if f.dimension == "D3"]
        scores["D3"] = max(0, 6 - len(auth_findings) * 2)

        # Check for TLS
        tls_findings = [f for f in findings if f.dimension == "D4"]
        scores["D4"] = max(0, 4 - len(tls_findings) * 2)

    return findings, scores, mcp_tools


def _find_mcp_configs(target: Path) -> list[Path]:
    """Find all MCP configuration files."""
    configs: list[Path] = []

    # Direct filenames in target
    for name in MCP_CONFIG_FILENAMES:
        candidate = target / name
        if candidate.is_file():
            configs.append(candidate)

    # Config subdirectories
    for subdir in MCP_CONFIG_DIRS:
        config_dir = target / subdir
        if config_dir.is_dir():
            for name in MCP_CONFIG_FILENAMES:
                candidate = config_dir / name
                if candidate.is_file():
                    configs.append(candidate)

    # Recursive search for mcp*.json
    import os

    skip_dirs = SKIP_DIRS - {".claude"}  # MCP configs live in .claude/
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fname in filenames:
            if fname.startswith("mcp") and fname.endswith(".json"):
                f = Path(dirpath) / fname
                if f not in configs:
                    configs.append(f)

    return configs


def _classify_tool_risk(tool_name: str, tool_desc: str) -> list[str]:
    """Classify a tool's risk tags from its name and description."""
    text = f"{tool_name} {tool_desc}".lower()
    tags = []
    for tag, keywords in _RISK_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            tags.append(tag)
    # If no tags matched, classify as read-only by default
    if not tags:
        tags.append("read-only")
    return tags


def _severity_from_risk_tags(tags: list[str]) -> Severity:
    """Compute severity from risk tags."""
    if "destructive" in tags or "financial" in tags:
        return Severity.CRITICAL
    if "exfiltration" in tags:
        return Severity.HIGH
    if "write-access" in tags:
        return Severity.MEDIUM
    return Severity.LOW


def _analyze_mcp_config(config_file: Path) -> tuple[list[Finding], list[McpToolInfo]]:
    """Analyze a single MCP configuration file."""
    findings: list[Finding] = []
    mcp_tools: list[McpToolInfo] = []

    try:
        content = config_file.read_text(encoding="utf-8")
        config = json.loads(content)
    except (json.JSONDecodeError, OSError):
        return findings, mcp_tools

    servers = config.get("mcpServers", config.get("servers", {}))
    if not isinstance(servers, dict):
        return findings, mcp_tools

    for server_name, server_config in servers.items():
        if not isinstance(server_config, dict):
            continue

        # Check for write tools without auth
        tools = server_config.get("tools", [])
        auth = server_config.get("auth", server_config.get("authentication"))
        write_tools = [t for t in tools if isinstance(t, dict) and
                       any(w in str(t.get("name", "")).lower()
                           for w in ("write", "delete", "update", "create", "execute"))]

        if write_tools and not auth:
            findings.append(Finding(
                layer=2, scanner="mcp_scanner",
                file=str(config_file), line=1,
                severity=Severity.CRITICAL, dimension="D3",
                message=f"MCP server '{server_name}' has write tools without authentication",
                remediation="Add authentication section to MCP server config",
                compliance=ComplianceMapping(eu_ai_act="Article 15", owasp_llm="LLM01"),
            ))

        # Check for filesystem-exposing tools
        fs_tools = [t for t in tools if isinstance(t, dict) and
                    any(f in str(t.get("name", "")).lower()
                        for f in ("read_file", "write_file", "list_dir", "filesystem"))]
        if fs_tools:
            findings.append(Finding(
                layer=2, scanner="mcp_scanner",
                file=str(config_file), line=1,
                severity=Severity.HIGH, dimension="D4",
                message=f"MCP server '{server_name}' exposes filesystem operations",
                remediation="Restrict file access to specific directories using allowlist",
            ))

        # Check for tools without schemas
        no_schema_tools = [t for t in tools if isinstance(t, dict) and
                          not t.get("inputSchema") and not t.get("schema")]
        if no_schema_tools:
            findings.append(Finding(
                layer=2, scanner="mcp_scanner",
                file=str(config_file), line=1,
                severity=Severity.HIGH, dimension="D2",
                message=f"MCP server '{server_name}' has tools without JSON Schema definitions",
                remediation="Add inputSchema to all tool definitions for validation",
            ))

        # Check transport security
        transport = server_config.get("transport", {})
        url = transport.get("url", server_config.get("url", ""))
        if url.startswith("http://") and "localhost" not in url and "127.0.0.1" not in url:
            findings.append(Finding(
                layer=2, scanner="mcp_scanner",
                file=str(config_file), line=1,
                severity=Severity.MEDIUM, dimension="D4",
                message=f"MCP server '{server_name}' transport uses HTTP (not HTTPS)",
                remediation="Use HTTPS for MCP server transport",
            ))

        # Check for tools without descriptions
        no_desc_tools = [t for t in tools if isinstance(t, dict) and not t.get("description")]
        if no_desc_tools:
            findings.append(Finding(
                layer=2, scanner="mcp_scanner",
                file=str(config_file), line=1,
                severity=Severity.LOW, dimension="D1",
                message=f"MCP server '{server_name}' has {len(no_desc_tools)} tool(s) without descriptions",
                remediation="Add descriptions to all tools for discoverability",
            ))

        # Classify each tool for risk
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            tool_name = str(tool.get("name", ""))
            tool_desc = str(tool.get("description", ""))
            risk_tags = _classify_tool_risk(tool_name, tool_desc)
            mcp_tools.append(McpToolInfo(
                name=tool_name,
                server=server_name,
                risk_tags=risk_tags,
                has_auth=bool(auth),
                has_schema=bool(tool.get("inputSchema") or tool.get("schema")),
                has_description=bool(tool_desc),
                severity=_severity_from_risk_tags(risk_tags),
            ))

    return findings, mcp_tools


def _should_skip(filepath: Path) -> bool:
    parts = filepath.parts
    return bool(SKIP_DIRS.intersection(parts))
