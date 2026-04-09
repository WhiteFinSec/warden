# Warden — Complete State (v1.5.3)

Last updated: 2026-04-10

## Overview

Warden is an open-source, local-only CLI scanner that evaluates AI agent governance posture. It produces a normalized score (0-100) across 17 dimensions derived from 12 scan layers. Zero runtime dependencies beyond `click` and `rich`. No data leaves the machine.

**PyPI:** `warden-ai` · **License:** MIT · **Python:** 3.10+

---

## Codebase Statistics

| Metric | Value |
|--------|-------|
| Total source lines | ~7,200 |
| Test lines | ~1,230 |
| Tests passing | 102 |
| Scanner modules | 14 |
| Scoring dimensions | 17 |
| Scan layers | 12 |
| Raw max score | 235 |
| Runtime dependencies | 2 (click, rich) |
| Dev dependencies | 2 (pytest, pytest-timeout) |

---

## Module Map

### Core

| File | Lines | Purpose |
|------|-------|---------|
| `warden/__init__.py` | 8 | Version (`1.5.3`) and scoring model (`4.3`) |
| `warden/__main__.py` | — | `python -m warden` entry point |
| `warden/cli.py` | 722 | Click CLI — `scan`, `methodology`, `leaderboard` commands. Orchestrates all layers, aggregates scores, writes reports |
| `warden/models.py` | 124 | Data models: `Finding`, `ScanResult`, `McpToolInfo`, `ComplianceMapping`, `Severity` enum |

### Scanners (`warden/scanner/`)

| File | Lines | Layer | Dimensions | File Types Scanned |
|------|-------|-------|------------|-------------------|
| `_common.py` | 24 | — | — | SKIP_DIRS constant (`.venv`, `node_modules`, `__pycache__`, etc.) |
| `code_analyzer.py` | 733 | 1: Code Patterns | D1-D16 | `.py` (AST), `.js/.ts/.jsx/.tsx` (regex) |
| `mcp_scanner.py` | 269 | 2: MCP Servers | D1-D4 | `mcp*.json`, config files |
| `infra_analyzer.py` | 226 | 3: Infrastructure | D4, D9 | Dockerfile, docker-compose `.yml`, K8s manifests |
| `secrets_scanner.py` | 237 | 4: Secrets | D4 | `.py`, `.js`, `.ts`, `.yaml`, `.json`, `.env`, `.md`, `.txt`, etc. |
| `agent_arch_scanner.py` | 219 | 5: Agent Architecture | D7-D9, D12 | `.py` only (AST) |
| `dependency_scanner.py` | 227 | 6: Supply Chain | D14 | `requirements.txt`, `pyproject.toml`, `package.json`, lockfiles |
| `audit_scanner.py` | 190 | 7: Audit & Compliance | D5, D14 | `.py` only |
| `cicd_scanner.py` | 170 | 8: CI/CD Governance | D3, D14 | `.yml/.yaml` in `.github/workflows/` |
| `iac_scanner.py` | 512 | 9: IaC Security | D4, D9 | `.tf`, `.yaml/.yml/.json` (CloudFormation), `.ts/.py` (Pulumi) |
| `framework_scanner.py` | 268 | 10: Framework Governance | D6, D7 | `.py` only |
| `multilang_scanner.py` | 525 | 11: Multi-Language | D7-D9 | `.go`, `.rs`, `.java` |
| `cloud_scanner.py` | 325 | 12: Cloud AI Governance | D4, D9-D11 | `.py`, `.tf`, `.json`, `.yaml` |
| `trap_defense_scanner.py` | 258 | D17 | D17 | `.py` only |
| `competitors.py` | 470 | — | — | `.env`, compose files, `.py`, `.js`, `.ts`, `.yaml`, `.json`, `.toml` |

### Scoring (`warden/scoring/`)

| File | Lines | Purpose |
|------|-------|---------|
| `dimensions.py` | 84 | 17 `Dimension` definitions, 4 groups, `TOTAL_RAW_MAX = 235` assertion |
| `engine.py` | 114 | `calculate_scores()` — normalize raw→/100, CRITICAL/HIGH deductions, level assignment |

### Reports (`warden/report/`)

| File | Lines | Purpose |
|------|-------|---------|
| `html_writer.py` | 1,094 | Self-contained HTML report — SVG gauge, dimension bars, findings, recommendations, comparison card, email form |
| `json_writer.py` | 89 | JSON report with `scoring_version`, dimension scores, findings, trap defense |
| `sarif_writer.py` | 113 | SARIF output for GitHub Code Scanning integration |
| `terminal.py` | 103 | Rich-formatted CLI output with progress bars and per-layer timing |

### GTM (`warden/gtm/`)

| File | Lines | Purpose |
|------|-------|---------|
| `signals.py` | 70 | GTM signal collection for email form (score, dimensions, MCP tools, frameworks) |

---

## 17 Dimensions

### Core Governance (100 pts)

| ID | Name | Max | Contributors (layer: max pts) |
|----|------|-----|-------------------------------|
| D1 | Tool Inventory | 25 | code: 10, mcp: 15 |
| D2 | Risk Detection | 20 | code: 16, mcp: 4 |
| D3 | Policy Coverage | 20 | code: 6, mcp: 6, cicd: 3, cloud: 5 |
| D4 | Credential Management | 20 | code: 8, infra: 6, mcp: 4, cloud: 3, secrets: 3 |
| D5 | Log Hygiene | 10 | code: 4, audit: 6 |
| D6 | Framework Coverage | 5 | code: 2, framework: 3 |

### Advanced Controls (50 pts)

| ID | Name | Max | Contributors |
|----|------|-----|--------------|
| D7 | Human-in-the-Loop | 15 | code: 12, framework: 3 |
| D8 | Agent Identity | 15 | code: 10, agent_arch: 5 |
| D9 | Threat Detection | 20 | code: 16, agent_arch: 2, multilang: 2 |

### Ecosystem (55 pts)

| ID | Name | Max | Contributors |
|----|------|-----|--------------|
| D10 | Prompt Security | 15 | code: 12, cloud: 3 |
| D11 | Cloud / Platform | 10 | code: 6, cloud: 4 |
| D12 | LLM Observability | 10 | code: 8, agent_arch: 2 |
| D13 | Data Recovery | 10 | code: 10 (sole contributor) |
| D14 | Compliance Maturity | 10 | code: 2, audit: 4, cicd: 3, deps: 1 |

### Unique Capabilities (30 pts)

| ID | Name | Max | Contributors |
|----|------|-----|--------------|
| D15 | Post-Exec Verification | 10 | code: 10 (sole contributor) |
| D16 | Data Flow Governance | 10 | code: 10 (sole contributor) |
| D17 | Adversarial Resilience | 10 | trap_defense: 10 (sole contributor) |

---

## Scoring Model (v4.3)

### Pattern Matching

`_score_governance_signals()` is the core scoring function in `code_analyzer.py`. It takes:

- **strong patterns** — governance-specific regexes, worth 3 points each (configurable)
- **weak patterns** — generic/ambiguous matches, worth 1 point each
- **cap** — maximum points from this function for the dimension
- **require_co_occurrence** — minimum number of distinct patterns before any points are awarded (0 = disabled)

Only Python file contents (`py_contents`) are scored for governance signals. JS/TS, Go, Rust, and Java files are scanned by their respective dedicated scanners.

### Anti-Inflation Mechanisms

1. **Strong/weak tiers** — `import logging` scores 1, `audit_log_tamper_proof` scores 3
2. **Co-occurrence** — D3 (Policy) requires 3+ distinct patterns; D11 (Cloud/Platform) requires 3+
3. **Boolean scoring** — each file contributes to only one pattern match per dimension
4. **CRITICAL deductions** — 2 pts per CRITICAL finding, capped at 60% of earned score; HIGH findings deduct 1 pt (max 3)
5. **MCP absence ≠ compliance** — no inline tool definitions → no D2/D3/D4 points from MCP
6. **Positive-signal scoring** — D4 (secrets): clean = 3 pts, not 10; D14 (deps): lockfile = 1 pt, not 4

### Score Normalization

```
normalized = round(raw_score / 235 * 100)
```

Level thresholds: GOVERNED >= 80, PARTIAL >= 60, AT_RISK >= 33, UNGOVERNED < 33.

---

## File Type Coverage

| Scanner | .py | .js/.ts | .yaml/.yml | .md/.txt | .json | .tf | .go/.rs/.java |
|---------|:---:|:-------:|:----------:|:--------:|:-----:|:---:|:-------------:|
| code_analyzer | AST | regex | — | — | — | — | — |
| mcp_scanner | — | — | — | — | MCP configs | — | — |
| infra_analyzer | — | — | Docker/K8s | — | — | — | — |
| secrets_scanner | Yes | Yes | Yes | **Yes** | Yes | — | — |
| agent_arch_scanner | AST | — | — | — | — | — | — |
| dependency_scanner | req files | pkg.json | — | — | lockfiles | — | — |
| audit_scanner | Yes | — | — | — | — | — | — |
| cicd_scanner | — | — | GH Actions | — | — | — | — |
| iac_scanner | — | Pulumi | CFn | — | CFn | HCL | — |
| framework_scanner | Yes | — | — | — | — | — | — |
| multilang_scanner | — | — | — | — | — | — | All three |
| cloud_scanner | Yes | — | Yes | — | Yes | Yes | — |
| trap_defense | Yes | — | — | — | — | — | — |

**Key insight:** Only `secrets_scanner` scans `.md/.txt` files — and that's intentional (secrets in docs are real risks). Governance dimension scoring in `code_analyzer` uses only Python files, so planning documents in `.md` cannot inflate governance scores.

---

## Skipped Directories

Defined in `_common.py` SKIP_DIRS:

`.git`, `.hg`, `.svn`, `.venv`, `venv`, `__pycache__`, `.eggs`, `site-packages`, `.tox`, `.nox`, `.mypy_cache`, `.pytest_cache`, `.ruff_cache`, `.pytype`, `__pypackages__`, `node_modules`, `.next`, `.nuxt`, `.output`, `bower_components`, `.parcel-cache`, `.turbo`, `.idea`, `.vscode`, `.vs`, `worktrees`, `target`, `htmlcov`

---

## Output Formats

### HTML (`warden_report.html`)

Self-contained, dark-theme, neon-accented report. No external requests — works air-gapped. Sections:
1. Header with privacy badge
2. Score gauge (SVG) with dimension breakdown bars
3. Summary grid (MCP-focused or findings-focused)
4. Discovered MCP tools with risk classification
5. Governance layer detection
6. Solutions comparison table (scan vs SharkRouter vs detected tools)
7. Top findings (expandable by severity)
8. Recommendations with point estimates
9. Workaround Tax callout
10. Comparison card (current vs SharkRouter projection)
11. Email form (optional, score metadata only)
12. Footer with privacy note

### JSON (`warden_report.json`)

```json
{
  "scoring_version": "4.3",
  "version": "1.5.3",
  "score": { "normalized": 70, "raw": 165, "raw_max": 235, "level": "PARTIAL", "dimensions": [...] },
  "findings": [...],
  "trap_defense": { "deepmind_citation": "...", "checks": [...] }
}
```

### SARIF (`warden_report.sarif`)

GitHub Code Scanning compatible. Each finding becomes a SARIF `result` with `ruleId`, `level`, `message`, and `physicalLocation`.

---

## CLI Commands

| Command | Description |
|---------|-------------|
| `warden scan <path>` | Run all 12 layers, generate reports |
| `warden scan <path> --format json\|html\|sarif\|all` | Specific output format |
| `warden scan <path> --skip secrets,deps` | Skip named layers |
| `warden scan <path> --only code,mcp` | Run only named layers |
| `warden scan <path> --output-dir <dir>` | Custom output directory |
| `warden methodology` | Print scoring methodology to terminal |
| `warden leaderboard` | Show 17-vendor x 17-dimension market comparison |

---

## Test Suite

102 tests across 5 test directories:

| Directory | Tests | Coverage |
|-----------|-------|----------|
| `tests/test_scoring/` | Dimension definitions, score engine, deductions |
| `tests/test_scanner/` | Individual scanner correctness |
| `tests/test_report/` | JSON report structure, scoring version |
| `tests/test_security/` | HTML self-contained (no external URLs), secrets masking, no SharkRouter imports |
| `tests/test_competitors/` | Competitor registry, detection logic |

All tests run in < 2 seconds with `pytest-timeout=30`.

---

## Version History

| Version | Scoring Model | Key Changes |
|---------|---------------|-------------|
| 1.0.0 | 1.0 | Initial release — 7 layers, 17 dimensions |
| 1.1.0 | 2.0 | SARIF output, IaC scanner, framework scanner |
| 1.2.0 | 3.0 | Multi-language scanner, cloud scanner |
| 1.3.0 | 3.5 | Competitor detection (17 vendors), MCP risk classification |
| 1.4.0 | 4.0 | HTML report, trap defense (D17), McpToolInfo model |
| 1.5.0 | 4.1 | HTML report v2 — neon palette, comparison card, recommendations |
| 1.5.1 | 4.2 | Progress bar fix, HTML footer contrast fix |
| 1.5.2 | 4.3 | Scoring accuracy overhaul — 6 anti-inflation mechanisms, secrets false positive reduction |
| 1.5.3 | 4.3 | Eliminate absence-based scoring in D4 and D14 |

---

## Architecture Principles

1. **Local-only forever** — no telemetry, no cloud, no data leaves the machine
2. **Zero heavy deps** — 2 runtime dependencies, installs in seconds
3. **Conservative scoring** — undetected = 0, never assume compliance; absence of problems ≠ presence of good practices
4. **Vendor-neutral** — fair scoring methodology, vendor corrections welcome via GitHub issues
5. **Research-backed** — D17 cites Google DeepMind "AI Agent Traps" (SSRN 6372438, March 2026)
6. **Compliance-mapped** — findings map to EU AI Act articles, OWASP LLM Top 10, and MITRE ATLAS

---

## Calibration Reference

Tested against real projects (v1.5.3):

| Project | Type | Score | Level | Notes |
|---------|------|-------|-------|-------|
| SharkRouter (sharkAI) | AI governance platform | ~60-65 | PARTIAL | Real governance patterns, some CRITICAL secrets in dev |
| codecontrol (gollm) | AI agent (non-governance) | ~25-30 | UNGOVERNED | Good infra practices but no governance layer |

The gap between a governance-focused platform and a general AI project is now clearly visible in scores.
