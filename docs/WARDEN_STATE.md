# Warden — Complete State (v1.5.6)

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
| Tests passing | 118 |
| Scanner modules | 14 |
| Scoring dimensions | 17 |
| Scan layers | 12 |
| Raw max score | 235 |
| Runtime dependencies | 2 (click, rich) + `tomli` on Python 3.10 only (stdlib `tomllib` on 3.11+) |
| Dev dependencies | 2 (pytest, pytest-timeout) |

---

## Module Map

### Core

| File | Lines | Purpose |
|------|-------|---------|
| `warden/__init__.py` | 8 | Version (`1.5.6`) and scoring model (`4.3`) |
| `warden/__main__.py` | — | `python -m warden` entry point |
| `warden/cli.py` | ~950 | Click CLI — `scan`, `methodology`, `leaderboard`, `baseline`, `diff`, `fix` commands. Orchestrates all layers (parallel), aggregates scores, writes reports. Merges `.warden.toml` defaults |
| `warden/config.py` | 140 | `.warden.toml` / `[tool.warden]` config loader with upward search, VCS-root stop, and unknown-key warnings |
| `warden/models.py` | 124 | Data models: `Finding`, `ScanResult`, `McpToolInfo`, `ComplianceMapping`, `Severity` enum |

### Scanners (`warden/scanner/`)

| File | Lines | Layer | Dimensions | File Types Scanned |
|------|-------|-------|------------|-------------------|
| `_common.py` | 24 | — | — | SKIP_DIRS constant (`.venv`, `node_modules`, `__pycache__`, etc.) |
| `code_analyzer.py` | 733 | 1: Code Patterns | D1-D16 | `.py` (AST), `.js/.ts/.jsx/.tsx` (regex) |
| `mcp_scanner.py` | 269 | 2: MCP Servers | D1-D4 | `mcp*.json`, config files |
| `infra_analyzer.py` | 226 | 3: Infrastructure | D4, D9 | Dockerfile, docker-compose `.yml`, K8s manifests |
| `secrets_scanner.py` | 337 | 4: Secrets | D4 | `.py`, `.js`, `.ts`, `.yaml`, `.json`, `.env`, `.md`, `.txt`, etc. Per-file scan parallelized via `ThreadPoolExecutor` (sequential fallback below 8 files) |
| `agent_arch_scanner.py` | 219 | 5: Agent Architecture | D7-D9, D12 | `.py` only (AST) |
| `dependency_scanner.py` | 227 | 6: Supply Chain | D14 | `requirements.txt`, `pyproject.toml`, `package.json`, lockfiles |
| `audit_scanner.py` | 190 | 7: Audit & Compliance | D5, D14 | `.py` only |
| `cicd_scanner.py` | 170 | 8: CI/CD Governance | D3, D14 | `.yml/.yaml` in `.github/workflows/` |
| `iac_scanner.py` | 512 | 9: IaC Security | D4, D9 | `.tf`, `.yaml/.yml/.json` (CloudFormation), `.ts/.py` (Pulumi) |
| `framework_scanner.py` | 268 | 10: Framework Governance | D6, D7 | `.py` only |
| `multilang_scanner.py` | 525 | 11: Multi-Language | D7-D9 | `.go`, `.rs`, `.java` |
| `cloud_scanner.py` | 325 | 12: Cloud AI Governance | D4, D9-D11 | `.py`, `.tf`, `.json`, `.yaml` |
| `trap_defense_scanner.py` | 258 | D17 | D17 | `.py` only |
| `competitors.py` | 551 | — | — | `.env`, compose files, `.py`, `.js`, `.ts`, `.yaml`, `.json`, `.toml` |

### Scoring (`warden/scoring/`)

| File | Lines | Purpose |
|------|-------|---------|
| `dimensions.py` | 84 | 17 `Dimension` definitions, 4 groups, `TOTAL_RAW_MAX = 235` assertion |
| `engine.py` | 114 | `calculate_scores()` — normalize raw→/100, CRITICAL/HIGH deductions, level assignment |

### Reports (`warden/report/`)

| File | Lines | Purpose |
|------|-------|---------|
| `html_writer.py` | 1,094 | Self-contained HTML report — SVG gauge, dimension bars, findings, recommendations, comparison card, email form |
| `pdf_writer.py` | 55 | Optional PDF output — renders `_build_html()` via weasyprint, gated behind the `warden-ai[pdf]` extra with a friendly `PdfDependencyMissing` raise |
| `json_writer.py` | 89 | JSON report with `scoring_version`, dimension scores, findings, trap defense |
| `sarif_writer.py` | 113 | SARIF output for GitHub Code Scanning integration |
| `terminal.py` | 103 | Rich-formatted CLI output with progress bars and per-layer timing |

### GTM (`warden/gtm/`)

| File | Lines | Purpose |
|------|-------|---------|
| `signals.py` | 70 | GTM signal collection for email form (score, dimensions, MCP tools, frameworks) |

### Gallery (`gallery/` — repo root, not shipped on PyPI)

| File | Lines | Purpose |
|------|-------|---------|
| `gallery/targets.toml` | ~80 | 10 curated OSS AI frameworks (LangChain, LangGraph, CrewAI, AutoGen, Haystack, LlamaIndex, Semantic Kernel, PydanticAI, MetaGPT, Langflow) with slug/repo/category/description/scan_path |
| `gallery/build.py` | ~720 | Stdlib-only site builder: `clone_or_update()`, `run_warden_scan()`, `write_target_landing()`, `write_master_index()`. Idempotent merge of existing + fresh scans. Supports `--only`, `--skip`, `--no-clone`, `--clean` |
| `gallery/README.md` | — | Build/deploy guide, target-selection criteria, vendor-neutrality policy |

**Output layout (gitignored):** `gallery/out/index.html`, `gallery/out/<slug>/{index.html,report.html,report.json,report.sarif}`, `gallery/out/assets/gallery.css`. Each target landing page includes title, description meta, canonical URL, OpenGraph, Twitter card, and JSON-LD Dataset schema for rich search results.

**Verified scans (2026-04-10):** PydanticAI 24/100 (UNGOVERNED), CrewAI 19/100 (UNGOVERNED), LangGraph 14/100 (UNGOVERNED). Remaining 7 targets not yet scanned — deploy step is one-time manual (scp to Caddy or push to GitHub Pages).

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
6. **Positive-signal scoring** — D4 (credentials): clean = 3 pts not 10; D14 (CI/CD): environment blocks, branch protection, OIDC each earn +1

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
  "version": "1.5.6",
  "scoring_model": "v4.3",
  "scoring_version": "4.3",
  "score": {
    "total": 70,
    "max": 100,
    "level": "PARTIAL",
    "raw_total": 164,
    "raw_max": 235,
    "dimensions": { "D1": { "name": "...", "raw": 18, "max": 25, "pct": 72 }, "...": {} }
  },
  "findings": [
    { "layer": "Code Patterns", "severity": "CRITICAL", "dimension": "D4", "file": "app.py", "line": 12, "message": "...", "remediation": "..." }
  ],
  "competitors_detected": [],
  "trap_defense": { "deepmind_citation": "...", "content_injection": {}, "rag_poisoning": {} }
}
```

### SARIF (`warden_report.sarif`)

GitHub Code Scanning compatible. Each finding becomes a SARIF `result` with `ruleId`, `level`, `message`, and `physicalLocation`.

---

## CLI Commands

| Command | Description |
|---------|-------------|
| `warden scan <path>` | Run all 12 layers (parallel), generate reports |
| `warden scan <path> --format json\|html\|sarif\|pdf\|all` | Specific output format (`pdf` requires `pip install warden-ai[pdf]`) |
| `warden scan <path> --skip secrets,deps` | Skip named layers |
| `warden scan <path> --only code,mcp` | Run only named layers |
| `warden scan <path> --output-dir <dir>` | Custom output directory |
| `warden scan <path> --ci` | CI mode — exit 0 GOVERNED, 1 PARTIAL, 2 AT_RISK, 3 UNGOVERNED |
| `warden scan <path> --min-score 60` | Fail CI if normalized score is below threshold |
| `warden scan <path> --baseline .warden-baseline.json` | Show only NEW findings not in baseline |
| `warden scan <path> --no-config` | Ignore any `.warden.toml` / `[tool.warden]` discovered from the scan path |
| `warden baseline <path>` | Save current findings as `.warden-baseline.json` for brownfield adoption |
| `warden diff <old.json> <new.json>` | Compare two JSON reports — score delta + new/resolved findings |
| `warden fix <path>` | Auto-remediate `.gitignore`, dependency pinning, Dockerfile `USER` |
| `warden methodology` | Print scoring methodology to terminal |
| `warden leaderboard` | Show 20-vendor x 17-dimension market comparison |

---

## Test Suite

124 tests across 5 test directories:

| Directory | Tests | Coverage |
|-----------|-------|----------|
| `tests/test_scoring/` | Dimension definitions, score engine, deductions |
| `tests/test_scanner/` | Individual scanner correctness |
| `tests/test_report/` | JSON report structure, scoring version |
| `tests/test_security/` | HTML self-contained (no external URLs), secrets masking, no SharkRouter imports |
| `tests/test_competitors/` | Competitor registry, detection logic |

All tests run in < 2 seconds with `pytest-timeout=30`.

---

## Competitor Detection

Warden detects **20 governance and security tools** in the scanned project. Detection uses 5 signal layers:

| Signal Layer | What It Checks |
|-------------|----------------|
| Environment variables | `PORTKEY_API_KEY`, `LAKERA_API_KEY`, etc. |
| Packages | `sharkrouter-sdk`, `lakera-guard`, etc. in requirements/package.json |
| Docker images | `sharkrouter/gateway`, `kong`, etc. in compose files |
| Config files | `sharkrouter.yaml`, `.lakerarc`, etc. |
| Code patterns | `base_url.*portkey`, `lakera.*guard`, etc. in source |

**Detection threshold:** 2+ signals from different layers = "detected" (confidence: medium/high). Single-signal matches are confidence: "low" and are NOT shown in the report.

### 20 Registered Vendors

| ID | Display Name | Category |
|----|-------------|----------|
| sharkrouter | SharkRouter | Tool Call Gateway |
| zenity | Zenity | AI Security Posture |
| oasis | Oasis Security | NHI Lifecycle |
| wiz | Wiz | Cloud Security |
| portkey | Portkey | LLM Gateway |
| lakera | Lakera | Prompt Security |
| prompt_security | Prompt Security | Prompt Security |
| pangea | Pangea / CrowdStrike | AI Guard |
| noma | Noma Security | AI Security Posture |
| kong | Kong | API Gateway |
| knostic | Knostic | AI Access Control |
| robust_intel | Robust Intelligence / Cisco | AI Validation |
| cloudflare_ai_gw | Cloudflare AI Gateway / Envoy | LLM Gateway |
| neuraltrust | NeuralTrust | AI Security |
| lasso | Lasso / Intent Security | AI Security |
| mcp_scan | mcp-scan / Snyk | Scanner |
| aifwall | aiFWall | AI Firewall |
| rubrik | Rubrik | Data Recovery |
| protect_ai | Protect AI (Palo Alto Networks) | ML Security |
| hiddenlayer | HiddenLayer | ML Security |

Each vendor has a `warden_score` (estimated score if fully deployed) and `strengths`/`weaknesses` for the HTML report's comparison table.

### GTM Signal Routing

When competitors are detected, `gtm/signals.py` maps them to sales actions:

| Signal | Action | Priority |
|--------|--------|----------|
| `existing_customer` | Upsell | Low |
| `warm_governance_aware` | Gap analysis ("can you BLOCK a tool call?") | High |
| `warm_jit_aware` | Before/during/after pitch | High |
| `warm_gateway_user` | Security upgrade ("routes vs governs") | Medium |
| `warm_prompt_security` | Layer completion ("prompt → tool call") | High |
| `warm_cloud_security` | Runtime gap pitch | Medium |
| `warm_scanner_user` | Runtime upgrade | Medium |

GTM data is included in the email form payload (opt-in) — never sent automatically.

---

## Secret Patterns

16 patterns with severity classification:

| Pattern | Severity | Regex Summary |
|---------|----------|--------------|
| OpenAI API Key | CRITICAL | `sk-[a-zA-Z0-9]{20,}` |
| Anthropic API Key | CRITICAL | `sk-ant-[a-zA-Z0-9\-]{20,}` |
| Google API Key | CRITICAL | `AIza[0-9A-Za-z\-_]{35}` |
| AWS Access Key | CRITICAL | `AKIA[0-9A-Z]{16}` |
| AWS Secret Key | HIGH | `aws_secret.*=.*[40 chars]` |
| GitHub Token | HIGH | `gh[ps]_[A-Za-z0-9_]{36,}` |
| Groq API Key | CRITICAL | `gsk_[a-zA-Z0-9]{20,}` |
| HuggingFace Token | HIGH | `hf_[a-zA-Z0-9]{20,}` |
| Slack Token | HIGH | `xox[bpors]-[0-9a-zA-Z\-]+` |
| DB URL (with creds) | CRITICAL | `postgres://user:pass@host` |
| DB URL (no creds) | MEDIUM | `redis://host:6379` (no password) |
| Private Key | CRITICAL | `-----BEGIN RSA PRIVATE KEY-----` |
| JWT Secret | HIGH | `jwt_secret=...` |
| Stripe Key | CRITICAL | `sk_live_[0-9a-zA-Z]{24,}` |
| SendGrid Key | HIGH | `SG.[22 chars].[43 chars]` |
| Generic Secret | MEDIUM | `password=..., token=..., api_key=...` |

### False Positive Filters

- **Regex definition filter:** lines containing `re.compile`, `Pattern(`, `SecretPattern(`, `\S+`, `[^`, etc. are excluded
- **SKIP_DIRS:** `.venv`, `node_modules`, `worktrees`, etc. never scanned
- **DB URL split:** credentials in URL = CRITICAL; bare connection string = MEDIUM

---

## CI/CD Pipeline

### Composite GitHub Action (`action.yml` at repo root)

Warden ships as a reusable composite action so downstream projects get one-step adoption:

```yaml
- uses: SharkRouter/warden@v1
  with:
    min-score: 60
    fail-on-level: at_risk
```

Inputs: `path`, `format`, `output-dir`, `skip`, `only`, `baseline`, `min-score`, `fail-on-level`, `upload-sarif`, `sarif-category`, `warden-version`, `python-version`. Outputs: `score`, `raw-score`, `level`, `findings-count`, `critical-count`, `report-json`, `report-html`, `report-sarif`. Writes a job summary with level + score + findings breakdown. Conditionally uploads SARIF to GitHub Code Scanning via `github/codeql-action/upload-sarif@v3`.

**Self-validation:** `.github/workflows/ci.yml` → `self-scan` job calls the action via `uses: ./` on every push, so a broken `action.yml` is caught before it reaches marketplace consumers.

### `ci.yml` — Runs on every push/PR to main

| Job | What It Does |
|-----|--------------|
| `test` | Matrix: 3 OS (ubuntu/windows/macos) × 4 Python (3.10-3.13) = 12 runs |
| `lint` | `ruff check warden/` on ubuntu with Python 3.12 |
| `self-scan` | Warden scans its own codebase, uploads report as artifact |

### `publish.yml` — Runs on `v*` tag push

| Job | What It Does |
|-----|--------------|
| `build` | Install, test, `uv build`, upload dist artifact |
| `publish` | Download artifact, `uv publish` with trusted publishing (OIDC, no API token) |

**Trusted publishing:** PyPI configured with GitHub Actions OIDC — no stored secrets. Tag `v1.5.6` → automatic build + test + publish.

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
| 1.5.4 | 4.3 | Gitignore-aware secrets scanning — `.env` secrets downgraded to INFO |
| 1.5.5 | 4.3 | Parallel scanning — 9 layers run concurrently, 2.2x faster (47s on 2554-file project) |
| 1.5.6 | 4.3 | `warden baseline` command, competitor score refresh (Zenity 55, Portkey 32, Noma 40) |

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

Tested against real projects (v1.5.6):

| Project | Type | Score | Level | Notes |
|---------|------|-------|-------|-------|
| SharkRouter (sharkAI) | AI governance platform | ~60-65 | PARTIAL | Real governance patterns, some CRITICAL secrets in dev |
| codecontrol (gollm) | AI agent (non-governance) | ~25-30 | UNGOVERNED | Good infra practices but no governance layer |

The gap between a governance-focused platform and a general AI project is now clearly visible in scores.
