# Warden — AI Agent Governance Scanner

Open-source, local-only CLI scanner that evaluates AI agent governance posture across **10 scan layers** and **17 dimensions**. Scans code patterns, MCP configs, infrastructure, secrets, agent architecture, dependencies, audit compliance, CI/CD pipelines, IaC security, and framework-specific governance. **No data leaves the machine.**

## Quick Start

```bash
# With pip
pip install warden-ai
warden scan /path/to/your-agent-project

# With uv (zero setup, one-shot)
uvx --from warden-ai warden scan /path/to/your-agent-project
```

From zero to governance score in under 60 seconds.

## What It Does

Warden scores your AI agent project across **17 governance dimensions** (out of 235 raw, normalized to /100):

| Group | Dimensions |
|-------|-----------|
| **Core Governance** (100 pts) | Tool Inventory, Risk Detection, Policy Coverage, Credential Management, Log Hygiene, Framework Coverage |
| **Advanced Controls** (50 pts) | Human-in-the-Loop, Agent Identity, Threat Detection |
| **Ecosystem** (55 pts) | Prompt Security, Cloud/Platform, LLM Observability, Data Recovery, Compliance Maturity |
| **Unique Capabilities** (30 pts) | Post-Exec Verification, Data Flow Governance, Adversarial Resilience |

### Score Levels

| Score | Level | Meaning |
|-------|-------|---------|
| >= 80 | **GOVERNED** | Comprehensive agent governance in place |
| >= 60 | **PARTIAL** | Significant coverage with material gaps |
| >= 33 | **AT_RISK** | Some controls exist but major blind spots |
| < 33 | **UNGOVERNED** | Minimal or no agent governance |

## CLI Commands

```bash
# Scan a project (generates HTML + JSON reports)
warden scan .
warden scan /path/to/project --format json
warden scan /path/to/project --output-dir /path/to/reports

# Skip specific layers
warden scan . --skip secrets,deps

# Run only specific layers
warden scan . --only code,mcp,cicd

# View the scoring methodology
warden methodology

# See the market leaderboard (17 vendors x 17 dimensions)
warden leaderboard
```

### Layer Keys for --skip / --only

| Key | Layer |
|-----|-------|
| `code` | Code Patterns (Python AST + JS/TS regex) |
| `mcp` | MCP Server Configs |
| `infra` | Infrastructure (Docker, K8s) |
| `secrets` | Secrets & Credentials |
| `agent` | Agent Architecture |
| `deps` | Supply Chain / Dependencies |
| `audit` | Audit & Compliance |
| `cicd` | CI/CD Governance |
| `iac` | IaC Security (Terraform) |
| `frameworks` | Framework-Specific Governance |

## 10 Scan Layers

1. **Code Patterns** -- AST-based Python + regex JS/TS analysis (unprotected LLM calls, agent loops, unrestricted tool access)
2. **MCP Servers** -- Config file analysis (write tools without auth, missing schemas, non-TLS transport)
3. **Infrastructure** -- Dockerfile, docker-compose, K8s manifests (root containers, exposed secrets, missing healthchecks)
4. **Secrets** -- 15+ credential patterns with value masking (OpenAI, Anthropic, AWS, GitHub, Stripe, etc.)
5. **Agent Architecture** -- Agent class analysis (no permissions, no cost tracking, unlimited sub-agent spawning)
6. **Supply Chain** -- Dependency analysis (unpinned AI packages, typosquat detection via Levenshtein distance)
7. **Audit & Compliance** -- Audit logging, structured logging, retention policies, compliance framework mapping
8. **CI/CD Governance** -- GitHub Actions analysis (missing approvals, exposed secrets, no branch protection, CODEOWNERS)
9. **IaC Security** -- Terraform analysis (unencrypted S3, open security groups, IAM wildcards, local state)
10. **Framework Governance** -- LangChain callbacks, CrewAI guardrails, AutoGen sandboxing, LlamaIndex limits

Plus **D17: Adversarial Resilience** -- 8 sub-checks based on Google DeepMind's "AI Agent Traps" paper (Franklin et al., March 2026).

## Competitor Detection

Warden detects **17 governance and security tools** across 5 signal layers (env vars, processes, MCP configs, packages, Docker containers). Detection requires 2+ signals from different layers to prevent false positives.

## Output Formats

- **CLI summary** -- colorized terminal output with per-layer elapsed time, progress bars, and D17 warning
- **warden_report.html** -- self-contained dark-theme report with SVG score ring, expandable findings, benchmark bars, and market comparison (no external requests, works air-gapped)
- **warden_report.json** -- machine-readable with `scoring_version` field

## Architecture Constraints

1. **Zero network access** -- Scanners never import httpx/requests/urllib. CI-enforced.
2. **Zero SharkRouter imports** -- Standalone package with no internal dependencies. CI-enforced.
3. **Secrets never stored** -- Only file, line, pattern name, and masked preview (first 3 + last 4 chars).
4. **HTML report self-contained** -- No CDN, no Google Fonts. Works in air-gapped environments.

## Development

```bash
# With uv (recommended)
uv sync --extra dev
uv run pytest tests/ -v

# With pip
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -e ".[dev]"
pytest tests/ -v
```

## Known Limitations

- **Language coverage:** v1.1 scans Python and JS/TS code patterns. Go/Rust/Java code analysis is planned for a future version. Infrastructure, secrets, and dependency scanning apply to all languages.
- **Framework vocabulary:** Scoring is optimized for recognized AI frameworks. Custom frameworks may score lower despite equivalent governance.
- **Static analysis:** Warden detects governance *patterns*, not enforcement. High score = controls present, not proven correct.
- **IaC coverage:** Currently supports Terraform. Pulumi, CloudFormation, and CDK planned for future versions.

See [SCORING.md](SCORING.md) for full details.

## Methodology

Full scoring methodology: [SCORING.md](SCORING.md)

Run `warden methodology` to see it in your terminal.

## License

MIT

## Research Citation

Adversarial resilience dimension (D17) cites:

> Franklin, Tomasev, Jacobs, Leibo, Osindero. "AI Agent Traps." Google DeepMind, March 2026.

Every D17 finding maps to EU AI Act articles, OWASP LLM Top 10, and MITRE ATLAS techniques.
