# Warden Scoring Methodology v4.3

Warden evaluates AI agent governance posture across **17 dimensions**, grouped into 4 categories. Raw scores (out of 235) are normalized to a 0-100 scale.

## Score Levels

| Score | Level | Meaning |
|-------|-------|---------|
| >= 80 | **GOVERNED** | Comprehensive agent governance in place |
| >= 60 | **PARTIAL** | Significant coverage with material gaps |
| >= 33 | **AT_RISK** | Some controls exist but major blind spots |
| < 33 | **UNGOVERNED** | Minimal or no agent governance |

## Dimensions

### Core Governance (100 pts)

| ID | Dimension | Max | What Warden Checks |
|----|-----------|-----|---------------------|
| D1 | Tool Inventory | 25 | MCP configs, tool registries, schema definitions |
| D2 | Risk Detection | 20 | Semantic analysis, risk scoring, intent classification |
| D3 | Policy Coverage | 20 | Policy engines, allowlists/denylists, guard chains |
| D4 | Credential Management | 20 | Secrets in code, key rotation, vault usage, TLS |
| D5 | Log Hygiene | 10 | Structured logging, audit trails, hash chains |
| D6 | Framework Coverage | 5 | Detection of LangChain, AutoGen, CrewAI, LlamaIndex, etc. |

### Advanced Controls (50 pts)

| ID | Dimension | Max | What Warden Checks |
|----|-----------|-----|---------------------|
| D7 | Human-in-the-Loop | 15 | Approval gates, dry-run modes, confirmation flows |
| D8 | Agent Identity | 15 | Agent registries, identity tokens, delegation chains |
| D9 | Threat Detection | 20 | Circuit breakers, anomaly detection, kill switches, rate limiting |

### Ecosystem (55 pts)

| ID | Dimension | Max | What Warden Checks |
|----|-----------|-----|---------------------|
| D10 | Prompt Security | 15 | Injection detection, content filtering, input sanitization |
| D11 | Cloud / Platform | 10 | SSO/SAML/OIDC, RBAC, multi-tenant isolation |
| D12 | LLM Observability | 10 | Cost tracking, token usage, model analytics |
| D13 | Data Recovery | 10 | Rollback, snapshots, backup, restore capabilities |
| D14 | Compliance Maturity | 10 | Audit trails, regulatory mapping, CI/CD governance, lockfile hygiene |

### Unique Capabilities (30 pts)

| ID | Dimension | Max | What Warden Checks |
|----|-----------|-----|---------------------|
| D15 | Post-Exec Verification | 10 | Result validation, fingerprinting, output assurance |
| D16 | Data Flow Governance | 10 | PII detection, DLP, taint tracking, sensitivity labels |
| D17 | Adversarial Resilience | 10 | Trap defense (6 types), red team testing, canary tokens |

## 12 Scan Layers

1. **Code Patterns** — AST analysis of Python, regex scanning of JS/TS
2. **MCP Servers** — Configuration file analysis for auth, schemas, transport security
3. **Infrastructure** — Dockerfile, docker-compose, Kubernetes manifest checks
4. **Secrets** — 15+ credential patterns with value masking, regex definition filtering
5. **Agent Architecture** — Agent class analysis for permissions, lifecycle, cost tracking
6. **Supply Chain** — Dependency pinning, typosquat detection (Levenshtein), cloud PII services
7. **Audit & Compliance** — Audit logging patterns, compliance framework references
8. **CI/CD Governance** — GitHub Actions analysis for approvals, secrets, branch protection
9. **IaC Security** — Terraform, Pulumi, CloudFormation (encryption, security groups, IAM wildcards)
10. **Framework Governance** — LangChain callbacks, CrewAI guardrails, AutoGen sandboxing
11. **Multi-Language** — Go (context/exec), Rust (unsafe/.unwrap()), Java (Spring AI auth)
12. **Cloud AI** — AWS Bedrock, Azure AI Content Safety, GCP Vertex AI safety settings

Plus a dedicated **D17 Adversarial Resilience** scanner checking 8 sub-dimensions (4 defense + 4 testing).

## Scoring Integrity (v4.3)

### Pattern Tiers

Each dimension uses **strong** (governance-specific) and **weak** (generic) pattern lists:
- Strong patterns: 3 points each (e.g., `audit_log_tamper_proof`, `approval_gate_enforce`)
- Weak patterns: 1 point each (e.g., `audit_log`, `confirm_action`)
- Per-dimension cap prevents runaway scoring

### Co-Occurrence Requirements

Dimensions like D3 (Policy Coverage) and D11 (Cloud/Platform) require 3+ distinct patterns matched before awarding any points. A single keyword like "rbac" cannot inflate the score.

### CRITICAL Finding Deductions

After scoring, findings deduct from the earned score:
- Each CRITICAL finding: -2 points
- HIGH findings: -1 point (max 3)
- Total deduction capped at 60% of earned score

### Positive-Signal Scoring

"Absence of problems" earns minimal credit:
- D4 (Credential Management): zero secrets = 3 pts (not 10). Real D4 points require secrets manager, key rotation, KMS patterns.
- D14 (Compliance Maturity): lockfile present = 1 pt (not 4). Real D14 points require audit trails, compliance framework references, CI/CD governance.

### MCP Scoring

MCP server configs earn D1 credit only. D2/D3/D4 points require inline tool definitions that can be statically analyzed. Config-only entries (tools loaded at runtime) get minimal credit.

## Principles

1. **Local-only, privacy-first** — No data leaves the machine. Zero network calls.
2. **Conservative scoring** — Undetected = 0, not "unknown". No credit without evidence.
3. **Absence ≠ compliance** — Having no problems is not the same as having good practices.
4. **Balanced methodology** — Fair credit to all tool categories, not biased toward any vendor.
5. **Transparent and correctable** — Full methodology published. Vendor corrections welcome.
6. **Research-backed severity** — D17 cites Google DeepMind "AI Agent Traps" (March 2026) attack success rates.
7. **Compliance-mapped** — Findings map to EU AI Act articles, OWASP LLM Top 10, and MITRE ATLAS.

## False Positive Mitigation

- **Regex definition filter** — patterns that appear inside regex definitions (e.g., `re.compile(r"api_key=.*")`) are excluded from secrets detection
- **Test file reduction** — test files use reduced detector sets (critical-only)
- **Frontend exclusion** — UI/frontend files excluded from backend-focused checks
- **Lockfile/generated exclusion** — lockfiles and generated files skipped for secrets scanning
- **Typosquat precision** — edit distance = 1 only (not fuzzy matching)
- **Database URL split** — `postgres://user:pass@host` = CRITICAL; bare `redis://host:6379` = MEDIUM

## Vendor Corrections

If you believe your tool is scored incorrectly, open an issue with:
1. Which dimension(s) are affected
2. Evidence of the capability (docs, code, config examples)
3. Suggested score adjustment with justification

We commit to reviewing and responding within 5 business days.

## Known Limitations

**Static Analysis:** Warden detects governance *patterns*, not governance *enforcement*. A high score indicates presence of governance controls, not proof they are correctly implemented.

**Framework Vocabulary:** Scoring is optimized for recognized AI frameworks. Custom frameworks with equivalent controls may score lower due to pattern vocabulary differences.

**Local Filesystem:** Warden scans all files on disk, including gitignored files. Secrets in `.env` are flagged even if not committed to git.

**IaC Depth:** Terraform has the deepest analysis. Pulumi and CloudFormation checks are regex-based heuristics.

**Multi-Language AST:** Go/Rust/Java use regex analysis, not AST parsing. Fewer patterns detected than Python.
