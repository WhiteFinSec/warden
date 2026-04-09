# Warden Roadmap

Status as of v1.5.3 (2026-04-10).

## What's Solid

- 12 scan layers, 17 scoring dimensions, 102 tests
- Scoring model v4.3 with 6 anti-inflation mechanisms
- Privacy-first: zero network calls, secrets masked, self-contained HTML reports
- 3 output formats: HTML, JSON, SARIF (GitHub Code Scanning)
- 2 runtime deps only (click, rich)
- MCP risk classification with inline tool analysis
- Python 3.10+, PyPI published as `warden-ai`

## Near-Term (v1.6.x)

### Hardening

- [ ] **Gitignore-aware secrets scanning** — differentiate between committed and gitignored files. Secrets in `.env` (gitignored) should be INFO, not CRITICAL.
- [ ] **Per-file pattern matching** for competitor detection — replace giant concatenated string with per-file regex + early exit.
- [ ] **CI pipeline** — GitHub Actions: lint (ruff), test (pytest), build (uv build) on every PR. Trusted publishing on tag push (already exists for releases).

### UX

- [ ] **`warden fix`** — auto-remediation for common findings (add .gitignore entries, pin deps, add USER to Dockerfile)
- [ ] **`warden diff`** — compare two scan results (before/after), show score delta
- [ ] **`warden watch`** — file watcher mode, re-scan on change (useful in CI pre-commit)
- [ ] **Exit codes** — `warden scan` returns 0 for GOVERNED, 1 for PARTIAL, 2 for AT_RISK, 3 for UNGOVERNED. Enables CI gating.

### Scanner Coverage

- [ ] **Layer 13: API Gateway Governance** — detect API key rotation, rate limiting, request signing in FastAPI/Express/Spring configs
- [ ] **Layer 14: Memory & State Governance** — detect unprotected vector DB access, RAG pipeline without access control, agent memory without TTL

## Mid-Term (v2.0)

### Architecture

- [ ] **Plugin system** — allow users to add custom scanners as Python packages (`warden-plugin-*` namespace). Each plugin registers scan layers via entry points.
- [ ] **Config file** — `warden.toml` or `.wardenrc` for project-level settings (severity thresholds, ignored paths, custom rules, baseline file)
- [ ] **Baseline / suppress** — `warden baseline` saves current findings; subsequent scans only report NEW findings. Critical for adoption in brownfield projects.
- [ ] **Parallel scanning** — run layers concurrently (ThreadPoolExecutor per layer). Currently sequential.

### Scoring

- [ ] **Scoring model v5** — weight dimensions by risk impact, not just presence/absence. D4 (credentials) should matter more than D12 (observability).
- [ ] **Confidence intervals** — instead of raw score, report "73 +/- 8" to acknowledge static analysis uncertainty
- [ ] **Custom scoring profiles** — different weight presets for "regulated enterprise" vs "startup MVP" vs "open source library"

### Reporting

- [ ] **PDF reports** — boardroom-ready governance posture report
- [ ] **Trend tracking** — `warden history` reads past JSON reports, shows score over time
- [ ] **Team dashboard** — aggregate scores across multiple repos (reads JSON reports from CI artifacts)

## Long-Term (v3.0)

- [ ] **Language Server Protocol** — real-time governance feedback in VS Code / JetBrains
- [ ] **AST analysis for Go/Rust/Java** — replace regex with tree-sitter for multi-language scanning
- [ ] **Runtime verification** — optional agent that checks governance at runtime (complements static analysis)
- [ ] **Compliance report generation** — map findings to SOC 2 / ISO 27001 / EU AI Act requirements and generate compliance evidence documents
- [ ] **Community rules** — shared rule repository where users contribute detection patterns

## Principles

1. **Local-only forever** — no telemetry, no cloud, no data leaves the machine
2. **Zero heavy deps** — keep install under 5 seconds, no binary extensions
3. **Conservative scoring** — undetected = 0, never assume compliance; absence ≠ good
4. **Vendor-neutral** — fair scoring methodology, vendor corrections welcome
5. **Research-backed** — cite sources for severity ratings (DeepMind, OWASP, MITRE)
