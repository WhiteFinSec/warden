# Warden Roadmap

Status as of **v1.5.6** (2026-04-10).

Status tags:
- **TODO** — committed, will build soon
- **DEFER** — good idea, wait for demand or for a prerequisite to land
- **SKIP** — evaluated and rejected; listed here so we don't re-debate it

---

## What's Solid (shipped)

- 12 scan layers, 17 scoring dimensions, 102 tests
- Scoring model v4.3 with 6 anti-inflation mechanisms, no absence=compliance
- Privacy-first: zero network calls, secrets masked, self-contained HTML reports
- 3 output formats: HTML, JSON, SARIF (GitHub Code Scanning)
- 2 runtime deps only (click, rich)
- MCP risk classification with inline tool analysis
- Python 3.10+, PyPI published as `warden-ai`
- **Parallel scanning** — 9 layers run concurrently, 47s full scan on 2554-file project (2.2x faster than sequential)
- **Gitignore-aware secrets** — `.env` secrets downgraded to INFO, not CRITICAL
- **Positive-signal D4 & D14** — credentials and compliance dimensions reward active practices, not absence of problems
- **CI mode** — `--ci` and `--min-score` exit codes
- **`warden baseline`** — save findings, subsequent scans only show new ones (brownfield adoption)
- **`warden diff`** — compare two JSON reports, show score delta + new/resolved findings
- **`warden fix`** — auto-remediation for .gitignore, dep pinning, Dockerfile USER
- **Competitor detection** — 17 vendors, cross-checked scores (Zenity 55, Portkey 32, Noma 40 per 2026-04-10 research)

---

## Product Work

### TODO

- **[B] Config file (`.warden.yml`)**
  Project-level defaults for `skip`, `only`, `min_score`, `baseline`, `output_dir`.
  Every mature linter has this (ruff, eslint, mypy). Table-stakes for CI adoption
  so teams don't sprinkle the same flags across every workflow.

- **[C] PDF reports** (behind optional `pip install warden-ai[pdf]` extra)
  Boardroom-ready governance posture. CISOs and auditors don't read HTML files —
  they email PDFs. Heavy deps (weasyprint) stay behind an extra so the core install
  remains lean.

- **[F] Parallel secrets scanning**
  Secrets is still the single biggest per-layer bottleneck (~17-33s). ThreadPool
  over files inside `secrets_scanner`. Pure performance win, no behavioral change.

- **[E-partial] Add Protect AI + HiddenLayer competitors**
  Both are real shipping products teams deploy. Surgical additions, not bulk —
  detection accuracy matters more than registry size.

### DEFER

- **[I] VSCode extension**
  Value case is real (inline findings beat post-hoc CI feedback), but SARIF output
  already works with the built-in SARIF Viewer extension. Defer until there is
  actual user demand — don't build speculative IDE tooling.

- **Layer 13: API Gateway Governance**
  API key rotation, rate limiting, request signing in FastAPI/Express/Spring.
  Real value but no concrete target user yet.

- **Layer 14: Memory & State Governance**
  Unprotected vector DB access, RAG without access control, agent memory without
  TTL. Depends on RAG/memory adoption patterns stabilizing.

- **Plugin system**
  Custom scanners as Python packages (`warden-plugin-*` namespace, entry points).
  Only worth building when there is one external plugin author asking for it.

- **Scoring model v5**
  Weight dimensions by risk impact, not just presence/absence. v4.3 is working;
  don't re-score until we have real deployment data showing bias.

- **Confidence intervals**
  "73 ± 8" instead of raw score. Interesting but unclear it helps users act.

- **Custom scoring profiles**
  "Regulated enterprise" vs "startup MVP" weight presets. Good idea, wait for
  people to complain the default doesn't fit.

- **Trend tracking (`warden history`)**
  Reads past JSON reports, shows score over time. Valuable, but `warden diff`
  already covers the 2-point case and most teams don't keep report history.

- **Team dashboard**
  Aggregate scores across repos from CI artifacts. Useful for platforms teams
  but requires infra. Defer until gallery (J) proves demand.

- **Language Server Protocol**
  Real-time governance feedback in editors. Bigger version of VSCode extension —
  same defer reason.

- **AST for Go/Rust/Java**
  Replace regex with tree-sitter. Nice-to-have, but Python AST is already strong
  and multi-language regex catches enough for v1.

- **Compliance report generation**
  Map findings to SOC 2 / ISO 27001 / EU AI Act requirements, generate evidence
  docs. Depends on customers asking for specific format, not speculative.

- **Community rules repository**
  Shared detection patterns. Only useful after a community exists.

### SKIP

- **[A] `warden watch`** — file watcher mode
  Full scan is 47s; watcher firing on every save produces spam and battery drain.
  Baselines + CI already handle "catch regressions." Would require incremental
  scanning to be useful — a whole separate project. Not worth it.

- **[D] `--baseline-age`** — suppress only old findings
  Baseline format has no per-finding timestamps; adding them means a format
  migration and ongoing bookkeeping. The problem it solves (stale baselines) is
  already fixed by re-running `warden baseline`.

- **[H] Pre-commit hook package**
  Pre-commit is for sub-second linters. A 47s full scan at commit time gets
  disabled within a day. Wrong layer.

- **[E-skipped] Straiker, Aim Security, CalypsoAI, Checkmarx AI**
  Thin signal data, high false positive risk. Adding noise to a registry that
  values accuracy is a net negative.

- **Scoring "undetected" as partial credit**
  Users have asked for "maybe assume some compliance if we can't scan it."
  Refused — the whole point of Warden is that undetected = 0. Absence ≠ good.

---

## Distribution & GTM

### TODO

- **[G] GitHub Action marketplace listing** (`warden-ai/action@v1`)
  The highest-value distribution move. One-line CI integration turns Warden from
  "a thing you run locally" into "a thing every repo has." PR annotations via
  SARIF land findings directly in code review.

- **[J] Sample report gallery site**
  Static HTML reports for popular OSS: LangChain, CrewAI, AutoGen, Haystack,
  LlamaIndex, etc. Permanent search-indexable content, trust signal, social
  proof. When someone googles "langchain security audit," Warden shows up.

### DEFER

- **Blog post series** — "Why LangChain scores X/100" walkthroughs that feed
  the gallery. Depends on gallery being live first.

- **Conference talk / paper** — methodology writeup for security conferences.
  Valuable for credibility but needs a concrete target venue.

### SKIP

- **Homebrew formula / Scoop bucket** — package managers beyond pip. Python
  devs already have `pip install warden-ai` / `uvx warden-ai`. Cross-ecosystem
  packaging is maintenance burden without reach.

- **Docker image** — `docker run warden scan .` wrapper. Adds nothing over
  `uvx warden-ai scan .` which is already a one-liner.

---

## Principles (unchanged)

1. **Local-only forever** — no telemetry, no cloud, no data leaves the machine
2. **Zero heavy deps in core** — optional extras OK (`[pdf]`), core install slim
3. **Conservative scoring** — undetected = 0, never assume compliance; absence ≠ good
4. **Vendor-neutral** — fair scoring, corrections welcome, cross-checks documented
5. **Research-backed** — cite sources (DeepMind, OWASP, MITRE)

---

## Execution Order (current)

1. **G** — GitHub Action (distribution multiplier, makes everything else reach farther)
2. **B** — Config file (adoption table-stakes)
3. **C** — PDF reports (unlocks enterprise/compliance buyer)
4. **J** — Sample gallery site (SEO + social proof compounds)
5. **F** — Parallel secrets scanning (last perf polish)
6. **E** — Add Protect AI + HiddenLayer (surgical competitor additions)
