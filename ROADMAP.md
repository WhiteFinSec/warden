# Warden Roadmap

Status as of **v1.7.0 in release** (2026-04-11).

Status tags:
- **TODO** — committed, will build soon
- **DEFER** — good idea, wait for demand or for a prerequisite to land
- **SKIP** — evaluated and rejected; listed here so we don't re-debate it
- **NEXT** — not code, unblocked, do it without debate

---

## What's Solid (shipped)

- 12 scan layers, 17 scoring dimensions, 124 tests
- Scoring model v4.3 with 6 anti-inflation mechanisms, no absence=compliance
- Privacy-first: zero network calls, secrets masked, self-contained HTML reports
- 3 output formats: HTML, JSON, SARIF (GitHub Code Scanning)
- 2 runtime deps only (click, rich)
- MCP risk classification with inline tool analysis
- Python 3.10+, PyPI published as `warden-ai`
- **Parallel scanning** — 9 layers run concurrently, 47s full scan on 2554-file project (2.2x faster than sequential)
- **Parallel secrets scanning** — per-file secrets scan runs on a thread pool (sequential fallback below 8 files), preserving gitignore downgrade and progress callback
- **Gitignore-aware secrets** — `.env` secrets downgraded to INFO, not CRITICAL
- **Positive-signal D4 & D14** — credentials and compliance dimensions reward active practices, not absence of problems
- **CI mode** — `--ci` and `--min-score` exit codes
- **`warden baseline`** — save findings, subsequent scans only show new ones (brownfield adoption)
- **`warden diff`** — compare two JSON reports, show score delta + new/resolved findings
- **`warden fix`** — auto-remediation for .gitignore, dep pinning, Dockerfile USER
- **`.warden.toml` / `[tool.warden]` config** — project-level defaults for format, skip, only, min_score, baseline, output_dir, ci. CLI flags override. Discovered by walking upward from the scan path until a VCS root
- **PDF reports** — `pip install warden-ai[pdf]` adds `--format pdf`; renders the existing HTML report via weasyprint for boardroom/auditor use. Core install stays lean (deps behind an extra)
- **GitHub Action** — composite `action.yml` at repo root with inputs for path/format/min-score/fail-on-level/baseline/skip/only, outputs for score/level/findings counts, and automatic SARIF upload to GitHub Code Scanning
- **Competitor detection** — 20 vendors, cross-checked scores (Zenity 55, Portkey 32, Noma 40, HiddenLayer 34, Protect AI 32 per 2026-04-10 research)
- **Sample report gallery** — `gallery/` builder scaffolds a static site of governance audits for 11 popular OSS AI frameworks (LangChain, LangGraph, CrewAI, AutoGen, Haystack, LlamaIndex, Semantic Kernel, PydanticAI, MetaGPT, Langflow, VigIA-Orchestrator). Stdlib-only build script, idempotent clones, per-target SEO landing pages with JSON-LD + OpenGraph, merged master index. Deploys to any static host (GitHub Pages / Caddy / Netlify)
- **C# / .NET scanner (Layer 13, second batch)** — regex detection of `Microsoft.Extensions.AI`, `Microsoft.SemanticKernel`, `IChatClient`, `[KernelFunction]`, `Result<T, E>`, `InvariantEnforcer`, `AuthorizationPolicyBuilder`, `ChatResponseFormat.CreateJsonSchemaFormat`, `ImmutableDictionary`, `readonly record struct`, `CancellationToken`, `DefaultAzureCredential`, `IHttpClientFactory`, and FSM-guarded state transitions. Scores C#/.NET projects on D1 / D7 / D8 / D14 / D17 without a Python bias
- **Absence-vs-coverage scoring fix** — absence-based findings are gated on `file_counts[lang] > 0` so pure C#/.NET projects no longer fire Python-scanner CRITICALs. Denominator exclusion at the scoring layer + finding-emission gating at the scanner layer (`trap_defense_scanner`, `audit_scanner`) via `file_counts` kwarg. VigIA-Orchestrator now scores 61/100 PARTIAL (was 2/100 UNGOVERNED coverage-failure artifact)

---

## Release & Distribution (v1.6.0)

### TODO

- **Push the current batch to origin/main**
  9 commits ahead as of 2026-04-11. Nothing downstream of `main` will
  see the shipped v1.5.6 items (G/B/C/F/E/J) or the VigIA-surfaced fix
  batch until this lands. One-liner, no debate.

- **Version bump 1.5.6 → 1.6.0, tag `v1.6.0`, publish to PyPI**
  Six shipped roadmap items (GitHub Action, `.warden.toml` config, PDF
  extras, parallel secrets, 20-vendor registry, gallery builder) plus
  the VigIA fix batch are user-visible. That's a minor bump, not a
  patch. Users need `pip install -U warden-ai` / `uvx warden-ai@1.6.0`
  to pick up PDF extras, the config file reader, and the fixed
  registry count. Tag drives the GitHub Marketplace listing below —
  Marketplace resolves `@v1` to the latest `v1.x.y` tag, so nothing
  further is needed on the action side once the tag exists.

- **GitHub Marketplace listing for the composite Action**
  `action.yml` at repo root is ready and tests green. The listing is
  a one-time click-through on the release page once `v1.6.0` is
  tagged: pick a category ("Security"), write a short description,
  upload the icon. Unlocks `uses: SharkRouter/warden@v1` for any
  GitHub workflow and opens the passive-lead-gen channel Web-Claude
  flagged as the main GTM lever.

---

## Product Work

### TODO

_(empty — Tier 1 shipped in v1.7.0, see Execution Order → Shipped in v1.7.0)_

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

Distribution TODOs are now consolidated under **Release & Distribution
(v1.6.0)** above — the gallery deploy, PyPI tag, and Marketplace listing
all live in the Tier 0 block so they get shipped as a single coherent
release, not as drifting GTM notes. Blog posts and the conference talk
live under **Execution Order → Tier 3** for the same reason.

This section previously held scattered NEXT items; they have been moved
into the structured Tier 0 / Tier 3 blocks to avoid having two places
that could disagree. If you're looking for "what's the next GTM move" —
check **Execution Order** at the bottom of this file.

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

### Shipped in v1.6.0 (tagged and released 2026-04-11)

1. ~~**G** — GitHub Action~~ (shipped 2026-04-10)
2. ~~**B** — Config file~~ (shipped 2026-04-10 — `.warden.toml` + `[tool.warden]`)
3. ~~**C** — PDF reports~~ (shipped 2026-04-10 — `warden-ai[pdf]` extra)
4. ~~**F** — Parallel secrets scanning~~ (shipped 2026-04-10 — `ThreadPoolExecutor` over `_scan_file`)
5. ~~**E** — Add Protect AI + HiddenLayer~~ (shipped 2026-04-10 — 20-vendor registry)
6. ~~**J** — Sample gallery site~~ (shipped 2026-04-10 — `gallery/` builder with 10 targets)
7. ~~**VigIA fix batch**~~ (committed 2026-04-11 — coverage warning, dynamic competitor count, `file_counts` + `coverage_warning` in JSON report)
8. ~~**Tier 0 #1** — Push `main` to origin~~ (2026-04-11)
9. ~~**Tier 0 #2** — Version bump 1.5.6 → 1.6.0, tag `v1.6.0`, PyPI publish~~ (2026-04-11, live at `pypi.org/project/warden-ai/1.6.0/`)
10. ~~**Tier 0 #3** — GitHub Release created with full notes~~ (2026-04-11 — Marketplace checkbox is a one-click manual step at `releases/tag/v1.6.0`)
11. ~~**Tier 0 #4** — Full 10-target gallery build + deploy~~ (2026-04-11 — live at `https://sharkrouter.github.io/warden/`, published from orphan `gh-pages` branch; Windows long-path fix committed so future fresh clones work on Windows too)

**Gallery scores captured for blog post series:**
langchain 13, langgraph 14, crewai 19, autogen 6, haystack 15, llamaindex 13, semantic-kernel 14, pydantic-ai 24, metagpt 11, langflow 18 — all UNGOVERNED.

### Shipped in v1.7.0 (tagged and released 2026-04-11)

1. ~~**Tier 1 #1 — C# / .NET scanner (Layer 13, second batch)**~~
   Shipped in commit `6a6144f`. Detects `Microsoft.Extensions.AI`,
   `IChatClient`, `[KernelFunction]`, `Result<T, E>`,
   `InvariantEnforcer`, `AuthorizationPolicyBuilder`,
   `ChatResponseFormat.CreateJsonSchemaFormat`, `ImmutableDictionary`,
   `readonly record struct`, `CancellationToken`, `DefaultAzureCredential`,
   `IHttpClientFactory`, and FSM-guarded state transitions. Scores
   C#/.NET projects on D1 / D7 / D8 / D14 / D17.
2. ~~**Tier 1 #2 — Absence-vs-coverage scoring fix**~~
   Shipped in commit `6a6144f`. Two-halves fix: denominator exclusion
   in `scoring/engine.py` plus finding-emission gating in
   `trap_defense_scanner` and `audit_scanner` via a `file_counts`
   kwarg. `functools.partial` pre-binds `file_counts` into the layer
   scanners at dispatch time. 6 new regression tests across
   `test_trap_defense.py` and `test_audit.py`.
3. ~~**Tier 1 #3 — VigIA gallery target #11**~~
   Shipped in commit `cfb2726`. `gallery/targets.toml` adds
   VigIA-Orchestrator as the first non-Python gallery target. VigIA
   now scores **61/100 PARTIAL** end-to-end (was 2/100 UNGOVERNED
   coverage-failure artifact before Tier 1 #1 and #2 landed). Proof
   that the C# scanner + coverage gate are both working on real
   .NET code, not just synthetic fixtures.
4. ~~**Version bump 1.6.0 → 1.7.0, tag `v1.7.0`, PyPI publish**~~
   Required because blog post #13 ("Why Every Python Agent Framework
   Scores UNGOVERNED") tells readers `pip install warden-ai` gets
   them the C#/.NET scanner and the coverage gate. Shipped as one
   release so that claim is true end-to-end the moment the post is
   live.
5. ~~**GitHub Release v1.7.0 with release notes**~~
   Covers the Tier 1 bundle, the VigIA before/after, and the scoring
   model hardening. Marketplace listing checkbox carried over from
   v1.6.0 (one-click manual step — still unchecked as of this release,
   same constraint as v1.6.0).
6. ~~**Full 11-target gallery rebuild + redeploy**~~
   First gallery run with VigIA + C# scanner + coverage gate all on.
   Published to `gh-pages` branch, live at
   `https://sharkrouter.github.io/warden/vigia-orchestrator/`.
7. ~~**Blog post #13 — "Why Every Python Agent Framework Scores UNGOVERNED"**~~
   Shipped in `sharkagent@2aafcb63` and deployed to sharkrouter.ai.
   Uses the 10-target Python gallery scores as the hook and the VigIA
   61/100 result as the counter-example. Gated on v1.7.0 being live
   on PyPI so the `pip install warden-ai` claim in the post is
   accurate.

### Next up (in order, not time — decision gates, not calendar days)

1. **Tier 3 — Blog post series (continued)**
   - Post #2: "How we fixed the 2/100 problem — C# scanner + coverage gating"
     (VigIA before/after case study, drafted alongside v1.7.0)
   - Post #3+: one per gallery target (LangChain deep-dive, AutoGen 6/100 anatomy, etc.), rolling cadence

2. **Conference talk / paper** — methodology writeup for a security venue. No concrete target yet; unblocked but waiting for a venue, not for code.

3. **GitHub Marketplace listing** — carryover from v1.6.0 and v1.7.0. One-click manual step on a GitHub release page. Still unchecked. Flag to user; can't be automated.
