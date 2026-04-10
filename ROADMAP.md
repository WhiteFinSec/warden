# Warden Roadmap

Status as of **v1.5.6 shipped, v1.6.0 in prep** (2026-04-11).

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
- **Sample report gallery** — `gallery/` builder scaffolds a static site of governance audits for 10 popular OSS AI frameworks (LangChain, LangGraph, CrewAI, AutoGen, Haystack, LlamaIndex, Semantic Kernel, PydanticAI, MetaGPT, Langflow). Stdlib-only build script, idempotent clones, per-target SEO landing pages with JSON-LD + OpenGraph, merged master index. Deploys to any static host (GitHub Pages / Caddy / Netlify)

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

- **C# / .NET scanner (Layer 13: Multi-Language, second batch)** — **HIGHEST PRIORITY**
  Surfaced 2026-04-10 while scanning `JordanCT/VigIA-Orchestrator`, a
  pure-C# agent project. Warden indexed 0 files, fired absence-based
  CRITICAL findings on an empty scan, and scored 2/100 — punishing the
  project for a scanner blind spot, not a governance gap. C# / .NET is
  a primary AI agent stack (Semantic Kernel, MCP C# SDK, Copilot
  Studio), so this is the single highest-value language addition.

  Minimum viable scope: regex detection of `Microsoft.SemanticKernel`
  imports, `[KernelFunction]` attribute auditing, `ILogger`-based audit
  logging, `IChatCompletionService` usage, approval-gate patterns, and
  hardcoded credentials in `.config`/`.json`/`appsettings*.json`.
  Same architecture as `multilang_scanner.py` (regex, not AST).

  **Extended scope (from reading VigIA source):** detect `Result<T, E>`
  monadic error handling, `ImmutableDictionary` / `readonly record
  struct` for state invariants, C# Source Generator JSON contexts
  (`JsonSerializerContext`), `ChatResponseFormat.CreateJsonSchemaFormat`
  strict schema enforcement, and command interceptor / FSM transition
  patterns. These map directly onto D1 (policy enforcement), D7 (kill
  switch / hard block), D8 (agent identity), D14 (compliance), and
  D17 (trap defense) — so a well-governed .NET project like VigIA
  should score comparably to a well-governed Python project, not 2/100.

  **Test fixture:** VigIA itself. It's small, well-structured, uses
  `Microsoft.Extensions.AI` (canonical .NET LLM SDK), and already has
  InvariantEnforcer + 3-strike NACK + snapshot rollbacks as real
  governance patterns to detect. Target: VigIA should score ≥ 60
  (PARTIAL) once the scanner lands, ideally higher.

- **Absence-vs-coverage scoring fix (architectural)**
  The VigIA coverage warning shipped in the fix batch is a band-aid
  at the CLI layer. The real bug is in `scoring/engine.py`: absence-
  based findings fire even when the relevant language wasn't scanned
  at all. A pure C# project gets CRITICAL findings like "No audit
  logging for tool calls detected" because Warden didn't find any
  Python `logging` calls — but it never had a chance to.

  Fix: gate absence-based findings on `result.file_counts[lang] > 0`
  for the language a dimension actually scans. Add a `coverage_gate`
  flag per dimension (or per finding template) so "we didn't look"
  becomes an `INFO`-level "not scanned" entry, not a CRITICAL finding.
  The overall score for an unscanned project should clamp to "N/A —
  coverage failure" instead of a number.

  This is the real fix for the "2/100 on any non-Python project"
  foot-gun, and it's independent of the C# scanner — but both should
  land in v1.7.0 together, because they're two halves of the same
  problem: "Warden needs to tell coverage failures apart from
  governance failures, and it needs to fix the coverage gaps for the
  languages that matter."

- **Add VigIA to the gallery target list (after the C# scanner lands)**
  Proof-by-example that Warden now handles .NET. `gallery/targets.toml`
  already has 10 Python/JS targets; adding VigIA as target #11 once
  the C# scanner is in gives a concrete "before 2/100, after ≥60"
  narrative for the blog post series. One line in `targets.toml`, one
  paragraph in the blog post. Blocked on the C# scanner, not on
  anything else.

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

### Shipped in v1.5.6 (committed 2026-04-10, tagged next as v1.6.0)

1. ~~**G** — GitHub Action~~ (shipped 2026-04-10)
2. ~~**B** — Config file~~ (shipped 2026-04-10 — `.warden.toml` + `[tool.warden]`)
3. ~~**C** — PDF reports~~ (shipped 2026-04-10 — `warden-ai[pdf]` extra)
4. ~~**F** — Parallel secrets scanning~~ (shipped 2026-04-10 — `ThreadPoolExecutor` over `_scan_file`)
5. ~~**E** — Add Protect AI + HiddenLayer~~ (shipped 2026-04-10 — 20-vendor registry)
6. ~~**J** — Sample gallery site~~ (shipped 2026-04-10 — `gallery/` builder with 10 targets, 3 validated, SEO landing pages ready to deploy)
7. ~~**VigIA fix batch**~~ (committed 2026-04-11 — coverage warning, dynamic competitor count, `file_counts` + `coverage_warning` in JSON report)

**All six committed TODO items plus the VigIA fix batch are now on `main`, ahead of origin.**

### Next up (in order, not time — decision gates, not calendar days)

1. **Tier 0 — Ship v1.6.0**
   - `git push origin main` (9 commits ahead)
   - Bump version 1.5.6 → 1.6.0, tag `v1.6.0`, publish to PyPI
   - Click-through GitHub Marketplace listing for the composite Action
   - Full 10-target gallery build, deploy `gallery/out/` to Caddy (or GH Pages)

2. **Tier 1 — C#/.NET scanner + absence-vs-coverage fix (v1.7.0)**
   - Implement C# / .NET regex scanner in `warden/scanner/multilang_scanner.py` extension
   - Ship absence-vs-coverage scoring fix in `scoring/engine.py` at the same time
   - Validate both against VigIA-Orchestrator as the test fixture — target: VigIA scores ≥ 60 (PARTIAL), down from the current 2/100 coverage-failure artifact
   - Add VigIA as gallery target #11 as proof-by-example

3. **Tier 3 — Blog post series**
   - Post #1: "Why LangChain scores X/100" — walkthrough of the first validated gallery target, using the fresh gallery site as evidence
   - Post #2: "How we fixed the 2/100 problem — C# scanner + coverage gating"
     (only possible after Tier 1 lands, uses VigIA as the before/after case study)
   - Post #3+: one per gallery target, rolling cadence

4. **Conference talk / paper** — methodology writeup for a security venue. No concrete target yet; unblocked but waiting for a venue, not for code.
