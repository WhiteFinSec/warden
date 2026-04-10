#!/usr/bin/env python3
"""Warden Gallery builder — scans popular OSS AI projects, generates a static site.

Usage:
    python gallery/build.py              # Build full gallery (clones + scans all targets)
    python gallery/build.py --only langchain,crewai  # Only specific slugs
    python gallery/build.py --skip langchain          # Skip specific slugs
    python gallery/build.py --no-clone    # Use existing clones (for iteration)
    python gallery/build.py --clean       # Wipe out/ and repos/ first

Output layout:
    gallery/
        out/
            index.html                 # Master gallery page
            assets/
                gallery.css            # Shared styles
            <slug>/
                index.html             # SEO landing with summary + link to report
                report.html            # Full warden HTML report (as generated)
                report.json            # Machine-readable scan result
        repos/
            <slug>/                    # Local clone (gitignored)

The builder is idempotent: re-running only re-scans targets whose HEAD has
moved since the last run. Use --no-clone to skip the git fetch (fastest
iteration when only the template/index changed).
"""

from __future__ import annotations

import argparse
import html
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

# Force UTF-8 stdout on Windows (cp1252 default would crash on any non-ASCII
# byte from warden's rich output or HTML/TOML content echoed to the console).
# reconfigure() is only available on TextIOWrapper (3.7+). It raises
# io.UnsupportedOperation when the stream is already detached (e.g. the
# harness captured it) and ValueError if data has already been written. In
# both cases the fallback is "keep the existing encoding" — any print that
# then hits a non-ASCII char will surface a real UnicodeEncodeError loudly,
# which is what we want for a build script.
if hasattr(sys.stdout, "reconfigure"):
    import io
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except (io.UnsupportedOperation, ValueError) as exc:
            print(
                f"gallery/build.py: could not set UTF-8 on {stream.name}: {exc}",
                file=sys.__stderr__,
            )

# --- Paths -----------------------------------------------------------------

GALLERY_DIR = Path(__file__).resolve().parent
REPO_ROOT = GALLERY_DIR.parent
OUT_DIR = GALLERY_DIR / "out"
REPOS_DIR = GALLERY_DIR / "repos"
TARGETS_FILE = GALLERY_DIR / "targets.toml"
INDEX_TEMPLATE = GALLERY_DIR / "index_template.html"

# --- TOML loader (stdlib on 3.11+, tomli fallback on 3.10) ----------------

try:
    import tomllib  # type: ignore[import-not-found]
except ModuleNotFoundError:  # pragma: no cover — Python 3.10 fallback
    import tomli as tomllib  # type: ignore[import-not-found,no-redef]


# --- Target model ----------------------------------------------------------


@dataclass(frozen=True)
class Target:
    slug: str
    name: str
    repo: str  # e.g. "langchain-ai/langchain"
    category: str
    description: str
    scan_path: str = ""  # Subdir to scan; empty = whole repo
    homepage: str = ""

    @property
    def clone_url(self) -> str:
        return f"https://github.com/{self.repo}.git"

    @property
    def clone_dir(self) -> Path:
        return REPOS_DIR / self.slug

    @property
    def scan_target(self) -> Path:
        if self.scan_path:
            return self.clone_dir / self.scan_path
        return self.clone_dir

    @property
    def out_dir(self) -> Path:
        return OUT_DIR / self.slug


def load_targets() -> list[Target]:
    with TARGETS_FILE.open("rb") as f:
        data = tomllib.load(f)
    return [Target(**t) for t in data.get("target", [])]


# --- Git helpers -----------------------------------------------------------


def _run(cmd: list[str], cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run a subprocess, raise on failure unless check=False."""
    return subprocess.run(
        cmd, cwd=str(cwd) if cwd else None,
        capture_output=True, text=True, check=check,
    )


def clone_or_update(target: Target) -> str:
    """Ensure `target.clone_dir` is a shallow clone at current default HEAD.

    Returns the current commit SHA.
    """
    REPOS_DIR.mkdir(parents=True, exist_ok=True)
    # `-c core.longpaths=true` lets git succeed on Windows even when a target
    # has files whose absolute path exceeds MAX_PATH (260 chars). Haystack's
    # docs-website/ has URL-encoded image filenames that trip this; without
    # the flag, clone and reset --hard both abort with exit 128. Applied to
    # every git invocation here so both fresh clones and updates are covered.
    LP = ["-c", "core.longpaths=true"]
    if target.clone_dir.exists():
        # Update existing clone. Use fetch + reset rather than pull to avoid
        # merge commits and to survive force-pushes on the default branch.
        print(f"  [update] {target.slug}")
        _run(["git", *LP, "-C", str(target.clone_dir), "fetch", "--depth=1", "origin"], check=False)
        # Determine the default branch from origin/HEAD; fall back to main/master.
        head = _run(
            ["git", *LP, "-C", str(target.clone_dir), "symbolic-ref", "refs/remotes/origin/HEAD"],
            check=False,
        )
        if head.returncode == 0 and head.stdout.strip():
            ref = head.stdout.strip().split("/")[-1]
        else:
            ref = "main"
        _run(["git", *LP, "-C", str(target.clone_dir), "reset", "--hard", f"origin/{ref}"], check=False)
    else:
        print(f"  [clone]  {target.slug} from {target.clone_url}")
        _run(["git", *LP, "clone", "--depth=1", target.clone_url, str(target.clone_dir)])

    sha = _run(["git", "-C", str(target.clone_dir), "rev-parse", "HEAD"]).stdout.strip()
    return sha


# --- Warden scan runner ----------------------------------------------------


def run_warden_scan(target: Target) -> dict | None:
    """Run `warden scan` on a target, dropping reports into its out_dir.

    Returns the parsed JSON report dict on success, None on failure.
    """
    target.out_dir.mkdir(parents=True, exist_ok=True)
    if not target.scan_target.exists():
        print(f"  [FAIL]{target.slug}: scan path missing: {target.scan_target}")
        return None

    # Invoke the local warden install via the current Python, so the gallery
    # always tests the version in this checkout (not whatever's on PATH).
    cmd = [
        sys.executable, "-m", "warden", "scan",
        str(target.scan_target),
        "--format", "all",
        "--output-dir", str(target.out_dir),
        "--no-config",  # Gallery builds must ignore any stray .warden.toml
    ]
    print(f"  [scan]   {target.slug}")
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)

    # Warden exits non-zero when `min_score` fails, but still writes reports.
    # Treat exit codes 0 and 1 as "scan completed"; anything else is a crash.
    if result.returncode not in (0, 1):
        print(f"  [FAIL]{target.slug}: warden crashed (exit {result.returncode})")
        print(f"      stderr: {result.stderr.strip()[:500]}")
        return None

    # Warden writes warden_report.{html,json,sarif} by default.
    json_path = target.out_dir / "warden_report.json"
    html_path = target.out_dir / "warden_report.html"
    if not json_path.exists() or not html_path.exists():
        print(f"  [FAIL]{target.slug}: expected reports not found in {target.out_dir}")
        return None

    # Rename to friendlier paths so gallery URLs are clean.
    json_path.replace(target.out_dir / "report.json")
    html_path.replace(target.out_dir / "report.html")
    for leftover in ("warden_report.sarif",):
        p = target.out_dir / leftover
        if p.exists():
            p.replace(target.out_dir / leftover.replace("warden_report", "report"))

    with (target.out_dir / "report.json").open("r", encoding="utf-8") as f:
        return json.load(f)


# --- Landing page + index generation --------------------------------------


LEVEL_COLORS = {
    "GOVERNED": "#22c55e",
    "PARTIAL": "#eab308",
    "AT_RISK": "#f97316",
    "UNGOVERNED": "#ef4444",
    "UNKNOWN": "#94a3b8",
}


def _level_color(level: str) -> str:
    return LEVEL_COLORS.get(level.upper(), LEVEL_COLORS["UNKNOWN"])


def write_target_landing(target: Target, report: dict, sha: str) -> None:
    """Write an SEO-friendly landing page that links to the full report."""
    score = report.get("score", {})
    total = score.get("total", 0)
    level = score.get("level", "UNKNOWN")
    raw_total = score.get("raw_total", 0)
    raw_max = score.get("raw_max", 235)
    findings = report.get("findings", [])
    critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high = sum(1 for f in findings if f.get("severity") == "HIGH")
    medium = sum(1 for f in findings if f.get("severity") == "MEDIUM")

    title = f"{target.name} governance audit — Warden score {total}/100"
    desc = (
        f"Automated AI-agent governance scan of {target.name} ({target.repo}). "
        f"Score: {total}/100 ({level}). {critical} critical, {high} high, "
        f"{medium} medium findings. Run by Warden, the open-source AI agent scanner."
    )
    canonical = f"https://warden.sharkrouter.ai/gallery/{target.slug}/"

    # JSON-LD Dataset schema for rich search results.
    jsonld = {
        "@context": "https://schema.org",
        "@type": "Dataset",
        "name": title,
        "description": desc,
        "url": canonical,
        "creator": {"@type": "Organization", "name": "Warden"},
        "license": "https://opensource.org/licenses/MIT",
        "keywords": [
            "AI governance",
            "AI security",
            "agent security",
            target.name,
            target.category,
        ],
        "variableMeasured": [
            {"@type": "PropertyValue", "name": "Warden Score", "value": total, "unitText": "/100"},
            {"@type": "PropertyValue", "name": "Governance Level", "value": level},
        ],
        "temporalCoverage": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
    }

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title>
<meta name="description" content="{html.escape(desc)}">
<link rel="canonical" href="{canonical}">
<meta property="og:type" content="article">
<meta property="og:title" content="{html.escape(title)}">
<meta property="og:description" content="{html.escape(desc)}">
<meta property="og:url" content="{canonical}">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="{html.escape(title)}">
<meta name="twitter:description" content="{html.escape(desc)}">
<link rel="stylesheet" href="../assets/gallery.css">
<script type="application/ld+json">{json.dumps(jsonld, indent=2)}</script>
</head>
<body>
<header class="gallery-header">
  <a href="../index.html" class="back">← Warden Gallery</a>
  <h1>{html.escape(target.name)} <span class="muted">governance audit</span></h1>
  <p class="sub">{html.escape(target.description)}</p>
  <p class="meta">
    Repo: <a href="https://github.com/{target.repo}" target="_blank"
      rel="noopener">github.com/{html.escape(target.repo)}</a>
    · Commit: <code>{sha[:7]}</code>
    · Scanned: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}
    · Warden v{report.get('version', '?')}
  </p>
</header>

<section class="score-card" style="border-color:{_level_color(level)}">
  <div class="score-main">
    <div class="score-value" style="color:{_level_color(level)}">{total}<span class="score-denom">/100</span></div>
    <div class="score-level" style="color:{_level_color(level)}">{html.escape(level)}</div>
  </div>
  <dl class="score-stats">
    <dt>Raw points</dt><dd>{raw_total} / {raw_max}</dd>
    <dt>Critical</dt><dd class="crit">{critical}</dd>
    <dt>High</dt><dd class="high">{high}</dd>
    <dt>Medium</dt><dd class="med">{medium}</dd>
    <dt>Total findings</dt><dd>{len(findings)}</dd>
  </dl>
</section>

<section class="cta">
  <a class="btn primary" href="report.html">View full HTML report</a>
  <a class="btn" href="report.json">Download JSON</a>
  <a class="btn" href="https://github.com/SharkRouter/warden">Run Warden yourself</a>
</section>

<section class="about">
  <h2>What does this score mean?</h2>
  <p>
    Warden evaluates AI-agent projects across <strong>17 governance dimensions</strong>:
    tool-call enforcement, agent identity, human-in-the-loop, audit trails,
    credential management, supply-chain security, trap defense, and more.
    Scores are normalized to 0–100 from 235 raw points. See the
    <a href="https://github.com/SharkRouter/warden/blob/main/docs/SCORING.md">full methodology</a>
    for how each dimension is calculated.
  </p>
  <p>
    A score below 33 is <strong>UNGOVERNED</strong>, 33–59 is <strong>AT_RISK</strong>,
    60–79 is <strong>PARTIAL</strong>, and 80+ is <strong>GOVERNED</strong>.
    Most general-purpose AI frameworks land in the AT_RISK or PARTIAL tiers —
    that's expected, because they are <em>libraries</em>, not governance platforms.
    The score reflects the governance posture of the framework's own source,
    not of any given application built on top of it.
  </p>
  <p class="disclaimer">
    This is an automated scan of open-source code. Warden is vendor-neutral
    and maintains a public
    <a href="https://github.com/SharkRouter/warden/blob/main/pyproject.toml">scoring model</a>.
    Framework maintainers are welcome to open an issue with corrections.
  </p>
</section>

<footer>
  <p>
    Generated by <a href="https://github.com/SharkRouter/warden">Warden</a>,
    the open-source AI agent governance scanner.
  </p>
</footer>
</body>
</html>
"""
    (target.out_dir / "index.html").write_text(html_doc, encoding="utf-8")


def _collect_existing_reports(
    scanned: list[tuple[Target, dict, str]],
) -> list[tuple[Target, dict, str]]:
    """Combine this run's results with reports already on disk.

    Running `build.py --only X` should not wipe other targets from the
    master index. We merge this run's results with any `out/<slug>/report.json`
    files that survived from earlier runs, deduping by slug (this run wins).
    """
    by_slug: dict[str, tuple[Target, dict, str]] = {t.slug: (t, r, s) for t, r, s in scanned}
    all_targets = {t.slug: t for t in load_targets()}

    if OUT_DIR.exists():
        for child in OUT_DIR.iterdir():
            if not child.is_dir() or child.name == "assets":
                continue
            slug = child.name
            if slug in by_slug:
                continue  # fresh result already present
            report_path = child / "report.json"
            if not report_path.exists():
                continue
            target = all_targets.get(slug)
            if target is None:
                # Report exists for a slug no longer in targets.toml —
                # skip it rather than render a dangling row.
                continue
            try:
                report = json.loads(report_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as exc:
                print(f"  [WARN] could not reuse {slug}: {exc}")
                continue
            by_slug[slug] = (target, report, "previous-run")

    return list(by_slug.values())


def write_master_index(scanned: list[tuple[Target, dict, str]]) -> None:
    """Write gallery/out/index.html listing all gallery targets with a report.

    Combines this run's fresh results with reports from earlier partial runs
    so `--only X` doesn't drop sibling targets from the index.
    """
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    all_reports = _collect_existing_reports(scanned)

    # Sort by score descending so the "best" governance postures lead.
    scanned_sorted = sorted(
        all_reports,
        key=lambda item: item[1].get("score", {}).get("total", 0),
        reverse=True,
    )

    rows = []
    for target, report, _sha in scanned_sorted:
        score = report.get("score", {})
        total = score.get("total", 0)
        level = score.get("level", "UNKNOWN")
        color = _level_color(level)
        findings = report.get("findings", [])
        critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        rows.append(f"""
        <tr>
          <td><a href="{target.slug}/index.html"><strong>{html.escape(target.name)}</strong></a></td>
          <td class="muted">{html.escape(target.category)}</td>
          <td class="desc">{html.escape(target.description)}</td>
          <td class="score" style="color:{color}"><strong>{total}</strong>/100</td>
          <td class="level" style="color:{color}">{html.escape(level)}</td>
          <td class="crit-count">{critical}</td>
          <td><a href="{target.slug}/index.html">Audit →</a></td>
        </tr>""")

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    description = (
        "Automated AI-agent governance scans of popular open-source frameworks: "
        "LangChain, CrewAI, AutoGen, Haystack, LlamaIndex, Semantic Kernel, and more. "
        "Run by Warden, the open-source scanner."
    )

    index_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Warden Gallery — AI agent framework governance audits</title>
<meta name="description" content="{html.escape(description)}">
<link rel="canonical" href="https://warden.sharkrouter.ai/gallery/">
<meta property="og:title" content="Warden Gallery — AI framework governance audits">
<meta property="og:description" content="{html.escape(description)}">
<meta property="og:url" content="https://warden.sharkrouter.ai/gallery/">
<link rel="stylesheet" href="assets/gallery.css">
</head>
<body>
<header class="gallery-header">
  <h1>Warden Gallery</h1>
  <p class="sub">
    Automated governance audits of the most popular open-source
    AI-agent frameworks — scored on 17 dimensions across 12 scan layers.
  </p>
  <p class="meta">Last rebuilt: {timestamp} · {len(scanned_sorted)} projects scanned</p>
</header>

<section class="intro">
  <p>
    <strong>What is this?</strong> Warden is an open-source CLI scanner that evaluates
    AI-agent projects across 17 governance dimensions: tool-call enforcement,
    agent identity, audit trails, credential management, supply-chain, trap defense,
    and more. Every project below was scanned with the latest version of Warden,
    producing the same HTML report you'd get locally by running
    <code>pip install warden-ai &amp;&amp; warden scan &lt;path&gt;</code>.
  </p>
  <p>
    <strong>What do the scores mean?</strong> These scores reflect the governance
    posture of the framework's <em>own source code</em>, not of applications built
    on top of it. Most general-purpose frameworks land in AT_RISK or PARTIAL
    territory — that's expected. They are <em>libraries</em>, not governance platforms.
    If your team needs full gateway-level enforcement, you probably want a dedicated
    runtime layer on top.
  </p>
</section>

<table class="gallery-table">
  <thead>
    <tr>
      <th>Project</th>
      <th>Category</th>
      <th>Description</th>
      <th>Score</th>
      <th>Level</th>
      <th>Critical</th>
      <th></th>
    </tr>
  </thead>
  <tbody>{''.join(rows)}
  </tbody>
</table>

<section class="cta">
  <h2>Run Warden on your own project</h2>
  <pre><code>pip install warden-ai
warden scan /path/to/your/project</code></pre>
  <p>
    Zero telemetry, zero cloud calls. Everything runs locally.
    See <a href="https://github.com/SharkRouter/warden">github.com/SharkRouter/warden</a>
    for the source, scoring model, and methodology.
  </p>
</section>

<footer>
  <p>
    Generated by <a href="https://github.com/SharkRouter/warden">Warden</a>
    · MIT licensed · Scans are automated and vendor-neutral
    · Framework maintainers: <a href="https://github.com/SharkRouter/warden/issues">open an issue</a>
    for corrections.
  </p>
</footer>
</body>
</html>
"""
    (OUT_DIR / "index.html").write_text(index_html, encoding="utf-8")


def write_gallery_css() -> None:
    assets = OUT_DIR / "assets"
    assets.mkdir(parents=True, exist_ok=True)
    css = """/* Warden Gallery — shared styles */
:root {
  --bg: #0b0f17;
  --card: #141a26;
  --text: #e2e8f0;
  --muted: #94a3b8;
  --border: #1f2937;
  --accent: #38bdf8;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.6;
}
.gallery-header {
  max-width: 1100px;
  margin: 0 auto;
  padding: 3rem 1.5rem 1.5rem;
}
.gallery-header h1 {
  font-size: 2.25rem;
  margin: 0 0 0.5rem;
}
.gallery-header .sub {
  color: var(--muted);
  font-size: 1.1rem;
  margin: 0 0 0.75rem;
  max-width: 65ch;
}
.gallery-header .meta {
  color: var(--muted);
  font-size: 0.9rem;
  margin: 0;
}
.gallery-header .meta code {
  background: var(--card);
  padding: 2px 6px;
  border-radius: 3px;
  font-size: 0.85em;
}
.back {
  display: inline-block;
  color: var(--accent);
  text-decoration: none;
  margin-bottom: 1rem;
  font-size: 0.9rem;
}
.back:hover { text-decoration: underline; }
.muted { color: var(--muted); }

.intro, .about, .cta {
  max-width: 1100px;
  margin: 0 auto;
  padding: 1rem 1.5rem;
}
.intro p, .about p { max-width: 75ch; }

.gallery-table {
  width: calc(100% - 3rem);
  max-width: 1100px;
  margin: 1.5rem auto;
  border-collapse: collapse;
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 8px;
  overflow: hidden;
}
.gallery-table th, .gallery-table td {
  padding: 0.75rem 1rem;
  text-align: left;
  border-bottom: 1px solid var(--border);
}
.gallery-table th {
  font-size: 0.8rem;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--muted);
  background: rgba(255,255,255,0.02);
}
.gallery-table tr:last-child td { border-bottom: none; }
.gallery-table a {
  color: var(--accent);
  text-decoration: none;
}
.gallery-table a:hover { text-decoration: underline; }
.gallery-table .desc {
  color: var(--muted);
  max-width: 340px;
  font-size: 0.9rem;
}
.gallery-table .score { font-size: 1.15rem; text-align: right; }
.gallery-table .level { font-weight: 600; font-size: 0.85rem; }
.gallery-table .crit-count { text-align: center; color: #ef4444; }

.score-card {
  max-width: 1100px;
  margin: 1.5rem auto;
  padding: 2rem;
  background: var(--card);
  border: 2px solid var(--border);
  border-radius: 12px;
  display: grid;
  grid-template-columns: auto 1fr;
  gap: 2rem;
  align-items: center;
}
.score-value {
  font-size: 4.5rem;
  font-weight: 700;
  line-height: 1;
}
.score-denom {
  font-size: 1.5rem;
  color: var(--muted);
  font-weight: 400;
}
.score-level {
  font-size: 1rem;
  letter-spacing: 1px;
  text-transform: uppercase;
  font-weight: 700;
  margin-top: 0.25rem;
}
.score-stats {
  display: grid;
  grid-template-columns: auto 1fr;
  gap: 0.35rem 1.5rem;
  margin: 0;
}
.score-stats dt { color: var(--muted); font-size: 0.9rem; }
.score-stats dd { margin: 0; font-weight: 600; }
.score-stats .crit { color: #ef4444; }
.score-stats .high { color: #f97316; }
.score-stats .med  { color: #eab308; }

.cta {
  display: flex;
  gap: 0.75rem;
  flex-wrap: wrap;
  margin: 1.5rem auto;
}
.cta h2 { width: 100%; }
.btn {
  display: inline-block;
  padding: 0.6rem 1.1rem;
  background: var(--card);
  color: var(--text);
  text-decoration: none;
  border: 1px solid var(--border);
  border-radius: 6px;
  font-size: 0.95rem;
  transition: all 0.15s;
}
.btn:hover { border-color: var(--accent); }
.btn.primary { background: var(--accent); color: #0b0f17; border-color: var(--accent); font-weight: 600; }
.btn.primary:hover { filter: brightness(1.1); }

pre {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 1rem;
  overflow-x: auto;
}
code { font-family: 'SF Mono', 'Monaco', 'Consolas', monospace; font-size: 0.9em; }

.disclaimer { color: var(--muted); font-size: 0.85rem; }

footer {
  max-width: 1100px;
  margin: 3rem auto 1.5rem;
  padding: 1.5rem;
  border-top: 1px solid var(--border);
  color: var(--muted);
  font-size: 0.85rem;
}
footer a { color: var(--accent); text-decoration: none; }
footer a:hover { text-decoration: underline; }

@media (max-width: 720px) {
  .gallery-table .desc { display: none; }
  .score-card { grid-template-columns: 1fr; }
}
"""
    (assets / "gallery.css").write_text(css, encoding="utf-8")


# --- Main ------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Build the Warden sample report gallery")
    ap.add_argument("--only", help="Comma-separated slugs to build (default: all)")
    ap.add_argument("--skip", help="Comma-separated slugs to skip")
    ap.add_argument("--no-clone", action="store_true",
                    help="Skip git clone/fetch - use existing repos/ only")
    ap.add_argument("--clean", action="store_true",
                    help="Wipe out/ and repos/ before building")
    return ap.parse_args()


def main() -> int:
    args = parse_args()

    if args.clean:
        for d in (OUT_DIR, REPOS_DIR):
            if d.exists():
                print(f"  [FAIL]removing {d}")
                shutil.rmtree(d)

    targets = load_targets()
    only = set(args.only.split(",")) if args.only else None
    skip = set(args.skip.split(",")) if args.skip else set()
    if only:
        targets = [t for t in targets if t.slug in only]
    targets = [t for t in targets if t.slug not in skip]

    if not targets:
        print("No targets selected.")
        return 1

    print(f"Building gallery for {len(targets)} target(s)...\n")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    write_gallery_css()

    scanned: list[tuple[Target, dict, str]] = []
    failed: list[tuple[Target, str]] = []

    for target in targets:
        print(f"[{target.slug}] {target.name}")
        try:
            if args.no_clone and target.clone_dir.exists():
                sha = _run(
                    ["git", "-C", str(target.clone_dir), "rev-parse", "HEAD"],
                ).stdout.strip()
            else:
                sha = clone_or_update(target)
        except subprocess.CalledProcessError as exc:
            print(f"  [FAIL]git failed: {exc.stderr.strip()[:300]}")
            failed.append((target, f"git: {exc}"))
            continue

        report = run_warden_scan(target)
        if report is None:
            failed.append((target, "scan failed"))
            continue

        write_target_landing(target, report, sha)
        scanned.append((target, report, sha))
        score = report.get("score", {})
        print(f"  [OK]     score={score.get('total')}/100 ({score.get('level')})")
        print()

    if scanned:
        write_master_index(scanned)
        print(f"\n[DONE] Gallery built: {len(scanned)} report(s) in {OUT_DIR}")
    else:
        print("\n[FAIL] No successful scans - master index not written.")

    if failed:
        print(f"\nFailures ({len(failed)}):")
        for target, reason in failed:
            print(f"  - {target.slug}: {reason}")
        return 1 if not scanned else 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
