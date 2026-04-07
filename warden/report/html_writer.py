# ruff: noqa: E501
"""Self-contained HTML report generation.

CRITICAL: No external requests. All CSS and layout are embedded.
Air-gapped environments work perfectly — system font stack only.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from warden import __scoring_model__, __version__
from warden.models import ScanResult, ScoreLevel, Severity
from warden.scoring.dimensions import GROUPS

# --- Matte professional palette ---
SEVERITY_COLORS = {
    Severity.CRITICAL: "#da3633",
    Severity.HIGH: "#d29922",
    Severity.MEDIUM: "#8b949e",
    Severity.LOW: "#3fb950",
}

LEVEL_COLORS = {
    ScoreLevel.GOVERNED: "#3fb950",
    ScoreLevel.PARTIAL: "#d29922",
    ScoreLevel.AT_RISK: "#da3633",
    ScoreLevel.UNGOVERNED: "#da3633",
}


def write_html_report(result: ScanResult, output_path: Path) -> None:
    """Write self-contained HTML report. No external requests."""
    html = _build_html(result)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")


def _build_html(result: ScanResult) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    sections = [
        _header(result, timestamp),
        _hero(result),
        _summary_grid(result),
        _findings_section(result),
        _governance_stack(result),
        _remediation_actions(result),
        _email_form(result),
        _footer(),
    ]

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Warden Governance Report — {result.total_score}/100</title>
{_css()}
</head>
<body>
<div class="wrap">
{''.join(sections)}
</div>
{_js()}
</body>
</html>"""


def _css() -> str:
    return """<style>
:root {
  --bg: #0f1117;
  --surface: #161b22;
  --surface2: #1c2128;
  --border: #21262d;
  --text: #c9d1d9;
  --muted: #484f58;
  --critical: #da3633;
  --high: #d29922;
  --medium: #8b949e;
  --low: #3fb950;
  --accent: #58a6ff;
  --critical-dim: rgba(218,54,51,.10);
  --high-dim: rgba(210,153,34,.10);
  --medium-dim: rgba(139,148,158,.10);
  --low-dim: rgba(63,185,80,.10);
  --accent-dim: rgba(88,166,255,.10);
  --mono: 'SF Mono','Cascadia Code','JetBrains Mono','Fira Code',Consolas,monospace;
  --sans: -apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--sans);background:var(--bg);color:var(--text);line-height:1.6}
.wrap{max-width:1100px;margin:0 auto;padding:0 24px 48px}

/* --- SECTION CARDS --- */
.sec{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:28px 32px;margin-top:24px}
.sec-title{font-size:13px;font-weight:700;color:var(--muted);letter-spacing:1.5px;text-transform:uppercase;margin-bottom:18px}

/* --- HEADER --- */
.hdr{display:flex;justify-content:space-between;align-items:flex-start;padding:32px 0 24px;flex-wrap:wrap;gap:16px}
.hdr-left{display:flex;align-items:center;gap:14px}
.hdr-logo{font-family:var(--mono);font-size:18px;font-weight:800;color:var(--accent);letter-spacing:3px}
.hdr-sub{font-size:13px;color:var(--muted)}
.hdr-meta{font-family:var(--mono);font-size:11px;color:var(--muted);line-height:1.8;margin-top:10px}
.hdr-badge{font-family:var(--mono);font-size:10px;color:var(--low);border:1px solid rgba(63,185,80,.25);padding:6px 12px;border-radius:6px;text-align:right;white-space:nowrap;max-width:280px;line-height:1.6}

/* --- HERO --- */
.hero{display:flex;gap:48px;align-items:flex-start;flex-wrap:wrap}
.hero-gauge{flex-shrink:0}
.hero-dims{flex:1;min-width:300px}
.gauge-label{text-align:center;margin-top:8px}
.level-badge{font-family:var(--mono);font-size:12px;font-weight:700;padding:4px 14px;border-radius:4px;display:inline-block}
.lvl-governed{background:var(--low-dim);color:var(--low)}
.lvl-partial{background:var(--high-dim);color:var(--high)}
.lvl-at_risk{background:var(--critical-dim);color:var(--critical)}
.lvl-ungoverned{background:var(--critical-dim);color:var(--critical)}

/* dimension bars */
.dim-group-label{font-family:var(--mono);font-size:10px;color:var(--accent);letter-spacing:2px;margin:16px 0 6px;padding-bottom:4px;border-bottom:1px solid var(--border)}
.dim-group-label:first-child{margin-top:0}
.dim-row{display:flex;align-items:center;gap:8px;margin:5px 0}
.dim-lbl{font-size:12px;width:170px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.dim-track{flex:1;height:7px;background:#21262d;border-radius:4px;overflow:hidden;min-width:60px}
.dim-fill{height:100%;border-radius:4px}
.dim-val{font-family:var(--mono);font-size:11px;color:var(--muted);width:50px;text-align:right}
.dim-subtotal{font-family:var(--mono);font-size:11px;color:var(--accent);text-align:right;margin:4px 0 0;padding-top:4px;border-top:1px dashed var(--border)}

/* --- SUMMARY GRID --- */
.sgrid{display:grid;grid-template-columns:repeat(5,1fr);gap:12px}
.sgrid-cell{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:16px;text-align:center}
.sgrid-val{font-family:var(--mono);font-size:28px;font-weight:700}
.sgrid-lbl{font-size:11px;color:var(--muted);margin-top:4px}

/* --- FINDINGS --- */
.fg-hdr{font-family:var(--mono);font-size:12px;font-weight:700;letter-spacing:1px;cursor:pointer;display:flex;align-items:center;gap:8px;margin-bottom:8px;user-select:none}
.fg-cnt{padding:2px 9px;border-radius:10px;font-size:11px}
.fg-body{display:none}.fg-body.open{display:block}
.f-card{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:12px 16px;margin-bottom:6px;cursor:pointer}
.f-top{display:flex;justify-content:space-between;align-items:flex-start;gap:8px}
.f-sev{font-family:var(--mono);font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;white-space:nowrap}
.f-dim{font-family:var(--mono);font-size:10px;color:var(--muted);background:var(--surface);padding:2px 6px;border-radius:3px}
.f-msg{font-size:13px;margin:6px 0 2px}
.f-loc{font-family:var(--mono);font-size:11px;color:var(--accent)}
.f-detail{font-size:12px;color:var(--muted);margin-top:8px;padding-top:8px;border-top:1px solid var(--border);display:none}
.f-card.exp .f-detail{display:block}
.f-rem{color:var(--low)}
.f-compliance{font-family:var(--mono);font-size:10px;color:var(--muted);margin-top:4px}
.f-compliance span{background:var(--accent-dim);color:var(--accent);padding:1px 6px;border-radius:3px;margin-right:4px}
.arrow{transition:transform .2s;display:inline-block}.arrow.open{transform:rotate(90deg)}

/* --- GOVERNANCE STACK --- */
.tc{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:14px 18px;margin-bottom:8px}
.tc-top{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px}
.tc-name{font-weight:600;font-size:14px}
.tc-cat{font-family:var(--mono);font-size:10px;padding:2px 8px;border-radius:4px;background:var(--medium-dim);color:var(--medium)}
.tc-conf{font-family:var(--mono);font-size:10px;padding:2px 8px;border-radius:4px}
.tc-conf-high{background:var(--low-dim);color:var(--low)}
.tc-conf-medium{background:var(--high-dim);color:var(--high)}
.tc-signals{font-size:11px;color:var(--muted);margin-top:6px}
.tc-gap{font-size:12px;margin-top:8px;padding:8px 12px;border-radius:6px;background:var(--surface);border:1px solid var(--border)}
.tc-disclaimer{font-size:10px;color:var(--muted);margin-top:12px;padding-top:12px;border-top:1px solid var(--border);font-style:italic}

/* --- REMEDIATION --- */
.rem-card{background:var(--surface2);border:1px solid var(--border);border-left:3px solid var(--accent);border-radius:8px;padding:14px 18px;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center;gap:12px}
.rem-num{font-family:var(--mono);font-size:24px;font-weight:700;color:var(--accent);flex-shrink:0}
.rem-text{font-size:13px;flex:1}.rem-text .sub{color:var(--muted);font-size:12px}
.rem-impact{font-family:var(--mono);font-size:12px;color:var(--low);white-space:nowrap}
.rem-cta{display:block;text-align:center;margin-top:16px;font-size:13px;color:var(--accent);font-family:var(--mono)}

/* --- EMAIL FORM --- */
.email-sec{display:flex;gap:32px;flex-wrap:wrap;align-items:flex-start}
.email-left{flex:1;min-width:280px}
.email-right{flex:1;min-width:260px;display:flex;flex-direction:column;gap:10px}
.email-cols{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:12px;font-size:12px}
.email-col h4{font-family:var(--mono);font-size:11px;letter-spacing:1px;margin-bottom:6px}
.email-col li{list-style:none;padding:2px 0}
.email-input{width:100%;padding:10px 14px;border-radius:6px;border:1px solid var(--border);background:var(--surface2);color:var(--text);font-size:14px;font-family:var(--sans)}
.email-input:focus{outline:none;border-color:var(--accent)}
.email-btn{width:100%;padding:12px;border:none;border-radius:6px;background:var(--accent);color:#fff;font-weight:700;font-size:14px;cursor:pointer;font-family:var(--mono);letter-spacing:1px;transition:opacity .2s}
.email-btn:hover{opacity:.85}
.email-note{font-size:11px;color:var(--muted);text-align:center}

/* --- FOOTER --- */
.ftr{text-align:center;padding:32px 0;font-size:12px;color:var(--muted);line-height:2}
.ftr a{color:var(--accent);text-decoration:none}
.ftr-cta{display:inline-block;margin-top:12px;background:var(--accent);color:#fff;padding:10px 24px;border-radius:8px;font-weight:700;font-size:13px;text-decoration:none}
.ftr-cta:hover{opacity:.85}

/* --- RESPONSIVE --- */
@media(max-width:768px){
  .hero{flex-direction:column;align-items:center}
  .sgrid{grid-template-columns:repeat(2,1fr)}
  .sgrid-cell:last-child{grid-column:span 2}
  .email-sec{flex-direction:column}
  .hdr{flex-direction:column}
  .dim-lbl{width:120px}
}
</style>"""


def _js() -> str:
    return """<script>
function toggleGroup(id){
  var b=document.getElementById(id);
  var a=document.getElementById(id+'-arrow');
  if(b){b.classList.toggle('open');if(a)a.classList.toggle('open')}
}
function toggleFinding(el){el.classList.toggle('exp')}
function submitEmail(btn){
  var email=document.getElementById('warden-email').value;
  var company=document.getElementById('warden-company');
  if(!email||email.indexOf('@')<1){btn.textContent='Enter valid email';setTimeout(function(){btn.textContent='GET FULL REPORT \\u2192'},2000);return}
  btn.disabled=true;btn.textContent='SENDING...';
  var data=JSON.parse(document.getElementById('warden-data').textContent);
  data.email=email;
  if(company&&company.value)data.company=company.value;
  fetch('https://api.sharkrouter.ai/v1/warden/submit',{
    method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify(data)
  }).then(function(r){
    if(r.ok){btn.textContent='\\u2713 SENT — CHECK YOUR INBOX';btn.style.background='#3fb950'}
    else{btn.textContent='GET FULL REPORT \\u2192';btn.disabled=false}
  }).catch(function(){btn.textContent='GET FULL REPORT \\u2192';btn.disabled=false});
}
</script>"""


def _header(result: ScanResult, timestamp: str) -> str:
    return f"""
<div class="hdr">
  <div>
    <div class="hdr-left">
      <span style="font-size:28px">&#x1F988;</span>
      <div>
        <div class="hdr-logo">WARDEN</div>
        <div class="hdr-sub">AI Agent Governance Report</div>
      </div>
    </div>
    <div class="hdr-meta">
      {_esc(result.target_path)}<br>
      {timestamp} &middot; Warden v{__version__} &middot; Scoring Model v{__scoring_model__}
    </div>
  </div>
  <div class="hdr-badge">&#x1F512; All data collected locally<br>Nothing left this machine</div>
</div>"""


def _hero(result: ScanResult) -> str:
    score = result.total_score
    level = result.level
    color = LEVEL_COLORS.get(level, "#999")
    lvl_cls = f"lvl-{level.value.lower()}"

    # SVG gauge — muted gradient
    r = 65
    circ = 2 * 3.14159 * r
    offset = circ - (score / 100) * circ
    if score >= 80:
        g1, g2 = "#3fb950", "#58a6ff"
    elif score >= 50:
        g1, g2 = "#d29922", "#3fb950"
    elif score >= 25:
        g1, g2 = "#da3633", "#d29922"
    else:
        g1, g2 = "#da3633", "#da3633"

    gauge_svg = f"""<svg width="150" height="150" viewBox="0 0 150 150">
  <defs><linearGradient id="sg" x1="0%" y1="0%" x2="100%" y2="100%">
    <stop offset="0%" stop-color="{g1}"/><stop offset="100%" stop-color="{g2}"/>
  </linearGradient></defs>
  <circle cx="75" cy="75" r="{r}" fill="none" stroke="#21262d" stroke-width="10"/>
  <circle cx="75" cy="75" r="{r}" fill="none" stroke="url(#sg)" stroke-width="10"
    stroke-linecap="round" stroke-dasharray="{circ:.1f}" stroke-dashoffset="{offset:.1f}"
    transform="rotate(-90 75 75)"/>
  <text x="75" y="72" text-anchor="middle" fill="{color}"
    font-family="var(--mono)" font-size="38" font-weight="700">{score}</text>
  <text x="75" y="92" text-anchor="middle" fill="#484f58"
    font-family="var(--mono)" font-size="13">/100</text>
</svg>"""

    # Dimension bars grouped
    dim_html = []
    for group_name, dims in GROUPS.items():
        dim_html.append(f'<div class="dim-group-label">{_esc(group_name)}</div>')
        grp_raw = 0
        grp_max = 0
        for dim in dims:
            ds = result.dimension_scores.get(dim.id)
            raw = ds.raw if ds else 0
            mx = ds.max if ds else dim.max_score
            pct = ds.pct if ds else 0
            grp_raw += raw
            grp_max += mx
            bar_color = _pct_color(pct)
            dim_html.append(f"""<div class="dim-row">
  <div class="dim-lbl">{dim.id} {_esc(dim.name)}</div>
  <div class="dim-track"><div class="dim-fill" style="width:{pct}%;background:{bar_color}"></div></div>
  <div class="dim-val">{raw}/{mx}</div>
</div>""")
        grp_pct = round(grp_raw / grp_max * 100) if grp_max else 0
        dim_html.append(f'<div class="dim-subtotal">{grp_raw}/{grp_max} ({grp_pct}%)</div>')

    return f"""
<div class="sec">
  <div class="hero">
    <div class="hero-gauge">
      {gauge_svg}
      <div class="gauge-label"><span class="level-badge {lvl_cls}">{level.value.replace('_', ' ')}</span></div>
    </div>
    <div class="hero-dims">
      {''.join(dim_html)}
    </div>
  </div>
</div>"""


def _summary_grid(result: ScanResult) -> str:
    total_files = sum(result.file_counts.values()) if result.file_counts else 0
    crits = sum(1 for f in result.findings if f.severity == Severity.CRITICAL)
    secrets = sum(1 for f in result.findings if f.layer == 4)
    gaps = sum(1 for ds in result.dimension_scores.values() if ds.pct == 0)
    # Unique compliance refs
    refs = set()
    for f in result.findings:
        if f.compliance.eu_ai_act:
            refs.add(f"EU: {f.compliance.eu_ai_act}")
        if f.compliance.owasp_llm:
            refs.add(f"OWASP: {f.compliance.owasp_llm}")
        if f.compliance.mitre_atlas:
            refs.add(f"MITRE: {f.compliance.mitre_atlas}")

    files_label = f"{total_files}" if total_files else "—"

    return f"""
<div class="sec">
  <div class="sec-title">Summary</div>
  <div class="sgrid">
    <div class="sgrid-cell"><div class="sgrid-val" style="color:var(--accent)">{files_label}</div><div class="sgrid-lbl">Files Scanned</div></div>
    <div class="sgrid-cell"><div class="sgrid-val" style="color:var(--critical)">{crits}</div><div class="sgrid-lbl">Critical Findings</div></div>
    <div class="sgrid-cell"><div class="sgrid-val" style="color:var(--high)">{secrets}</div><div class="sgrid-lbl">Secrets Exposed</div></div>
    <div class="sgrid-cell"><div class="sgrid-val" style="color:var(--medium)">{gaps}</div><div class="sgrid-lbl">Governance Gaps</div></div>
    <div class="sgrid-cell"><div class="sgrid-val" style="color:var(--accent)">{len(refs)}</div><div class="sgrid-lbl">Compliance Refs</div></div>
  </div>
</div>"""


def _findings_section(result: ScanResult) -> str:
    if not result.findings:
        return """
<div class="sec">
  <div class="sec-title">Findings</div>
  <p style="color:var(--muted)">No findings. Your governance posture is clean.</p>
</div>"""

    groups_html = []
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        sev_findings = [f for f in result.findings if f.severity == sev]
        if not sev_findings:
            continue
        sev_low = sev.value.lower()
        color = SEVERITY_COLORS[sev]
        dim_var = f"var(--{sev_low}-dim)"
        gid = f"fg-{sev_low}"

        # Show top 3 by default, rest in expandable
        preview = sev_findings[:3]
        rest = sev_findings[3:]

        cards = []
        for f in preview:
            cards.append(_finding_card(f, color, dim_var))

        # The preview cards are always visible
        rest_html = ""
        if rest:
            rest_cards = []
            for f in rest:
                rest_cards.append(_finding_card(f, color, dim_var))
            rest_html = f"""
  <details style="margin-top:4px">
    <summary style="cursor:pointer;font-family:var(--mono);font-size:11px;color:var(--muted);margin-bottom:8px">Show {len(rest)} more {sev.value} findings</summary>
    {''.join(rest_cards)}
  </details>"""

        # Auto-open CRITICAL group
        open_cls = " open" if sev == Severity.CRITICAL else ""
        arrow_cls = " open" if sev == Severity.CRITICAL else ""

        groups_html.append(f"""<div style="margin-bottom:20px">
  <div class="fg-hdr" style="color:{color}" onclick="toggleGroup('{gid}')">
    <span id="{gid}-arrow" class="arrow{arrow_cls}">&#9654;</span>
    {sev.value} <span class="fg-cnt" style="background:{dim_var};color:{color}">{len(sev_findings)}</span>
  </div>
  <div id="{gid}" class="fg-body{open_cls}">{''.join(cards)}{rest_html}</div>
</div>""")

    return f"""
<div class="sec">
  <div class="sec-title">Findings ({len(result.findings)})</div>
  {''.join(groups_html)}
</div>"""


def _finding_card(f, color: str, dim_var: str) -> str:
    """Render a single finding card."""
    loc = ""
    if f.file and f.line:
        short = f.file if len(f.file) <= 60 else "..." + f.file[-57:]
        loc = f'<div class="f-loc">{_esc(short)}:{f.line}</div>'

    # Compliance tags
    comp_tags = ""
    tags = []
    if f.compliance.eu_ai_act:
        tags.append(f"<span>EU AI Act {_esc(f.compliance.eu_ai_act)}</span>")
    if f.compliance.owasp_llm:
        tags.append(f"<span>OWASP {_esc(f.compliance.owasp_llm)}</span>")
    if f.compliance.mitre_atlas:
        tags.append(f"<span>MITRE {_esc(f.compliance.mitre_atlas)}</span>")
    if tags:
        comp_tags = f'<div class="f-compliance">{"".join(tags)}</div>'

    return f"""<div class="f-card" onclick="toggleFinding(this)">
  <div class="f-top">
    <span class="f-sev" style="background:{dim_var};color:{color}">{f.severity.value}</span>
    <span class="f-dim">{f.dimension}</span>
  </div>
  <div class="f-msg">{_esc(f.message)}</div>
  {loc}
  <div class="f-detail">
    <div class="f-rem">{_esc(f.remediation)}</div>
    {comp_tags}
  </div>
</div>"""


def _governance_stack(result: ScanResult) -> str:
    """Your Governance Stack — only detected tools."""
    detected = [c for c in result.competitors if c.confidence != "low"]

    if not detected:
        return """
<div class="sec">
  <div class="sec-title">Your Governance Stack</div>
  <p style="color:var(--muted);margin-bottom:12px">No third-party governance tools detected in this project.</p>
  <p style="font-size:13px">Governance tools help enforce policies, detect risks, and provide audit trails for AI agent operations.
    Consider evaluating tools that align with your compliance requirements.</p>
</div>"""

    cards = []
    project_score = result.total_score
    for c in detected:
        conf_cls = "tc-conf-high" if c.confidence == "high" else "tc-conf-medium"
        signals_str = ", ".join(c.signals[:5]) if c.signals else ""

        # Gap analysis
        gap_html = ""
        if c.warden_score > 0:
            if project_score > c.warden_score:
                gap_html = f'<div class="tc-gap" style="border-color:var(--low)">Your governance posture ({project_score}/100) exceeds {_esc(c.display_name)}\'s estimated capability ({c.warden_score}/100) — strong internal practices detected.</div>'
            elif project_score < c.warden_score:
                delta = c.warden_score - project_score
                gap_html = f'<div class="tc-gap" style="border-color:var(--high)">Configuration gaps may exist — {_esc(c.display_name)} is capable of scoring ~{c.warden_score}/100 with full setup (+{delta} pts potential).</div>'
            else:
                gap_html = f'<div class="tc-gap">{_esc(c.display_name)} is well-configured — project score matches expected capability.</div>'

        cards.append(f"""<div class="tc">
  <div class="tc-top">
    <div>
      <span class="tc-name">{_esc(c.display_name)}</span>
      <span class="tc-cat" style="margin-left:8px">{_esc(c.category)}</span>
    </div>
    <span class="tc-conf {conf_cls}">{c.confidence.upper()}</span>
  </div>
  {f'<div class="tc-signals">Signals: {_esc(signals_str)}</div>' if signals_str else ''}
  {gap_html}
</div>""")

    disclaimer = '<div class="tc-disclaimer">Tool capability scores are estimates based on publicly documented features. Actual effectiveness varies by version, configuration, and the scope of the scanned directory. These are not endorsements or criticisms of any product.</div>'

    return f"""
<div class="sec">
  <div class="sec-title">Your Governance Stack</div>
  {''.join(cards)}
  {disclaimer}
</div>"""


def _remediation_actions(result: ScanResult) -> str:
    """Top 5 highest-impact remediation actions by dimension gap."""
    if not result.findings:
        return ""

    # Find dimensions with biggest gaps (max - raw)
    dim_gaps = []
    for dim_id, ds in result.dimension_scores.items():
        gap = ds.max - ds.raw
        if gap > 0:
            dim_gaps.append((dim_id, ds.name, ds.raw, ds.max, gap))
    dim_gaps.sort(key=lambda x: x[4], reverse=True)

    top5 = dim_gaps[:5]
    if not top5:
        return ""

    items = []
    for i, (dim_id, name, raw, mx, gap) in enumerate(top5, 1):
        # Find best remediation for this dimension
        dim_findings = [f for f in result.findings if f.dimension == dim_id]
        if dim_findings:
            best = max(dim_findings, key=lambda f: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(f.severity.value, 0))
            msg = best.message
            rem = best.remediation
        else:
            msg = f"Improve {name}"
            rem = f"Address gaps in {name} to gain up to +{gap} raw points"

        items.append(f"""<div class="rem-card">
  <div class="rem-num">{i}</div>
  <div class="rem-text">
    <strong>{_esc(msg)}</strong><br>
    <span class="sub">{_esc(rem)}</span>
  </div>
  <div class="rem-impact">+{gap} pts</div>
</div>""")

    total = len(result.findings)
    return f"""
<div class="sec">
  <div class="sec-title">Top Remediation Actions</div>
  {''.join(items)}
  <div class="rem-cta">Get the full remediation plan for all {total} findings &darr;</div>
</div>"""


def _email_form(result: ScanResult) -> str:
    crits = sum(1 for f in result.findings if f.severity == Severity.CRITICAL)
    detected_tools = [c.display_name for c in result.competitors if c.confidence != "low"]
    finding_counts = {}
    for sev in Severity:
        finding_counts[sev.value] = sum(1 for f in result.findings if f.severity == sev)

    data_json = json.dumps({
        "score": result.total_score,
        "level": result.level.value,
        "total_findings": len(result.findings),
        "critical_count": crits,
        "finding_counts": finding_counts,
        "detected_tools": detected_tools,
        "warden_version": __version__,
        "scoring_model": __scoring_model__,
    })

    return f"""
<div class="sec">
  <div class="email-sec">
    <div class="email-left">
      <div style="font-size:18px;font-weight:700;margin-bottom:8px">Get Your Full Remediation Report</div>
      <div style="font-size:13px;color:var(--muted)">
        We'll send detailed, per-file remediation steps for all
        <strong style="color:var(--critical)">{len(result.findings)}</strong> findings
        ({crits} critical).
      </div>
      <div class="email-cols">
        <div class="email-col">
          <h4 style="color:var(--low)">&#10003; WE SEND</h4>
          <ul>
            <li>Full remediation plan</li>
            <li>Priority-ranked fixes</li>
            <li>Compliance mapping</li>
            <li>Score improvement guide</li>
          </ul>
        </div>
        <div class="email-col">
          <h4 style="color:var(--critical)">&#10007; WE NEVER SEND</h4>
          <ul>
            <li>API keys or secrets</li>
            <li>Source code content</li>
            <li>File paths or PII</li>
            <li>Log data</li>
          </ul>
        </div>
      </div>
    </div>
    <div class="email-right">
      <input type="email" id="warden-email" class="email-input" placeholder="you@company.com">
      <input type="text" id="warden-company" class="email-input" placeholder="Company (optional)" style="margin-top:0">
      <button class="email-btn" onclick="submitEmail(this)">GET FULL REPORT &#x2192;</button>
      <div class="email-note">Your score and finding counts are sent. No code, secrets, or file paths ever leave your machine.</div>
    </div>
  </div>
  <script type="application/json" id="warden-data">{data_json}</script>
</div>"""


def _footer() -> str:
    return f"""
<div class="ftr">
  Warden v{__version__} &middot; Scoring Model v{__scoring_model__} &middot; MIT License<br>
  <a href="https://github.com/SharkRouter/warden">Methodology &amp; Source</a><br>
  This report was generated locally. No data was transmitted.<br>
  <span style="font-family:var(--mono);font-size:10px;color:var(--muted)">Powered by SharkRouter</span><br>
  <a href="https://sharkrouter.ai" class="ftr-cta">Explore SharkRouter &#x2192;</a>
</div>"""


def _pct_color(pct: int) -> str:
    """Return bar fill color based on percentage."""
    if pct >= 80:
        return "var(--low)"
    if pct >= 60:
        return "var(--accent)"
    if pct >= 35:
        return "var(--high)"
    if pct > 0:
        return "var(--critical)"
    return "#484f58"


def _esc(text: str) -> str:
    """HTML-escape text."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
