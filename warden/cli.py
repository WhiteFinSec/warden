"""Warden CLI entry point."""

from __future__ import annotations

import time
from pathlib import Path

import click
from rich.console import Console

from warden import __scoring_model__, __version__

BANNER = r"""
 __        __            _
 \ \      / /_ _ _ __ __| | ___ _ __
  \ \ /\ / / _` | '__/ _` |/ _ \ '_ \
   \ V  V / (_| | | | (_| |  __/ | | |
    \_/\_/ \__,_|_|  \__,_|\___|_| |_|
         by SharkRouter
"""

console = Console()


@click.group(invoke_without_command=True)
@click.pass_context
@click.version_option(__version__)
def cli(ctx: click.Context) -> None:
    """Warden -- AI Agent Governance Scanner."""
    if ctx.invoked_subcommand is None:
        console.print(BANNER, style="bold bright_blue", highlight=False)
        console.print(
            f"[bold]Warden v{__version__}[/bold] -- "
            "[white]AI Agent Governance Scanner[/white]"
        )
        console.print()
        console.print("  warden [bold]scan[/bold] <path>       Scan a project")
        console.print("  warden [bold]methodology[/bold]       Scoring model")
        console.print("  warden [bold]leaderboard[/bold]       Vendor scores")


LAYER_NAMES = {
    "code": "Layer 1: Code Patterns",
    "mcp": "Layer 2: MCP Servers",
    "infra": "Layer 3: Infrastructure",
    "secrets": "Layer 4: Secrets",
    "agent": "Layer 5: Agent Architecture",
    "deps": "Layer 6: Supply Chain",
    "audit": "Layer 7: Audit & Compliance",
    "cicd": "Layer 8: CI/CD Governance",
    "iac": "Layer 9: IaC Security",
    "frameworks": "Layer 10: Framework Governance",
    "multilang": "Layer 11: Multi-Language Governance",
    "cloud": "Layer 12: Cloud AI Governance",
}


@cli.command()
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option("--format", "output_format", type=click.Choice(["json", "html", "all"]),
              default="all", help="Output format (default: all)")
@click.option("--output-dir", type=click.Path(), default=None,
              help="Directory for report files (default: current directory)")
@click.option("--skip", "skip_layers", default=None,
              help="Layers to skip (code,mcp,infra,secrets,agent,deps,audit,cicd,iac,frameworks)")
@click.option("--only", "only_layers", default=None,
              help="Only run these layers (code,mcp,infra,secrets,agent,deps,audit,cicd,iac,frameworks)")
def scan(
    path: str, output_format: str, output_dir: str | None,
    skip_layers: str | None, only_layers: str | None,
) -> None:
    """Scan a project for AI agent governance posture."""
    target = Path(path).resolve()
    out_dir = Path(output_dir).resolve() if output_dir else Path.cwd()

    console.print(BANNER, style="bold bright_blue", highlight=False)
    console.print(
        f"[bold]Warden v{__version__}[/bold] -- "
        "[white]AI Agent Governance Scanner[/white]"
    )
    console.print(f"Scanning: [white]{target}[/white]")

    # Count analyzable files — single walk, prune skip dirs
    from warden.scanner.code_analyzer import _walk_files

    with console.status("[bright_cyan]Indexing files...[/bright_cyan]"):
        _py_files, _js_files, _other_files = _walk_files(target)
        py_count = len(_py_files)
        js_count = len(_js_files)
        other_count = len(_other_files)
    found_parts = [f"{py_count} Python", f"{js_count} JS/TS"]
    if other_count:
        found_parts.append(f"{other_count} Go/Rust/Java")
    console.print(f"  Found: {', '.join(found_parts)} files")
    console.print("[bright_blue]" + "-" * 50 + "[/bright_blue]")

    import warnings

    start = time.monotonic()

    # Suppress SyntaxWarnings from target code (e.g. invalid escape sequences)
    warnings.filterwarnings("ignore", category=SyntaxWarning)

    # Import scanners lazily to keep CLI startup fast
    from warden.models import ScanResult
    from warden.scanner.agent_arch_scanner import scan_agent_arch
    from warden.scanner.audit_scanner import scan_audit
    from warden.scanner.cicd_scanner import scan_cicd
    from warden.scanner.cloud_scanner import scan_cloud
    from warden.scanner.code_analyzer import scan_code
    from warden.scanner.competitors import detect_competitors
    from warden.scanner.dependency_scanner import scan_dependencies
    from warden.scanner.framework_scanner import scan_frameworks
    from warden.scanner.iac_scanner import scan_iac
    from warden.scanner.infra_analyzer import scan_infra
    from warden.scanner.mcp_scanner import scan_mcp
    from warden.scanner.multilang_scanner import scan_multilang
    from warden.scanner.secrets_scanner import scan_secrets
    from warden.scanner.trap_defense_scanner import scan_trap_defense
    from warden.scoring.engine import apply_scores

    result = ScanResult(target_path=str(target))
    raw_scores: dict[str, int] = {}

    # Layers with per-file progress support
    progress_layers = {
        "Layer 1: Code Patterns": (scan_code, py_count + js_count),
        "Layer 4: Secrets": (scan_secrets, py_count + js_count),
        "Layer 7: Audit & Compliance": (scan_audit, py_count),
    }

    # All layers in order
    all_layers = [
        ("Layer 1: Code Patterns", scan_code, "code"),
        ("Layer 2: MCP Servers", scan_mcp, "mcp"),
        ("Layer 3: Infrastructure", scan_infra, "infra"),
        ("Layer 4: Secrets", scan_secrets, "secrets"),
        ("Layer 5: Agent Architecture", scan_agent_arch, "agent"),
        ("Layer 6: Supply Chain", scan_dependencies, "deps"),
        ("Layer 7: Audit & Compliance", scan_audit, "audit"),
        ("Layer 8: CI/CD Governance", scan_cicd, "cicd"),
        ("Layer 9: IaC Security", scan_iac, "iac"),
        ("Layer 10: Framework Governance", scan_frameworks, "frameworks"),
        ("Layer 11: Multi-Language Governance", scan_multilang, "multilang"),
        ("Layer 12: Cloud AI Governance", scan_cloud, "cloud"),
    ]

    # Apply --skip / --only filters
    if only_layers:
        only_set = {s.strip().lower() for s in only_layers.split(",")}
        all_layers = [t for t in all_layers if t[2] in only_set]
    elif skip_layers:
        skip_set = {s.strip().lower() for s in skip_layers.split(",")}
        all_layers = [t for t in all_layers if t[2] not in skip_set]

    if not all_layers:
        console.print("[red]No layers selected — nothing to scan.[/red]")
        return

    from rich.progress import (
        BarColumn,
        MofNCompleteColumn,
        Progress,
        TaskProgressColumn,
        TextColumn,
        TimeElapsedColumn,
    )

    for label, scanner_fn, _layer_key in all_layers:
        if label in progress_layers:
            _, total_files = progress_layers[label]
            with Progress(
                TextColumn(f"  [bright_cyan]{label}[/bright_cyan]"),
                BarColumn(bar_width=25),
                TaskProgressColumn(),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task(label, total=total_files)

                def advance(_t=task, _p=progress):
                    _p.advance(_t)

                findings, scores = scanner_fn(target, on_file=advance)
        else:
            from rich.status import Status

            with Status(
                f"  [bright_cyan]{label}[/bright_cyan]",
                console=console,
                spinner="dots",
            ):
                findings, scores = scanner_fn(target)

        result.findings.extend(findings)
        for dim_id, score in scores.items():
            raw_scores[dim_id] = raw_scores.get(dim_id, 0) + score
        count = len(findings)
        suffix = "finding" if count == 1 else "findings"
        critical = sum(
            1 for f in findings if f.severity.value == "CRITICAL"
        )
        extra = f" ([red]{critical} CRITICAL[/red])" if critical else ""
        elapsed_so_far = time.monotonic() - start
        mins, secs = divmod(int(elapsed_so_far), 60)
        ts = f"{mins}m{secs:02d}s" if mins else f"{secs}s"
        dots = "." * (28 - len(label))
        console.print(f"  {label} {dots} {count} {suffix}{extra}  [dim]{ts}[/dim]")

    # D17 trap defense
    from rich.status import Status

    with Status(
        "[bright_cyan]D17: Adversarial Resilience[/bright_cyan]",
        console=console,
        spinner="dots",
    ):
        trap_findings, trap_scores, trap_status = scan_trap_defense(target)
    result.findings.extend(trap_findings)
    result.trap_defense = trap_status
    for dim_id, score in trap_scores.items():
        raw_scores[dim_id] = raw_scores.get(dim_id, 0) + score

    # Competitor detection
    with Status(
        "[bright_cyan]Competitor Detection[/bright_cyan]",
        console=console,
        spinner="dots",
    ):
        competitors, comp_gtm = detect_competitors(target)
    result.competitors = competitors
    result.gtm_signal = comp_gtm

    if competitors:
        names = ", ".join(c.display_name for c in competitors if c.confidence != "low")
        if names:
            console.print(f"\n  Governance tools detected: [bright_cyan]{names}[/bright_cyan]")
    console.print("  Competitors in registry: 17")

    # Apply scores
    apply_scores(result, raw_scores)

    elapsed = time.monotonic() - start
    console.print("[bright_blue]" + "-" * 50 + "[/bright_blue]")

    # Color the score based on level
    level = result.level.value
    score_color = {
        "GOVERNED": "bold green",
        "PARTIAL": "bold yellow",
        "AT_RISK": "bold red",
        "UNGOVERNED": "bold red",
    }.get(level, "bold")
    console.print(
        f"  GOVERNANCE SCORE: [{score_color}]{result.total_score} / 100 "
        f"-- {level}[/{score_color}]"
    )

    # D17 warning when score is 0
    d17 = result.dimension_scores.get("D17")
    if d17 and d17.raw == 0:
        console.print()
        console.print(
            "  [bold red]WARNING:[/bold red] Your environment is exposed "
            "to 6 trap types with"
        )
        console.print("    documented 80%+ attack success rates.")
        console.print(
            '    [dim](Franklin, Tomasev, Jacobs, Leibo, Osindero.\n'
            '     "AI Agent Traps." Google DeepMind, March 2026)[/dim]'
        )

    # Generate reports
    from warden.report.html_writer import write_html_report
    from warden.report.json_writer import write_json_report

    if output_format in ("json", "all"):
        json_path = out_dir / "warden_report.json"
        write_json_report(result, json_path)
        file_url = json_path.as_uri()
        console.print(
            f"\n  Full data: [bright_cyan][link={file_url}]"
            f"{json_path}[/link][/bright_cyan]"
        )

    if output_format in ("html", "all"):
        html_path = out_dir / "warden_report.html"
        write_html_report(result, html_path)
        file_url = html_path.as_uri()
        console.print(
            f"  Report:    [bold bright_cyan][link={file_url}]"
            f"{html_path}[/link][/bold bright_cyan]"
        )

    console.print("[bright_blue]" + "-" * 50 + "[/bright_blue]")
    console.print(f"  [dim]Completed in {elapsed:.1f}s[/dim]")


@cli.command()
def methodology() -> None:
    """Print the scoring methodology (17 dimensions, weights, levels)."""
    from warden.scoring.dimensions import GROUPS, TOTAL_RAW_MAX

    click.echo(f"Warden Scoring Model v{__scoring_model__}")
    click.echo(f"Total raw: {TOTAL_RAW_MAX} points across {len(GROUPS)} groups, normalized to /100")
    click.echo()

    click.echo("Score Levels:")
    click.echo("  >= 80  GOVERNED     Comprehensive agent governance in place")
    click.echo("  >= 60  PARTIAL      Significant coverage with material gaps")
    click.echo("  >= 33  AT_RISK      Some controls exist but major blind spots")
    click.echo("  <  33  UNGOVERNED   Minimal or no agent governance")
    click.echo()

    for group_name, dims in GROUPS.items():
        group_total = sum(d.max_score for d in dims)
        click.echo(f"{group_name} ({group_total} pts):")
        for dim in dims:
            click.echo(f"  {dim.id:4} {dim.name:30} /{dim.max_score:3}  {dim.description}")
        click.echo()

    click.echo("Principles:")
    click.echo("  1. Local-only, privacy-first (no data leaves the machine)")
    click.echo("  2. Conservative scoring (undetected = 0, not unknown)")
    click.echo("  3. Balanced methodology (fair credit to all tool categories)")
    click.echo("  4. Transparent and correctable (vendor corrections welcome)")
    click.echo("  5. Research-backed severity (D17 cites DeepMind attack stats)")
    click.echo("  6. Compliance-mapped (EU AI Act, OWASP LLM Top 10, MITRE ATLAS)")


@cli.command()
def leaderboard() -> None:
    """Show the market comparison table (17 vendors x 17 dimensions)."""
    click.echo(f"Warden Market Leaderboard -- Scoring Model v{__scoring_model__}")
    click.echo()

    # Market scores from spec Section 6
    market_data = [
        ("SharkRouter",      91, "Full gateway"),
        ("Zenity",           48, "Agent gov."),
        ("Wiz",              41, "Cloud AI-SPM"),
        ("Oasis Security",   38, "NHI access"),
        ("Lasso / Noma",     30, "Agent monitor"),
        ("Kong",             27, "API gateway"),
        ("Robust / Cisco",   26, "AI firewall"),
        ("Rubrik",           26, "Data + agents"),
        ("Portkey",          24, "LLM gateway"),
        ("Pangea / CS",      23, "Prompt layer"),
        ("NeuralTrust",      23, "LLM gateway"),
        ("Knostic",          22, "Agent monitor"),
        ("Prompt Security",  21, "Prompt layer"),
        ("CF / Envoy",       20, "Proxy"),
        ("mcp-scan / Snyk",  18, "Vuln scanner"),
        ("Lakera",           13, "Prompt layer"),
        ("aiFWall",          11, "Prompt FW"),
    ]

    click.echo(f"  {'#':>3}  {'Vendor':<22} {'Category':<16} {'Score':>5}")
    click.echo(f"  {'---':>3}  {'-' * 22} {'-' * 16} {'-----':>5}")
    for i, (name, score, cat) in enumerate(market_data, 1):
        level = "GOVERNED" if score >= 80 else "PARTIAL" if score >= 60 else "AT_RISK" if score >= 33 else "UNGOVERNED"
        click.echo(f"  {i:>3}  {name:<22} {cat:<16} {score:>3}/100  {level}")

    click.echo()
    click.echo("  Market whitespace (avg < 20% across all vendors):")
    click.echo("    D17 Adversarial Resilience  -- avg 5%,  best: SharkRouter 90%")
    click.echo("    D15 Post-Exec Verification  -- avg 3%,  best: SharkRouter 100%")
    click.echo("    D16 Data Flow Governance    -- avg 6%,  best: SharkRouter 90%")
    click.echo("    D8  Agent Identity          -- avg 10%, best: SharkRouter 100%")
    click.echo("    D7  Human-in-the-Loop       -- avg 12%, best: SharkRouter 100%")
    click.echo()
    click.echo("  Methodology: warden methodology")
    click.echo("  Full report: warden scan <path>")


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
