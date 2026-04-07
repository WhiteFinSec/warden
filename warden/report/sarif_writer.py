"""SARIF 2.1.0 report generation for GitHub Code Scanning integration."""

from __future__ import annotations

import json
from pathlib import Path

from warden import __version__
from warden.models import ScanResult, Severity

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "sarif-2.1/schema/sarif-schema-2.1.0.json"
)

_SEVERITY_TO_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}


def _make_relative(file_path: str, target_path: str) -> str:
    """Return *file_path* relative to *target_path* using forward slashes."""
    try:
        return Path(file_path).resolve().relative_to(
            Path(target_path).resolve()
        ).as_posix()
    except ValueError:
        # If the file isn't under target_path, normalise but keep as-is.
        return Path(file_path).as_posix()


def write_sarif_report(result: ScanResult, output_path: Path) -> None:
    """Write a SARIF 2.1.0 JSON report.

    Produces one ``run`` with ``rules`` (one per unique scanner/dimension/severity
    combination) and ``results`` (one per finding).
    """
    # --- Build deduplicated rules index ---
    # Key: (scanner, dimension) -> rule dict + index position
    rule_index: dict[tuple[str, str], int] = {}
    rules: list[dict] = []

    for f in result.findings:
        key = (f.scanner, f.dimension)
        if key not in rule_index:
            rule_id = f"{f.scanner}/{f.dimension}"
            rule_index[key] = len(rules)
            rule: dict = {
                "id": rule_id,
                "shortDescription": {"text": rule_id},
                "defaultConfiguration": {
                    "level": _SEVERITY_TO_LEVEL.get(f.severity, "warning"),
                },
            }
            if f.remediation:
                rule["help"] = {"text": f.remediation}
            rules.append(rule)

    # --- Build results array ---
    sarif_results: list[dict] = []
    for f in result.findings:
        key = (f.scanner, f.dimension)
        rule_idx = rule_index[key]
        rule_id = rules[rule_idx]["id"]

        sarif_result: dict = {
            "ruleId": rule_id,
            "ruleIndex": rule_idx,
            "level": _SEVERITY_TO_LEVEL.get(f.severity, "warning"),
            "message": {"text": f.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": _make_relative(f.file, result.target_path),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": max(f.line, 1),
                        },
                    },
                },
            ],
        }
        sarif_results.append(sarif_result)

    # --- Assemble the SARIF envelope ---
    sarif: dict = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "warden-ai",
                        "version": __version__,
                        "informationUri": "https://github.com/SharkRouter/warden",
                        "rules": rules,
                    },
                },
                "results": sarif_results,
            },
        ],
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(sarif, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
