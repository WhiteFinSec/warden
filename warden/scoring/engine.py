"""Scoring engine: raw dimension scores -> normalized /100 score."""

from __future__ import annotations

from warden.models import DimensionScore, ScanResult, ScoreLevel
from warden.scoring.dimensions import ALL_DIMENSIONS, TOTAL_RAW_MAX, Dimension


def get_score_level(score: int) -> ScoreLevel:
    """Determine governance level from normalized /100 score."""
    if score >= 80:
        return ScoreLevel.GOVERNED
    elif score >= 60:
        return ScoreLevel.PARTIAL
    elif score >= 33:
        return ScoreLevel.AT_RISK
    else:
        return ScoreLevel.UNGOVERNED


def normalize_score(raw_total: int, raw_max: int = TOTAL_RAW_MAX) -> int:
    """Convert raw score to normalized score (/100).

    ``raw_max`` defaults to the full 235-point total. When coverage
    gating drops dimensions (e.g. a pure C# project has D9/D10/D13/D15/
    D16 excluded because Warden has no C# scanners for them), callers
    pass the reduced ``raw_max`` so the score reflects only dimensions
    the scanner could actually assess.
    """
    if raw_max <= 0:
        return 0
    return round(raw_total / raw_max * 100)


def _has_coverage(dim: Dimension, file_counts: dict[str, int] | None) -> bool:
    """Decide whether a dimension was actually scanned for this project.

    A dimension is considered "covered" if:
    - It's language-agnostic (``supported_langs is None``), OR
    - The project has at least one file in any of the supported languages.

    ``file_counts`` comes from ``ScanResult.file_counts`` which cli.py
    populates with keys ``python``, ``js``, ``other``, ``csharp``. If
    ``file_counts`` is missing or empty we fall back to the old behavior
    (all dims covered) so existing callers that don't populate it still
    work unchanged.
    """
    if dim.supported_langs is None:
        return True
    if not file_counts:
        # Back-compat: no file_counts → assume everything is in scope.
        return True
    for lang in dim.supported_langs:
        if file_counts.get(lang, 0) > 0:
            return True
    return False


def _apply_finding_deductions(
    raw_scores: dict[str, int],
    findings: list,
) -> dict[str, int]:
    """Apply deductions based on CRITICAL/HIGH findings per dimension.

    CRITICAL findings actively reduce dimension score (governance gaps
    should penalize, not be ignored). HIGH findings have smaller impact.
    """
    from warden.models import Severity

    adjusted = dict(raw_scores)

    # Count CRITICAL and HIGH findings per dimension
    crit_counts: dict[str, int] = {}
    high_counts: dict[str, int] = {}
    for f in findings:
        if f.severity == Severity.CRITICAL:
            crit_counts[f.dimension] = crit_counts.get(f.dimension, 0) + 1
        elif f.severity == Severity.HIGH:
            high_counts[f.dimension] = high_counts.get(f.dimension, 0) + 1

    for dim in ALL_DIMENSIONS:
        crits = crit_counts.get(dim.id, 0)
        highs = high_counts.get(dim.id, 0)
        if crits == 0 and highs == 0:
            continue

        current = adjusted.get(dim.id, 0)
        if current == 0:
            continue

        # Deductions are capped at 60% of earned score — even a project with
        # many CRITICALs keeps partial credit for governance signals it earned.
        max_penalty = int(current * 0.6)

        # Each CRITICAL deducts 2 pts, each HIGH deducts 1 pt (HIGHs capped at 3)
        crit_penalty = min(crits * 2, max_penalty)
        remaining_budget = max(max_penalty - crit_penalty, 0)
        high_penalty = min(min(highs, 3), remaining_budget)
        adjusted[dim.id] = current - crit_penalty - high_penalty

    return adjusted


def calculate_scores(
    raw_scores: dict[str, int],
    findings: list | None = None,
    file_counts: dict[str, int] | None = None,
) -> tuple[dict[str, DimensionScore], int, ScoreLevel]:
    """Calculate dimension scores and total from raw scores.

    Args:
        raw_scores: Dict mapping dimension ID (e.g. "D1") to raw score.
                    Missing dimensions default to 0.
        findings: Optional list of Finding objects. If provided, CRITICAL/HIGH
                  findings will deduct from dimension scores.
        file_counts: Optional per-language file counts (``python``,
                    ``js``, ``csharp``, ``other``). When provided, drives
                    coverage gating: dimensions whose scanners had no
                    applicable files are excluded from the normalization
                    denominator. Without this (back-compat), all 17 dims
                    stay in the denominator.

    Returns:
        Tuple of (dimension_scores dict, total_normalized, score_level).
    """
    # Apply finding-based deductions before calculating final scores
    effective_scores = raw_scores
    if findings:
        effective_scores = _apply_finding_deductions(raw_scores, findings)

    dimension_scores: dict[str, DimensionScore] = {}
    raw_total = 0
    effective_max = 0

    for dim in ALL_DIMENSIONS:
        raw = min(effective_scores.get(dim.id, 0), dim.max_score)  # Cap at max
        raw = max(raw, 0)  # Floor at 0

        covered = _has_coverage(dim, file_counts)
        dimension_scores[dim.id] = DimensionScore(
            name=dim.name,
            raw=raw,
            max=dim.max_score,
            covered=covered,
        )
        if covered:
            raw_total += raw
            effective_max += dim.max_score

    total = normalize_score(raw_total, effective_max or TOTAL_RAW_MAX)
    level = get_score_level(total)

    return dimension_scores, total, level


def apply_scores(result: ScanResult, raw_scores: dict[str, int]) -> None:
    """Apply calculated scores to a ScanResult in-place."""
    result.dimension_scores, result.total_score, result.level = calculate_scores(
        raw_scores,
        findings=result.findings,
        file_counts=result.file_counts,
    )
