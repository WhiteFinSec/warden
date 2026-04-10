"""Edge-case tests for the parallel branch of ``scan_secrets``.

The main ``test_secrets.py`` file exercises the sequential path only — each
test writes a single file, which falls below ``_PARALLEL_THRESHOLD`` and skips
the ``ThreadPoolExecutor`` branch entirely. These tests deliberately push the
file count above the threshold so the concurrent code path is covered.

What we verify:

1. **Parity with sequential.** Same inputs → same findings, regardless of
   which branch ran.
2. **No duplicates / no drops.** Every file that has a secret must produce
   exactly one finding, and every finding must map back to a real file.
3. **Progress callback fires once per file.** In parallel mode callbacks
   fire in ``as_completed`` order, not source order, but the total count
   must still equal the file count.
4. **Gitignore downgrade works in parallel.** The downgrade mutates each
   ``Finding.severity`` on the main thread after ``future.result()`` — this
   test makes sure that mutation actually reaches the aggregated output.
5. **Mixed clean + dirty files.** Half the files have secrets, half are
   clean. Parallel aggregation must keep them correctly attributed.
"""

from __future__ import annotations

from pathlib import Path

from warden.models import Severity
from warden.scanner import secrets_scanner
from warden.scanner.secrets_scanner import _PARALLEL_THRESHOLD, scan_secrets


def _write_dirty(dirpath: Path, idx: int) -> Path:
    """Write a file that contains exactly one OpenAI-shaped key."""
    f = dirpath / f"svc_{idx:02d}.py"
    # Each file gets a unique key suffix so duplicate-detection bugs would
    # surface as mismatched previews.
    f.write_text(
        f'OPENAI_API_KEY = "sk-abcdefghij{idx:010d}klmnopqrstuv"\n',
        encoding="utf-8",
    )
    return f


def _write_clean(dirpath: Path, idx: int) -> Path:
    f = dirpath / f"clean_{idx:02d}.py"
    f.write_text(f'print("hello from module {idx}")\n', encoding="utf-8")
    return f


def test_parallel_branch_activates_above_threshold(tmp_path: Path) -> None:
    """Sanity: ≥ threshold files exercises the ThreadPoolExecutor branch.

    We can't directly assert "the pool ran" without monkeypatching, but we
    can assert the file count exceeds the threshold — if it does and the
    scan still returns correct results, the parallel path is exercised.
    """
    for i in range(_PARALLEL_THRESHOLD + 4):  # 12 files, well above 8
        _write_dirty(tmp_path, i)

    findings, _ = scan_secrets(tmp_path)

    # Every file contributed exactly one CRITICAL finding.
    assert len(findings) == _PARALLEL_THRESHOLD + 4
    assert all(f.severity == Severity.CRITICAL for f in findings)
    assert all("OpenAI" in f.message for f in findings)


def test_parallel_no_duplicate_or_dropped_findings(tmp_path: Path) -> None:
    """Every file shows up exactly once, no file is silently skipped."""
    files = [_write_dirty(tmp_path, i) for i in range(_PARALLEL_THRESHOLD + 6)]

    findings, _ = scan_secrets(tmp_path)

    # Each finding should map back to a unique file, and every file we
    # created should appear in the findings.
    found_files = {Path(f.file).name for f in findings}
    created_files = {f.name for f in files}
    assert found_files == created_files, (
        f"Dropped or duplicated: missing={created_files - found_files}, "
        f"extra={found_files - created_files}"
    )


def test_parallel_mixed_clean_and_dirty(tmp_path: Path) -> None:
    """Clean files must not contribute findings even when interleaved."""
    for i in range(_PARALLEL_THRESHOLD):
        _write_dirty(tmp_path, i)
        _write_clean(tmp_path, i)

    findings, _ = scan_secrets(tmp_path)

    # Exactly one finding per dirty file, zero for clean files.
    assert len(findings) == _PARALLEL_THRESHOLD
    found_files = {Path(f.file).name for f in findings}
    assert all(name.startswith("svc_") for name in found_files)
    assert not any(name.startswith("clean_") for name in found_files)


def test_parallel_progress_callback_fires_once_per_file(tmp_path: Path) -> None:
    """Progress callback contract holds across the parallel path.

    ``on_file`` is documented as "called once per scanned file." In parallel
    mode the callback fires in ``as_completed`` order, not source order, but
    the total count must still match the file count exactly.
    """
    for i in range(_PARALLEL_THRESHOLD + 2):
        _write_dirty(tmp_path, i)
    for i in range(3):
        _write_clean(tmp_path, i)

    call_count = [0]

    def tick() -> None:
        call_count[0] += 1

    scan_secrets(tmp_path, on_file=tick)

    # 10 dirty + 3 clean = 13 scannable files.
    assert call_count[0] == _PARALLEL_THRESHOLD + 2 + 3


def test_parallel_gitignore_downgrade_applied(
    tmp_path: Path, monkeypatch
) -> None:
    """Gitignore downgrade must still reach aggregated findings in parallel.

    The downgrade mutates ``Finding.severity`` on the main thread in the
    ``as_completed`` loop, not in worker threads. If that wiring broke we'd
    see CRITICAL findings survive into the output even though the path was
    flagged gitignored.
    """
    for i in range(_PARALLEL_THRESHOLD + 2):
        _write_dirty(tmp_path, i)

    # Monkeypatch gitignore discovery: report every scanned file as ignored.
    def fake_gitignored(target: Path, file_list: list[Path]) -> set[str]:
        return {str(f).replace("\\", "/") for f in file_list}

    monkeypatch.setattr(
        secrets_scanner, "_get_gitignored_files", fake_gitignored
    )

    findings, scores = scan_secrets(tmp_path)

    # All findings should be downgraded to INFO — none should remain CRITICAL.
    assert len(findings) > 0
    assert all(f.severity == Severity.INFO for f in findings)
    assert all("gitignored" in f.message for f in findings)

    # Because no CRITICAL secrets remain after downgrade, D4 should reflect
    # "some findings but no critical exposure" (= 2 pts), not "critical
    # exposed" (= 0 pts).
    assert scores["D4"] == 2


def test_parallel_and_sequential_agree_on_same_input(tmp_path: Path) -> None:
    """Parity check: identical corpus → identical findings, both branches.

    Build two identical corpora — one small (sequential) and one large
    (parallel) — and assert the per-file finding shape matches.
    """
    # Sequential corpus: 3 files (below threshold)
    seq_dir = tmp_path / "seq"
    seq_dir.mkdir()
    for i in range(3):
        _write_dirty(seq_dir, i)
    seq_findings, _ = scan_secrets(seq_dir)

    # Parallel corpus: same 3 files + padding to force parallel branch
    par_dir = tmp_path / "par"
    par_dir.mkdir()
    for i in range(3):
        _write_dirty(par_dir, i)
    for i in range(3, _PARALLEL_THRESHOLD + 3):
        _write_dirty(par_dir, i)
    par_findings, _ = scan_secrets(par_dir)

    # Both branches should detect the OpenAI key pattern the same way for
    # the shared first 3 files. Normalize by basename + severity + pattern.
    def _shape(findings: list) -> set[tuple]:
        return {
            (Path(f.file).name, f.severity, f.dimension)
            for f in findings
            if Path(f.file).name in {f"svc_{i:02d}.py" for i in range(3)}
        }

    assert _shape(seq_findings) == _shape(par_findings)
