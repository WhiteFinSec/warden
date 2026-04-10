"""Tests for the optional PDF report writer.

WeasyPrint is intentionally NOT a test dependency (it drags in cairo/pango and
would bloat CI). We verify behavior two ways:

1. When weasyprint is not installed → ``PdfDependencyMissing`` is raised with
   the expected install hint.
2. When a fake ``weasyprint`` module is injected into ``sys.modules``, the
   writer calls ``HTML(string=..., base_url=...).write_pdf(path)`` with the
   rendered Warden HTML.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from unittest import mock

import pytest

from warden.models import ScanResult
from warden.report.pdf_writer import PdfDependencyMissing, write_pdf_report


def _empty_result() -> ScanResult:
    result = ScanResult(target_path=".")
    result.file_counts = {"python": 0, "js": 0, "other": 0}
    return result


def test_missing_weasyprint_raises_friendly_error(tmp_path: Path) -> None:
    with mock.patch.dict(sys.modules, {"weasyprint": None}):
        with pytest.raises(PdfDependencyMissing) as exc_info:
            write_pdf_report(_empty_result(), tmp_path / "out.pdf")
    assert "warden-ai[pdf]" in str(exc_info.value)


def test_write_pdf_with_fake_weasyprint(tmp_path: Path) -> None:
    calls: dict = {}

    class FakeHTML:
        def __init__(self, string: str, base_url: str) -> None:
            calls["string"] = string
            calls["base_url"] = base_url

        def write_pdf(self, path: str) -> None:
            calls["path"] = path
            Path(path).write_bytes(b"%PDF-1.4 fake\n")

    fake_module = types.ModuleType("weasyprint")
    fake_module.HTML = FakeHTML  # type: ignore[attr-defined]

    out_path = tmp_path / "reports" / "warden_report.pdf"
    with mock.patch.dict(sys.modules, {"weasyprint": fake_module}):
        write_pdf_report(_empty_result(), out_path)

    # Writer should have produced a file at the requested location
    assert out_path.exists()
    assert out_path.read_bytes().startswith(b"%PDF")

    # And passed the real Warden HTML to weasyprint
    assert "string" in calls
    assert "<!DOCTYPE html>" in calls["string"]
    assert "Warden" in calls["string"]
    assert calls["base_url"] == str(out_path.parent)
    assert calls["path"] == str(out_path)


def test_write_pdf_creates_parent_directory(tmp_path: Path) -> None:
    class FakeHTML:
        def __init__(self, string: str, base_url: str) -> None:
            pass

        def write_pdf(self, path: str) -> None:
            Path(path).write_bytes(b"%PDF-1.4\n")

    fake_module = types.ModuleType("weasyprint")
    fake_module.HTML = FakeHTML  # type: ignore[attr-defined]

    nested = tmp_path / "a" / "b" / "c" / "warden_report.pdf"
    assert not nested.parent.exists()

    with mock.patch.dict(sys.modules, {"weasyprint": fake_module}):
        write_pdf_report(_empty_result(), nested)

    assert nested.exists()
