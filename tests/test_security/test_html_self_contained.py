"""CI-enforced: HTML report has no external URLs."""

import re
import tempfile
from pathlib import Path

from warden.models import ScanResult
from warden.report.html_writer import write_html_report
from warden.scoring.engine import apply_scores


def _make_result() -> ScanResult:
    result = ScanResult(target_path="/test/project")
    apply_scores(result, {})  # All zeros
    return result


def test_html_no_external_urls():
    """HTML report must not reference any external URLs (CDN, fonts, etc.)."""
    result = _make_result()

    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "report.html"
        write_html_report(result, path)
        html = path.read_text(encoding="utf-8")

    # Find all URLs in the HTML
    urls = re.findall(r'(?:href|src|url)\s*[=\(]\s*["\']?(https?://[^"\'>\s]+)', html)

    # Filter out text links and the email form action (not resource loads)
    resource_urls = [
        u for u in urls
        if "github.com/SharkRouter" not in u
        and "sharkrouter.ai" not in u
        and "api.sharkrouter.ai/v1/warden" not in u
    ]

    assert not resource_urls, f"HTML report contains external resource URLs: {resource_urls}"


def test_html_no_google_fonts():
    result = _make_result()

    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "report.html"
        write_html_report(result, path)
        html = path.read_text(encoding="utf-8")

    assert "fonts.googleapis.com" not in html
    assert "fonts.gstatic.com" not in html


def test_html_no_cdn():
    result = _make_result()

    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "report.html"
        write_html_report(result, path)
        html = path.read_text(encoding="utf-8")

    cdn_patterns = ["cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com"]
    for cdn in cdn_patterns:
        assert cdn not in html, f"HTML report references CDN: {cdn}"


def test_html_is_valid_document():
    result = _make_result()

    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "report.html"
        write_html_report(result, path)
        html = path.read_text(encoding="utf-8")

    assert "<!DOCTYPE html>" in html
    assert "<html" in html
    assert "</html>" in html
    assert "<style>" in html
