"""PDF report writer — optional feature gated on the ``warden-ai[pdf]`` extra.

This module reuses :mod:`warden.report.html_writer` to build the self-contained
HTML report, then renders it to PDF using `WeasyPrint`_. WeasyPrint ships native
dependencies (cairo, pango) that are unnecessary for 99% of Warden users, so
it is intentionally kept behind an optional extra:

.. code-block:: bash

    pip install "warden-ai[pdf]"

CLI integration: ``warden scan --format pdf``. When the extra is not installed,
the CLI raises a :class:`click.UsageError` pointing users at the install
command instead of crashing with an opaque ``ImportError``.

.. _WeasyPrint: https://weasyprint.readthedocs.io/
"""

from __future__ import annotations

from pathlib import Path

from warden.models import ScanResult
from warden.report.html_writer import _build_html


class PdfDependencyMissing(RuntimeError):
    """Raised when ``weasyprint`` is not importable.

    The CLI catches this and renders a friendly hint; tests use it as a
    precise marker instead of depending on the exact ``ImportError`` shape.
    """


def write_pdf_report(result: ScanResult, output_path: Path) -> None:
    """Render the HTML report to a PDF file.

    :param result: The scan result to render.
    :param output_path: Destination file. Parent directories are created if
        they don't exist yet.
    :raises PdfDependencyMissing: When ``weasyprint`` is not installed.
    """
    try:
        from weasyprint import HTML  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - exercised via unit test
        raise PdfDependencyMissing(
            "warden PDF reports require the 'pdf' extra — install with: "
            "pip install 'warden-ai[pdf]'"
        ) from exc

    html = _build_html(result)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    # base_url lets WeasyPrint resolve any relative URLs in the HTML. The
    # Warden report is fully self-contained (no network fetches), so the
    # base_url is only used as a hint and never actually resolves anything.
    HTML(string=html, base_url=str(output_path.parent)).write_pdf(str(output_path))
