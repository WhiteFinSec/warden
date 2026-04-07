"""Shared constants for all scanner modules."""

from __future__ import annotations

# Directories to prune during os.walk — never descend into these.
# These are universally recognized non-source directories: virtual
# environments, package caches, build outputs, VCS internals, and
# IDE metadata. No project-specific entries.
SKIP_DIRS: frozenset[str] = frozenset({
    # Python virtual environments & caches
    ".venv", "venv", "__pycache__", ".eggs", "site-packages",
    ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".pytype", "__pypackages__",
    # JavaScript / Node
    "node_modules", ".next", ".nuxt", ".output",
    "bower_components", ".parcel-cache", ".turbo",
    # Build artifacts
    "dist", "build", "out", "_build", "target",
    # Version control
    ".git", ".hg", ".svn",
    # IDE / editor
    ".idea", ".vscode", ".vs",
    # Coverage
    "coverage", ".coverage", "htmlcov",
})
