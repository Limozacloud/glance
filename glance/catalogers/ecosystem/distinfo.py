"""Installed Python package cataloger — reads *.dist-info/METADATA files.

Covers everything pip (and pip-compatible tools like uv, poetry, pipx) installs:
  - System Python:   /usr/lib/python3.x/site-packages/
  - User installs:   ~/.local/lib/python3.x/site-packages/
  - Any venv:        <any-name>/lib/python3.x/site-packages/  (name-agnostic)
  - Windows:         C:\\PythonXX\\Lib\\site-packages\\

Only packages that are actually installed leave a .dist-info directory.
requirements.txt describes intent; dist-info proves installation.
"""

from __future__ import annotations

import os

from ...models import Source
from .base import EcosystemCataloger

# Directories to skip during walk — notably venv dirs are NOT here because
# we specifically want to find installed packages inside venvs.
_SKIP = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "__pycache__",
        "node_modules",
        ".tox",
        ".nox",
    }
)


class DistInfoCataloger(EcosystemCataloger):
    """Cataloger for Python packages installed via pip / uv / poetry."""

    name = "distinfo"
    source = Source.DISTINFO

    def manifest_filenames(self) -> list[str]:
        return ["METADATA"]

    def _is_manifest(self, filename: str) -> bool:
        return filename == "METADATA"

    def _is_dist_info_metadata(self, path: str) -> bool:
        parent = os.path.basename(os.path.dirname(path))
        return parent.endswith(".dist-info")

    # ── Discovery overrides ───────────────────────────────────────────────────

    def _index_candidates(self, index) -> list[str]:
        found: list[str] = []
        seen: set[str] = set()
        for path in index.by_name("METADATA"):
            if path in seen:
                continue
            if not self._is_dist_info_metadata(path):
                continue
            # intentionally NOT calling _in_skip_dir — we want venvs
            seen.add(path)
            found.append(path)
        return found

    def _walk_candidates(self) -> list[str]:
        found: list[str] = []
        for root in self.paths:
            if not os.path.isdir(root):
                continue
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [d for d in dirnames if d not in _SKIP]
                if "METADATA" in filenames and dirpath.endswith(".dist-info"):
                    found.append(os.path.join(dirpath, "METADATA"))
        return found

    # ── Parsing ───────────────────────────────────────────────────────────────

    def _purl(self, name: str, version: str | None) -> str:
        norm = name.lower().replace("_", "-")
        v = version or "*"
        return f"pkg:pypi/{norm}@{v}"

    def _parse_manifest(self, path: str) -> list[tuple[str, str | None]]:
        name: str | None = None
        version: str | None = None
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.rstrip()
                    if not line:
                        break  # blank line ends the RFC 822 header block
                    if line.startswith("Name:"):
                        name = line[5:].strip()
                    elif line.startswith("Version:"):
                        version = line[8:].strip()
                    if name and version:
                        break
        except OSError:
            return []
        if name:
            return [(name, version)]
        return []
