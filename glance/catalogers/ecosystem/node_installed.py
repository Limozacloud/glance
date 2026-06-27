"""Node.js installed packages cataloger — reads node_modules/*/package.json.

Scans the actual install store (node_modules/) instead of lock-files.
Each installed package (including scoped @scope/pkg) has a package.json
directly under its node_modules sub-directory with exact resolved versions.
"""

from __future__ import annotations

import json
import os

from ...models import Source
from .base import EcosystemCataloger, _SKIP_DIRS

# Walk into node_modules — exclude everything else from _SKIP_DIRS.
_WALK_SKIP = _SKIP_DIRS - {"node_modules"}


def _is_installed(path: str) -> bool:
    """True only for package.json files directly under node_modules/<pkg>/."""
    parts = path.replace("\\", "/").split("/")
    if not parts or parts[-1] != "package.json":
        return False
    # Regular: ...node_modules/<pkg>/package.json  → grandparent is node_modules
    if len(parts) >= 3 and parts[-3] == "node_modules":
        return True
    # Scoped: ...node_modules/@scope/<pkg>/package.json
    if len(parts) >= 4 and parts[-3].startswith("@") and parts[-4] == "node_modules":
        return True
    return False


class NodeInstalledCataloger(EcosystemCataloger):
    name = "node_installed"
    source = Source.NPM

    def manifest_filenames(self) -> list[str]:
        return ["package.json"]

    def _is_manifest(self, filename: str) -> bool:
        return filename == "package.json"

    def _index_candidates(self, index) -> list[str]:
        found: list[str] = []
        seen: set[str] = set()
        for path in index.by_name("package.json"):
            if path in seen or not self._in_scope(path) or not _is_installed(path):
                continue
            seen.add(path)
            found.append(path)
        return found

    def _walk_candidates(self) -> list[str]:
        found: list[str] = []
        for root in self.paths:
            if not os.path.isdir(root):
                continue
            for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
                dirnames[:] = [d for d in dirnames if d not in _WALK_SKIP]
                if "package.json" in filenames:
                    path = os.path.join(dirpath, "package.json")
                    if _is_installed(path):
                        found.append(path)
        return found

    def _purl(self, name: str, version: str | None) -> str:
        v = version or "*"
        return f"pkg:npm/{name}@{v}"

    def _parse_manifest(self, path: str) -> list[tuple[str, str | None]]:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return []
        name = data.get("name")
        version = data.get("version")
        if not name:
            return []
        return [(name, version or None)]
