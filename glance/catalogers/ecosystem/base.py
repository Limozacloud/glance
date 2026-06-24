"""Base class for ecosystem (language package manager) catalogers."""

from __future__ import annotations

import os
from abc import abstractmethod

from ...models import CatalogerStatus, Component, ComponentType, Occurrence, ScanReport, Source

_SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn",
    "node_modules", "__pycache__", ".venv", "venv", ".env",
    ".tox", ".nox", "dist", "build", ".eggs",
})


class EcosystemCataloger:
    name: str
    source: Source

    def __init__(self, paths: list[str] | None = None) -> None:
        self.paths = paths or []

    def available(self) -> bool:
        return True

    def file_index(self) -> dict[str, str]:
        return {}

    @abstractmethod
    def _is_manifest(self, filename: str) -> bool: ...

    @abstractmethod
    def _parse_manifest(self, path: str) -> list[tuple[str, str | None]]:
        """Return list of (name, version_or_None) tuples."""
        ...

    def _purl(self, name: str, version: str | None) -> str: ...

    def _make_component(self, name: str, version: str | None, manifest_path: str) -> Component:
        purl = self._purl(name, version)
        return Component(
            name=name,
            version=version,
            type=ComponentType.LIBRARY,
            source=self.source,
            purl=purl,
            bom_ref=purl,
            managed=True,
            occurrences=[Occurrence(path=manifest_path, found_by=self.name)],
        )

    def catalog(self, report: ScanReport) -> list[Component]:
        components: list[Component] = []
        seen: set[tuple[str, str]] = set()

        for root in self.paths:
            if not os.path.isdir(root):
                continue
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
                for filename in filenames:
                    if not self._is_manifest(filename):
                        continue
                    fpath = os.path.join(dirpath, filename)
                    try:
                        pkgs = self._parse_manifest(fpath)
                    except Exception:
                        continue
                    for pkg_name, pkg_version in pkgs:
                        key = (pkg_name.lower(), (pkg_version or "").lower())
                        if key in seen:
                            continue
                        seen.add(key)
                        components.append(self._make_component(pkg_name, pkg_version, fpath))

        report.catalogers.append(CatalogerStatus(self.name, True, len(components)))
        return components
