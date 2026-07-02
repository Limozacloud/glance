"""Base class for ecosystem (language package manager) catalogers."""

from __future__ import annotations

import logging
import os
from abc import abstractmethod

from ...models import CatalogerStatus, Component, ComponentType, Occurrence, ScanReport, Source

log = logging.getLogger(__name__)

_SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        ".env",
        ".tox",
        ".nox",
        "dist",
        "build",
        ".eggs",
    }
)


class EcosystemCataloger:
    name: str
    source: Source

    def __init__(self, config=None) -> None:
        self.config = config

    def available(self) -> bool:
        return True

    def file_index(self) -> dict[str, str]:
        return {}

    @abstractmethod
    def _is_manifest(self, filename: str) -> bool: ...

    def manifest_filenames(self) -> list[str]:
        """Literal filenames used as locate/MFT query anchors."""
        return []

    @abstractmethod
    def _parse_manifest(self, path: str) -> list[tuple[str, str | None]]:
        """Return list of (name, version_or_None) tuples."""
        ...

    def _purl(self, name: str, version: str | None) -> str:
        raise NotImplementedError

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

    # ── Candidate discovery ───────────────────────────────────────────────────

    def _in_skip_dir(self, path: str) -> bool:
        parts = path.replace("\\", "/").split("/")
        return any(p in _SKIP_DIRS for p in parts)

    def _index_candidates(self, index) -> list[str]:
        """Query a FileIndex built by discover_all()."""
        found: list[str] = []
        seen_paths: set[str] = set()
        for anchor in self.manifest_filenames():
            for path in index.by_name_substr(anchor):
                if path in seen_paths:
                    continue
                fname = os.path.basename(path)
                if not self._is_manifest(fname):
                    continue
                if self._in_skip_dir(path):
                    continue
                seen_paths.add(path)
                found.append(path)
        return found

    # ── Catalog ───────────────────────────────────────────────────────────────

    def catalog(self, report: ScanReport, index=None) -> list[Component]:
        """Catalog components from the FileIndex built by discover_all()."""
        candidates = self._index_candidates(index) if index is not None else []
        engine_used = "index"

        components: list[Component] = []
        seen: set[tuple[str, str]] = set()

        for fpath in candidates:
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

        report.catalogers.append(
            CatalogerStatus(self.name, True, len(components), detail=f"engine={engine_used}")
        )
        return components
