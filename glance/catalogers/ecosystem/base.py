"""Base class for ecosystem (language package manager) catalogers."""

from __future__ import annotations

import logging
import os
import sys
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

    def __init__(self, paths: list[str] | None = None, config=None) -> None:
        self.paths = paths or []
        self.config = config

    def available(self) -> bool:
        return True

    def file_index(self) -> dict[str, str]:
        return {}

    @abstractmethod
    def _is_manifest(self, filename: str) -> bool: ...

    @abstractmethod
    def manifest_filenames(self) -> list[str]:
        """Literal filenames used as locate/MFT query anchors."""
        ...

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

    # ── Candidate discovery ───────────────────────────────────────────────────

    def _in_skip_dir(self, path: str) -> bool:
        parts = path.replace("\\", "/").split("/")
        return any(p in _SKIP_DIRS for p in parts)

    def _in_scope(self, path: str) -> bool:
        if not self.paths:
            return True
        return any(path.startswith(root) for root in self.paths)

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
                if not self._in_scope(path):
                    continue
                if self._in_skip_dir(path):
                    continue
                seen_paths.add(path)
                found.append(path)
        return found

    def _walk_candidates(self) -> list[str]:
        found: list[str] = []
        for root in self.paths:
            if not os.path.isdir(root):
                continue
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
                for filename in filenames:
                    if self._is_manifest(filename):
                        found.append(os.path.join(dirpath, filename))
        return found

    def _locate_candidates(self) -> list[str] | None:
        """Query plocate/mlocate (Linux only). Returns None if unavailable."""
        if sys.platform == "win32":
            return None

        from ...config import Engine, OnStaleDB
        from ...discovery.engines import detect_engines, query

        cfg = self.config
        if cfg is not None and getattr(cfg, "engine", None) == Engine.WALK:
            return None

        db_override = getattr(cfg, "locate_db_path", None) if cfg else None
        max_age = getattr(cfg, "max_db_age_hours", 24.0) if cfg else 24.0
        on_stale = getattr(cfg, "on_stale_db", OnStaleDB.FALLBACK) if cfg else OnStaleDB.FALLBACK

        engine = None
        for e in detect_engines(db_override):
            age = e.db_age_hours()
            if age is None:
                continue
            if age > max_age:
                if on_stale == OnStaleDB.FALLBACK:
                    log.debug("ecosystem/%s: %s DB stale (%.1fh) -> next", self.name, e.name, age)
                    continue
                log.warning(
                    "ecosystem/%s: %s DB stale (%.1fh), used anyway", self.name, e.name, age
                )
            engine = e
            break

        if engine is None:
            return None

        anchors = self.manifest_filenames()
        found: list[str] = []
        for path in query(engine, anchors, db_override):
            fname = os.path.basename(path)
            if not self._is_manifest(fname):
                continue
            if not self._in_scope(path):
                continue
            if self._in_skip_dir(path):
                continue
            found.append(path)

        log.debug("ecosystem/%s: locate returned %d candidates", self.name, len(found))
        return found

    # ── Catalog ───────────────────────────────────────────────────────────────

    def catalog(self, report: ScanReport, index=None) -> list[Component]:
        """Catalog components.

        When *index* is provided (a FileIndex from discover_all), queries it
        directly. Otherwise falls back to locate/MFT/walk.
        """
        if index is not None:
            candidates = self._index_candidates(index)
            engine_used = "index"
        else:
            candidates = self._locate_candidates()
            engine_used = "locate"
            if candidates is None:
                candidates = self._walk_candidates()
                engine_used = "walk"

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
