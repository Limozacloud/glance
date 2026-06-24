"""Pip/PyPI ecosystem cataloger — parses requirements.txt and Pipfile.lock."""

from __future__ import annotations

import json
import re

from ...models import Source
from .base import EcosystemCataloger

_REQ_LINE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9._!+*-]+)", re.ASCII)
_FILENAMES = frozenset({"requirements.txt", "requirements-dev.txt", "requirements-test.txt",
                        "requirements-prod.txt", "Pipfile.lock"})


class PipCataloger(EcosystemCataloger):
    name = "pip"
    source = Source.PIP

    def _is_manifest(self, filename: str) -> bool:
        return filename in _FILENAMES

    def _purl(self, name: str, version: str | None) -> str:
        norm = name.lower().replace("_", "-")
        v = version or "*"
        return f"pkg:pypi/{norm}@{v}"

    def _parse_manifest(self, path: str) -> list[tuple[str, str | None]]:
        if path.endswith("Pipfile.lock"):
            return self._parse_pipfile_lock(path)
        return self._parse_requirements(path)

    def _parse_requirements(self, path: str) -> list[tuple[str, str | None]]:
        results: list[tuple[str, str | None]] = []
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                m = _REQ_LINE.match(line)
                if m:
                    results.append((m.group(1), m.group(2)))
        return results

    def _parse_pipfile_lock(self, path: str) -> list[tuple[str, str | None]]:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        results: list[tuple[str, str | None]] = []
        for section in ("default", "develop"):
            for pkg, info in data.get(section, {}).items():
                ver_raw = info.get("version", "")
                version = ver_raw.lstrip("=") or None
                results.append((pkg, version))
        return results
