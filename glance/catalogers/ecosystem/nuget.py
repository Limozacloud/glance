"""NuGet ecosystem cataloger — parses packages.config and *.packages.lock.json."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET

from ...models import Source
from .base import EcosystemCataloger


class NugetCataloger(EcosystemCataloger):
    name = "nuget"
    source = Source.NUGET

    def _is_manifest(self, filename: str) -> bool:
        return filename == "packages.config" or filename.endswith(".packages.lock.json")

    def _purl(self, name: str, version: str | None) -> str:
        v = version or "*"
        return f"pkg:nuget/{name}@{v}"

    def _parse_manifest(self, path: str) -> list[tuple[str, str | None]]:
        if path.endswith(".packages.lock.json"):
            return self._parse_lock_json(path)
        return self._parse_packages_config(path)

    def _parse_packages_config(self, path: str) -> list[tuple[str, str | None]]:
        tree = ET.parse(path)
        root = tree.getroot()
        results: list[tuple[str, str | None]] = []
        for pkg in root.iter("package"):
            name = pkg.get("id")
            version = pkg.get("version")
            if name:
                results.append((name, version or None))
        return results

    def _parse_lock_json(self, path: str) -> list[tuple[str, str | None]]:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        results: list[tuple[str, str | None]] = []
        for _framework, deps in data.get("dependencies", {}).items():
            for name, info in deps.items():
                version = info.get("resolved")
                results.append((name, version or None))
        return results
