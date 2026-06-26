"""NuGet ecosystem cataloger.

Parses four source types:
- packages.config          — classic .NET Framework projects
- *.packages.lock.json     — SDK-style lock files
- *.deps.json              — deployed .NET apps (runtime dependency manifest);
                             only entries with type="package" are NuGet packages
- *.csproj                 — SDK-style project files (<PackageReference>)
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET

from ...models import Source
from .base import EcosystemCataloger


class NugetCataloger(EcosystemCataloger):
    name = "nuget"
    source = Source.NUGET

    def manifest_filenames(self) -> list[str]:
        return ["packages.config", ".packages.lock.json", ".deps.json", ".csproj"]

    def _is_manifest(self, filename: str) -> bool:
        return (
            filename == "packages.config"
            or filename.endswith(".packages.lock.json")
            or filename.endswith(".deps.json")
            or filename.endswith(".csproj")
        )

    def _purl(self, name: str, version: str | None) -> str:
        v = version or "*"
        return f"pkg:nuget/{name}@{v}"

    def _parse_manifest(self, path: str) -> list[tuple[str, str | None]]:
        if path.endswith(".packages.lock.json"):
            return self._parse_lock_json(path)
        if path.endswith(".deps.json"):
            return self._parse_deps_json(path)
        if path.endswith(".csproj"):
            return self._parse_csproj(path)
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

    def _parse_csproj(self, path: str) -> list[tuple[str, str | None]]:
        tree = ET.parse(path)
        root = tree.getroot()
        results: list[tuple[str, str | None]] = []
        for ref in root.iter("PackageReference"):
            name = ref.get("Include")
            if not name:
                continue
            version = ref.get("Version") or ref.get("version")
            if version is None:
                child = ref.find("Version")
                if child is not None:
                    version = child.text
            results.append((name, version or None))
        return results

    def _parse_deps_json(self, path: str) -> list[tuple[str, str | None]]:
        with open(path, encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        results: list[tuple[str, str | None]] = []
        for entry, meta in data.get("libraries", {}).items():
            if meta.get("type") != "package":
                continue
            # entry format: "PackageName/1.2.3"
            if "/" in entry:
                name, _, version = entry.partition("/")
            else:
                name, version = entry, None
            if name:
                results.append((name, version or None))
        return results
