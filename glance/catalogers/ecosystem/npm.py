"""npm ecosystem cataloger — parses package-lock.json and yarn.lock."""

from __future__ import annotations

import json
import re

from ...models import Source
from .base import EcosystemCataloger

_YARN_VERSION = re.compile(r'^  version "([^"]+)"')
_YARN_ENTRY = re.compile(r'^"?(@?[^@"]+)@')


class NpmCataloger(EcosystemCataloger):
    name = "npm"
    source = Source.NPM

    def _is_manifest(self, filename: str) -> bool:
        return filename in ("package-lock.json", "yarn.lock")

    def _purl(self, name: str, version: str | None) -> str:
        v = version or "*"
        return f"pkg:npm/{name}@{v}"

    def _parse_manifest(self, path: str) -> list[tuple[str, str | None]]:
        if path.endswith("yarn.lock"):
            return self._parse_yarn_lock(path)
        return self._parse_package_lock(path)

    def _parse_package_lock(self, path: str) -> list[tuple[str, str | None]]:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        results: list[tuple[str, str | None]] = []
        lock_version = data.get("lockfileVersion", 1)
        if lock_version >= 2 and "packages" in data:
            for pkg_path, info in data["packages"].items():
                if not pkg_path or pkg_path == "":
                    continue
                # "node_modules/foo" or "node_modules/@scope/foo"
                name = pkg_path.removeprefix("node_modules/")
                # nested: "node_modules/a/node_modules/b" — take the last segment
                if "node_modules/" in name:
                    name = name.rsplit("node_modules/", 1)[-1]
                version = info.get("version")
                results.append((name, version))
        else:
            for name, info in data.get("dependencies", {}).items():
                version = info.get("version")
                results.append((name, version))
        return results

    def _parse_yarn_lock(self, path: str) -> list[tuple[str, str | None]]:
        results: list[tuple[str, str | None]] = []
        current_name: str | None = None
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("#") or not line.strip():
                    current_name = None
                    continue
                if not line.startswith(" ") and not line.startswith("\t"):
                    m = _YARN_ENTRY.match(line.split(",")[0].strip())
                    current_name = m.group(1).strip('"') if m else None
                elif current_name:
                    m = _YARN_VERSION.match(line)
                    if m:
                        results.append((current_name, m.group(1)))
                        current_name = None
        return results
