"""Go modules ecosystem cataloger — parses go.sum."""

from __future__ import annotations

import re

from ...models import Source
from .base import EcosystemCataloger

_LINE = re.compile(r"^(\S+)\s+(v[^\s/]+)(?:/go\.mod)?\s")


class GoCataloger(EcosystemCataloger):
    name = "go"
    source = Source.GO

    def manifest_filenames(self) -> list[str]:
        return ["go.sum"]

    def _is_manifest(self, filename: str) -> bool:
        return filename == "go.sum"

    def _purl(self, name: str, version: str | None) -> str:
        v = version or "*"
        return f"pkg:golang/{name}@{v}"

    def _parse_manifest(self, path: str) -> list[tuple[str, str | None]]:
        seen: set[tuple[str, str]] = set()
        results: list[tuple[str, str | None]] = []
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = _LINE.match(line)
                if not m:
                    continue
                module, version = m.group(1), m.group(2)
                ver = version
                key = (module, ver)
                if key in seen:
                    continue
                seen.add(key)
                results.append((module, ver))
        return results
