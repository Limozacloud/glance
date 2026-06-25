"""RubyGems ecosystem cataloger — parses Gemfile.lock."""

from __future__ import annotations

import re

from ...models import Source
from .base import EcosystemCataloger

_SPEC_LINE = re.compile(r"^    ([A-Za-z0-9][A-Za-z0-9_.-]*) \(([^)]+)\)$")


class GemCataloger(EcosystemCataloger):
    name = "gem"
    source = Source.GEM

    def _is_manifest(self, filename: str) -> bool:
        return filename == "Gemfile.lock"

    def _purl(self, name: str, version: str | None) -> str:
        v = version or "*"
        return f"pkg:gem/{name}@{v}"

    def _parse_manifest(self, path: str) -> list[tuple[str, str | None]]:
        results: list[tuple[str, str | None]] = []
        in_specs = False
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                stripped = line.rstrip()
                if stripped == "  specs:":
                    in_specs = True
                    continue
                if in_specs:
                    if stripped and not stripped.startswith("    "):
                        in_specs = False
                        continue
                    m = _SPEC_LINE.match(stripped)
                    if m:
                        results.append((m.group(1), m.group(2)))
        return results
