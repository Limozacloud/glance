"""Maven ecosystem cataloger — parses pom.xml."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from ...models import Source
from .base import EcosystemCataloger

_NS = "http://maven.apache.org/POM/4.0.0"


def _text(el: ET.Element | None) -> str | None:
    if el is None:
        return None
    t = (el.text or "").strip()
    return t if t and not t.startswith("${") else None


class MavenCataloger(EcosystemCataloger):
    name = "maven"
    source = Source.MAVEN

    def _is_manifest(self, filename: str) -> bool:
        return filename == "pom.xml"

    def _purl(self, name: str, version: str | None) -> str:
        v = version or "*"
        return f"pkg:maven/{name}@{v}"

    def _parse_manifest(self, path: str) -> list[tuple[str, str | None]]:
        tree = ET.parse(path)
        root = tree.getroot()
        ns = _NS if root.tag.startswith("{") else ""
        prefix = f"{{{ns}}}" if ns else ""

        results: list[tuple[str, str | None]] = []
        for dep_section in root.iter(f"{prefix}dependencies"):
            for dep in dep_section.findall(f"{prefix}dependency"):
                group = _text(dep.find(f"{prefix}groupId"))
                artifact = _text(dep.find(f"{prefix}artifactId"))
                version = _text(dep.find(f"{prefix}version"))
                if group and artifact:
                    results.append((f"{group}/{artifact}", version))
        return results
