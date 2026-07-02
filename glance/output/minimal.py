"""Minimal output format: one flat list of {name, version, purl, cpe, path, source}."""

from __future__ import annotations

from ..models import ScanResult


def to_minimal(result: ScanResult) -> list[dict]:
    out = []
    for c in result.components:
        # skip correlate app-container placeholders (name=path, no version/purl)
        if c.version is None and c.purl is None and not c.cpes:
            continue
        # skip unresolved ecosystem deps (version wildcard * — no VDB match possible)
        if c.version is None:
            continue
        path = c.occurrences[0].path if c.occurrences else None
        entry: dict = {"name": c.name, "version": c.version, "purl": c.purl}
        if c.cpes:
            entry["cpe"] = c.cpes[0]
        if path:
            entry["path"] = path
        if c.source:
            entry["source"] = c.source.value
        container = c.metadata.get("container")
        if container:
            entry["container"] = container
            if c.metadata.get("container_image"):
                entry["container_image"] = c.metadata["container_image"]
            if c.metadata.get("container_provenance"):
                entry["container_provenance"] = c.metadata["container_provenance"]
        out.append(entry)
    return out
