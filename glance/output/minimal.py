"""Minimal output format: one flat list of {name, version, purl, cpe, path, source}."""

from __future__ import annotations

from ..models import ScanResult


def to_minimal(result: ScanResult) -> list[dict]:
    out = []
    for c in result.components:
        path = c.occurrences[0].path if c.occurrences else None
        entry: dict = {"name": c.name, "version": c.version, "purl": c.purl}
        if c.cpes:
            entry["cpe"] = c.cpes[0]
        if path:
            entry["path"] = path
        if c.source:
            entry["source"] = c.source.value
        out.append(entry)
    return out
