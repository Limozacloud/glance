"""Compact native JSON — one flat record per find, for humans and debugging."""

from __future__ import annotations

from ..models import ScanResult


def to_native(result: ScanResult) -> dict:
    components = []
    for comp in result.components:
        components.append(
            {
                "name": comp.name,
                "version": comp.version,
                "type": comp.type.value,
                "source": comp.source.value,
                "purl": comp.purl,
                "cpes": comp.cpes,
                "managed": comp.managed,
                "owned_by": comp.owned_by,
                "found_by": comp.occurrences[0].found_by if comp.occurrences else None,
                "paths": [occ.path for occ in comp.occurrences],
                "evidence": comp.occurrences[0].evidence if comp.occurrences else None,
                "sha256": next((o.sha256 for o in comp.occurrences if o.sha256), None),
            }
        )
    return {"components": components}
