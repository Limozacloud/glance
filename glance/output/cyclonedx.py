"""Serialize a :class:`ScanResult` to CycloneDX 1.6 JSON.

CycloneDX is the chosen primary format because Grype, Trivy and osv-scanner all
ingest it natively. Each component carries ``name``/``version``/``purl``/``cpe``;
file locations go into ``evidence.occurrences`` and glance-specific facts
(found_by, managed, owning package) into namespaced ``properties``. The
application -> bundled-library links become the ``dependencies`` graph.
"""

from __future__ import annotations

from datetime import datetime, timezone

from ..models import Component, ScanResult


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _properties(comp: Component) -> list[dict]:
    props: list[dict] = []
    if comp.occurrences and comp.occurrences[0].found_by:
        props.append({"name": "glance:found_by", "value": comp.occurrences[0].found_by})
    if comp.managed is not None:
        props.append({"name": "glance:managed", "value": "true" if comp.managed else "false"})
    if comp.owned_by:
        props.append({"name": "glance:owned_by", "value": comp.owned_by})
    if comp.source:
        props.append({"name": "glance:source", "value": comp.source.value})
    # extra CPEs beyond the first (CycloneDX components carry a single `cpe`)
    for extra in comp.cpes[1:]:
        props.append({"name": "glance:cpe", "value": extra})
    for occ in comp.occurrences:
        if occ.sha256:
            props.append({"name": "glance:sha256", "value": occ.sha256})
            break
    container = comp.metadata.get("container")
    if container:
        props.append({"name": "glance:container", "value": container})
    return props


def _component(comp: Component) -> dict:
    out: dict = {"type": comp.type.value, "name": comp.name}
    if comp.bom_ref:
        out["bom-ref"] = comp.bom_ref
    if comp.version:
        out["version"] = comp.version
    if comp.purl:
        out["purl"] = comp.purl
    if comp.cpes:
        out["cpe"] = comp.cpes[0]
    occurrences = [{"location": occ.path} for occ in comp.occurrences if occ.path]
    if occurrences:
        out["evidence"] = {"occurrences": occurrences}
    props = _properties(comp)
    if props:
        out["properties"] = props
    return out


def _dependencies(components: list[Component]) -> list[dict]:
    # ref -> ordered list of dependency bom-refs, merged from explicit depends_on
    # and from owned_by (a bundled/owned component is a dependency of its owner).
    edges: dict[str, list[str]] = {}

    def add(ref: str, child: str) -> None:
        children = edges.setdefault(ref, [])
        if child not in children:
            children.append(child)

    for comp in components:
        if comp.bom_ref and comp.depends_on:
            for child in comp.depends_on:
                add(comp.bom_ref, child)
        if comp.bom_ref and comp.owned_by:
            add(comp.owned_by, comp.bom_ref)
    return [{"ref": ref, "dependsOn": children} for ref, children in edges.items() if children]


def to_cyclonedx(result: ScanResult, tool_version: str = "0.1.0") -> dict:
    """Render the scan result as a CycloneDX 1.6 BOM document (a ``dict``)."""
    bom: dict = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": _iso(result.timestamp),
            "tools": {
                "components": [{"type": "application", "name": "glance", "version": tool_version}]
            },
        },
        "components": [_component(c) for c in result.components],
    }
    deps = _dependencies(result.components)
    if deps:
        bom["dependencies"] = deps
    return bom
