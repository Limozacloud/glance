"""Managed/unmanaged correlation (Policy: unmanaged-first).

For each binary find we ask the package DBs: *does any package own this exact
path?* If yes, the find is managed — the package component already represents it
(with a proper ``pkg:rpm/deb/apk`` PURL), so we suppress it as a standalone
component and only record it in the report. If no package owns it, it is an
unmanaged find (e.g. a vendored/bundled library); it becomes its own
``pkg:generic`` component, and — when it lives outside the standard system
library dirs — is attributed to the install path as an ``application`` that
bundles it.
"""

from __future__ import annotations

import os
from collections.abc import Callable

from .models import Component, ComponentType, Occurrence, ScanReport, Source

#: Standard locations where an unowned library is "just a system file", not a
#: bundled application payload — so we do not wrap these in an application.
SYSTEM_DIRS = (
    "/usr/lib",
    "/usr/lib64",
    "/lib",
    "/lib64",
    "/usr/local/lib",
    "/usr/libexec",
    "/bin",
    "/usr/bin",
    "/sbin",
    "/usr/sbin",
)


class OwnershipResolver:
    """Resolve a path to its owning package PURL across the package backends."""

    def __init__(
        self,
        file_index: dict[str, str] | None = None,
        rpm_owner: Callable[[str], str | None] | None = None,
    ) -> None:
        self.file_index = file_index or {}
        self.rpm_owner = rpm_owner

    def resolve(self, path: str) -> str | None:
        owner = self.file_index.get(path)
        if owner is not None:
            return owner
        if self.rpm_owner is not None:
            return self.rpm_owner(path)
        return None


def _is_system_dir(directory: str) -> bool:
    return any(directory == d or directory.startswith(d + "/") for d in SYSTEM_DIRS)


def correlate(
    binary_components: list[Component],
    resolver: OwnershipResolver,
    report: ScanReport,
    enabled: bool = True,
) -> list[Component]:
    """Return the components the binary cataloger contributes after correlation."""
    out: list[Component] = []
    apps: dict[str, Component] = {}

    for comp in binary_components:
        unmanaged_by_dir: dict[str, list[Occurrence]] = {}
        for occ in comp.occurrences:
            owner = resolver.resolve(occ.path) if enabled else None
            if owner:
                report.correlations.append(
                    f"{occ.path} -> managed by {owner} (suppressed; classifier={occ.found_by})"
                )
            else:
                unmanaged_by_dir.setdefault(os.path.dirname(occ.path), []).append(occ)

        for directory, occs in unmanaged_by_dir.items():
            lib = Component(
                name=comp.name,
                version=comp.version,
                type=ComponentType.LIBRARY,
                source=Source.BINARY,
                purl=comp.purl,
                cpes=list(comp.cpes),
                occurrences=occs,
                managed=False,
                metadata=dict(comp.metadata),
            )
            base_ref = comp.purl or f"{comp.name}@{comp.version}"
            lib.bom_ref = f"{base_ref}#{directory}"

            if _is_system_dir(directory):
                out.append(lib)
                continue

            app = apps.get(directory)
            if app is None:
                app = Component(
                    name=directory,
                    version=None,
                    type=ComponentType.APPLICATION,
                    source=Source.BINARY,
                    bom_ref=f"app:{directory}",
                    managed=False,
                    occurrences=[Occurrence(path=directory, found_by="correlate")],
                )
                apps[directory] = app
            lib.owned_by = app.bom_ref
            if lib.bom_ref not in app.depends_on:
                app.depends_on.append(lib.bom_ref)
            out.append(lib)

    out.extend(apps.values())
    return out
