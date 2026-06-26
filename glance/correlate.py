"""Managed/unmanaged correlation.

For each binary find we ask the package DBs: *does any package own this exact
path?* Three outcomes:

* **same product** — the owning package *is* this library (e.g. ``libcrypto.so.3``
  owned by ``libssl3``). Redundant; suppressed (the package component already
  represents it) and only recorded in the report.
* **foreign bundler** — a *different* package owns the path (e.g.
  ``/opt/Agent/libcrypto.so.1.1`` = openssl 1.1.1, owned by an ``agent`` deb).
  This is a bundled library a vulnerability scanner would otherwise miss (it only
  sees the agent package), so we **keep** it as a component with the upstream
  PURL/CPE and attribute it to the owning package.
* **unowned** — no package owns it (truly vendored). Emitted as its own
  ``pkg:generic`` component; outside the standard system dirs it is attributed to
  the install path as an ``application`` that bundles it.
"""

from __future__ import annotations

import os
import re
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


def _owner_pkg_name(purl: str) -> str:
    """Extract the package name from a PURL (``pkg:deb/ubuntu/NAME@ver`` -> NAME)."""
    return purl.split("@", 1)[0].rsplit("/", 1)[-1]


def _core(name: str) -> str:
    """Normalise a product/package name for comparison: drop separators, a leading
    ``lib`` prefix, and a trailing version-ish digit run."""
    s = re.sub(r"[^a-z0-9]", "", name.lower())
    if s.startswith("lib"):
        s = s[3:]
    return re.sub(r"\d+$", "", s)


def _same_product(product: str, owner_purl: str) -> bool:
    """True if the owning package looks like the same product as the binary find.

    Biased toward *False* (surface) when unsure — hiding a bundled vulnerable lib
    is worse than an occasionally redundant component.
    """
    pc = _core(product)
    kc = _core(_owner_pkg_name(owner_purl))
    if not pc or not kc:
        return False
    if pc == kc:
        return True
    if min(len(pc), len(kc)) < 3:
        return kc.startswith(pc) or pc.startswith(kc)
    return pc in kc or kc in pc


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
        bundled_by_owner: dict[str, list[Occurrence]] = {}

        for occ in comp.occurrences:
            owner = resolver.resolve(occ.path) if enabled else None
            if owner and (
                _same_product(comp.name, owner)
                or _is_system_dir(os.path.dirname(occ.path))
            ):
                report.correlations.append(
                    f"{occ.path} -> managed by {owner} (same product, suppressed; "
                    f"classifier={occ.found_by})"
                )
            elif owner:
                report.correlations.append(
                    f"{occ.path} -> bundled by {owner} (surfaced as {comp.name} "
                    f"{comp.version}; classifier={occ.found_by})"
                )
                bundled_by_owner.setdefault(owner, []).append(occ)
            else:
                unmanaged_by_dir.setdefault(os.path.dirname(occ.path), []).append(occ)

        base_ref = comp.purl or f"{comp.name}@{comp.version}"

        # foreign-bundled: keep the upstream identity, attribute to the owner package
        for owner, occs in bundled_by_owner.items():
            lib = Component(
                name=comp.name,
                version=comp.version,
                type=ComponentType.LIBRARY,
                source=Source.BINARY,
                purl=comp.purl,
                cpes=list(comp.cpes),
                occurrences=occs,
                managed=True,
                owned_by=owner,
                metadata=dict(comp.metadata),
            )
            lib.bom_ref = f"{base_ref}#bundled:{owner}"
            out.append(lib)

        # truly unowned: own component, attributed to its install path
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
