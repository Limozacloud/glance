"""glance — a mini-SBOM scanner.

Two kinds of evidence, one unified CycloneDX SBOM:

* **package catalogers** (rpm / dpkg / apk) enumerate installed packages with
  full versions and ``pkg:rpm``/``pkg:deb``/``pkg:apk`` PURLs;
* the **binary cataloger** finds files via cheap locate gates, reads the version
  out of the bytes, and attributes them to an upstream identity (e.g. a
  bundled ``libcrypto.so`` -> ``openssl 1.1.1w`` with PURL + CPE) — exactly the
  unmanaged libraries OSV/Trivy miss because no package owns them.

Quick start::

    from glance import scan, Config
    result = scan(Config())
    for c in result.components:
        print(c.name, c.version, c.purl, c.managed)
"""

from __future__ import annotations

import logging
import time

from .catalogers import (
    ECOSYSTEM_INSTALLED_CATALOGERS,
    ECOSYSTEM_PROJECT_CATALOGERS,
    PACKAGE_CATALOGERS,
    BinaryCataloger,
    GoBinaryCataloger,
    expand_catalogers,
)
from .classifiers.core.loader import load_classifier_file_split
from .classifiers.linux_binary import default_classifiers
from .config import Config
from .correlate import OwnershipResolver, correlate
from .discovery import discover_all
from .discovery.gate import Gate, derive_globs
from .models import CatalogerStatus, Component, ScanReport, ScanResult

try:  # pragma: no cover
    from importlib.metadata import version as _version

    __version__ = _version("glance")
except Exception:  # pragma: no cover
    __version__ = "0.5.0"

__all__ = [
    "scan",
    "Config",
    "ScanResult",
    "ScanReport",
    "Component",
    "__version__",
]

log = logging.getLogger(__name__)


def scan(config: Config | None = None) -> ScanResult:
    """Run all applicable catalogers and return a unified :class:`ScanResult`."""
    config = config or Config()
    report = ScanReport()
    start = time.perf_counter()

    classifiers = default_classifiers()
    registry_extra: list[dict] = []
    win_binary_extra: list[dict] = []
    for path in config.classifier_files:
        bin_cls, reg_ent, wb_ent = load_classifier_file_split(path)
        classifiers.extend(bin_cls)
        registry_extra.extend(reg_ent)
        win_binary_extra.extend(wb_ent)
    globs = config.file_globs or derive_globs(classifiers)
    gate = Gate(globs)

    from .discovery.containers import build_container_map

    container_map = build_container_map()

    raw_catalogers = expand_catalogers(config.catalogers) if config.catalogers is not None else None
    enabled: set[str] | None = set(raw_catalogers) if raw_catalogers is not None else None

    components: list[Component] = []
    file_index: dict[str, str] = {}
    rpm_owner = None

    # 1) package catalogers (also feed ownership correlation)
    from .catalogers.win_binary import WinBinaryCataloger as _WinBin

    for name, cataloger_cls in PACKAGE_CATALOGERS.items():
        if enabled is not None and name not in enabled:
            report.catalogers.append(CatalogerStatus(name, False, detail="disabled by config"))
            continue
        from .catalogers.registry import RegistryCataloger as _Reg

        if cataloger_cls is _WinBin:
            cataloger = cataloger_cls(  # type: ignore[assignment]
                extensions=config.win_pe_extensions,
                engine=config.win_binary_engine,
                extra_entries=win_binary_extra or None,
            )
        elif cataloger_cls is _Reg:
            cataloger = cataloger_cls(  # type: ignore[assignment]
                extra_entries=registry_extra or None,
            )
        else:
            cataloger = cataloger_cls()
        if not cataloger.available():
            report.catalogers.append(
                CatalogerStatus(name, False, detail="not available on this host")
            )
            continue
        components.extend(cataloger.catalog(report))
        index_fn = getattr(cataloger, "file_index", None)
        if callable(index_fn):
            file_index.update(index_fn())
        owner_fn = getattr(cataloger, "owner", None)
        if callable(owner_fn):
            rpm_owner = owner_fn

    # 2+3) unified discovery — one filesystem pass for binary + all ecosystem catalogers

    # Pick the active ecosystem cataloger set:
    # - No explicit --catalogers (enabled is None) or "ecosystem" sentinel in enabled
    #   → use ecosystem_mode to select project vs installed set.
    # - Explicit individual cataloger names → run exactly those (user override).
    _all_eco = {**ECOSYSTEM_PROJECT_CATALOGERS, **ECOSYSTEM_INSTALLED_CATALOGERS}
    _eco_sentinel = "ecosystem" in (enabled or set())
    if enabled is None or _eco_sentinel:
        _active_eco = (
            ECOSYSTEM_INSTALLED_CATALOGERS
            if config.ecosystem_mode == "installed"
            else ECOSYSTEM_PROJECT_CATALOGERS
        )
        eco_catalogers = {name: cls(paths=[], config=config) for name, cls in _active_eco.items()}
    else:
        eco_catalogers = {
            name: cls(paths=[], config=config) for name, cls in _all_eco.items() if name in enabled
        }

    extra_names: list[str] = [
        n for cat in eco_catalogers.values() for n in cat.manifest_filenames()
    ]

    if enabled is None or "binary" in enabled:
        file_idx = discover_all(config, gate, extra_names, report)
        binary_candidates = file_idx.matching_gate(gate)
        binary_components = BinaryCataloger(classifiers, container_map=container_map).catalog(
            binary_candidates, config, report
        )
        resolver = OwnershipResolver(file_index, rpm_owner)
        correlated = correlate(
            binary_components, resolver, report, enabled=config.correlate_ownership
        )
        components.extend(correlated)
        report.catalogers.append(CatalogerStatus("binary", True, len(correlated)))
    else:
        report.catalogers.append(CatalogerStatus("binary", False, detail="disabled by config"))
        file_idx = discover_all(config, gate, extra_names, report)

    if enabled is None or "gobinary" in enabled:
        go_comps = GoBinaryCataloger().catalog(["/"], report)
        components.extend(go_comps)
    else:
        report.catalogers.append(CatalogerStatus("gobinary", False, detail="disabled by config"))

    for name, cataloger in eco_catalogers.items():
        components.extend(cataloger.catalog(report, index=file_idx))

    report.duration_seconds = time.perf_counter() - start
    return ScanResult(components=components, report=report)
