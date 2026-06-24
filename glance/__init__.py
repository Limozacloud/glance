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
    result = scan(Config(include_paths=["/opt", "/usr/lib64"]))
    for c in result.components:
        print(c.name, c.version, c.purl, c.managed)
"""

from __future__ import annotations

import logging
import time

from .catalogers import ECOSYSTEM_CATALOGERS, PACKAGE_CATALOGERS, BinaryCataloger, expand_catalogers
from .catalogers.binary.classifiers import default_classifiers
from .catalogers.binary.loader import load_classifier_file
from .config import Config, Engine, OnStaleDB
from .correlate import OwnershipResolver, correlate
from .discovery import discover
from .discovery.gate import Gate, derive_globs
from .models import CatalogerStatus, Component, ScanReport, ScanResult

try:  # pragma: no cover
    from importlib.metadata import version as _version

    __version__ = _version("glance")
except Exception:  # pragma: no cover
    __version__ = "0.2.0"

__all__ = [
    "scan",
    "Config",
    "Engine",
    "OnStaleDB",
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
    for path in config.classifier_files:
        classifiers.extend(load_classifier_file(path))
    globs = config.file_globs or derive_globs(classifiers)
    gate = Gate(globs)

    raw_catalogers = expand_catalogers(config.catalogers) if config.catalogers is not None else None
    enabled: set[str] | None = set(raw_catalogers) if raw_catalogers is not None else None

    components: list[Component] = []
    file_index: dict[str, str] = {}
    rpm_owner = None

    # 1) package catalogers (also feed ownership correlation)
    for name, cataloger_cls in PACKAGE_CATALOGERS.items():
        if enabled is not None and name not in enabled:
            report.catalogers.append(CatalogerStatus(name, False, detail="disabled by config"))
            continue
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

    # 2) binary cataloger + correlation
    if enabled is None or "binary" in enabled:
        candidates = discover(config, gate, report)
        binary_components = BinaryCataloger(classifiers).catalog(candidates, config, report)
        resolver = OwnershipResolver(file_index, rpm_owner)
        correlated = correlate(
            binary_components, resolver, report, enabled=config.correlate_ownership
        )
        components.extend(correlated)
        report.catalogers.append(CatalogerStatus("binary", True, len(correlated)))
    else:
        report.catalogers.append(CatalogerStatus("binary", False, detail="disabled by config"))

    # 3) ecosystem catalogers (need include_paths to know where to walk)
    eco_paths = config.include_paths or []
    for name, cataloger_cls in ECOSYSTEM_CATALOGERS.items():
        if enabled is not None and name not in enabled:
            report.catalogers.append(CatalogerStatus(name, False, detail="disabled by config"))
            continue
        cataloger = cataloger_cls(paths=eco_paths)
        components.extend(cataloger.catalog(report))

    report.duration_seconds = time.perf_counter() - start
    return ScanResult(components=components, report=report)
