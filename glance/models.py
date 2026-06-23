"""Data model for glance: components, evidence, and the audit scan report.

These dataclasses are the single source of truth produced by the catalogers.
Serialization to CycloneDX or the compact native JSON happens in
:mod:`glance.output` — the model itself is format-agnostic.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum


class ComponentType(str, Enum):
    """CycloneDX component types we emit."""

    APPLICATION = "application"
    LIBRARY = "library"
    OPERATING_SYSTEM = "operating-system"


class Source(str, Enum):
    """Which cataloger produced a component."""

    BINARY = "binary"
    RPM = "rpm"
    DPKG = "dpkg"
    APK = "apk"
    REGISTRY = "registry"


class SkipReason(str, Enum):
    """Why a path / filesystem / cataloger was not (fully) scanned.

    The whole point of the report is that nothing is skipped silently, so every
    omission is tagged with one of these.
    """

    CONFIG_EXCLUDE_PATH = "config:exclude_path"
    CONFIG_FS_TYPE = "config:exclude_fs_type"
    PERMISSION_DENIED = "permission_denied"
    NOT_FOUND = "not_found"
    DB_STALE = "db_stale"
    DB_MISSING = "db_missing"
    ENGINE_UNAVAILABLE = "engine_unavailable"
    CATALOGER_UNAVAILABLE = "cataloger_unavailable"
    MAX_FILE_SIZE = "max_file_size"
    NOT_ELF = "not_elf"
    READ_ERROR = "read_error"


@dataclass
class Occurrence:
    """A single physical location where evidence for a component was found."""

    path: str
    #: the classifier / cataloger that matched here
    found_by: str
    #: the literal pattern or DB field that produced the match (audit trail)
    evidence: str | None = None
    sha256: str | None = None


@dataclass
class Component:
    """One package/library/application in the SBOM.

    Components are mutable because the binary cataloger merges identical finds
    (same name + version, found at different paths or by different classifiers)
    into a single component with multiple :class:`Occurrence` entries.
    """

    name: str
    version: str | None
    type: ComponentType
    source: Source
    purl: str | None = None
    cpes: list[str] = field(default_factory=list)
    occurrences: list[Occurrence] = field(default_factory=list)
    #: True when a package manager owns the file(s); False for unmanaged finds;
    #: None when correlation did not run / does not apply (e.g. the package itself).
    managed: bool | None = None
    #: PURL of the owning package, when this component is bundled by an application
    #: or owned by a package.
    owned_by: str | None = None
    #: bom-ref / dependency-graph children (PURLs or bom-refs).
    bom_ref: str | None = None
    depends_on: list[str] = field(default_factory=list)
    #: free-form metadata (e.g. classifier match details, raw package fields).
    metadata: dict = field(default_factory=dict)

    @property
    def key(self) -> tuple:
        """Merge key — components with the same key are consolidated."""
        return (self.source.value, self.name, self.version, self.type.value)


@dataclass
class SkippedEntry:
    """An audit record of something deliberately or unavoidably not scanned."""

    target: str
    reason: SkipReason
    detail: str | None = None


@dataclass
class CatalogerStatus:
    """Per-cataloger audit record: did it run, and if not, why."""

    name: str
    ran: bool
    components_found: int = 0
    detail: str | None = None


@dataclass
class ScanReport:
    """Auditable account of the scan.

    A "green" result must never silently mean "green, except the 2 TB nobody
    looked at" — everything omitted shows up here.
    """

    engine_used: str | None = None
    engine_reason: str | None = None
    engine_cascade: list[str] = field(default_factory=list)
    scanned_paths: list[str] = field(default_factory=list)
    mandatory_paths: list[str] = field(default_factory=list)
    skipped: list[SkippedEntry] = field(default_factory=list)
    catalogers: list[CatalogerStatus] = field(default_factory=list)
    files_considered: int = 0
    files_read: int = 0
    duration_seconds: float = 0.0
    warnings: list[str] = field(default_factory=list)
    #: audit of binary finds suppressed because a package owns the path.
    correlations: list[str] = field(default_factory=list)

    def skip(self, target: str, reason: SkipReason, detail: str | None = None) -> None:
        self.skipped.append(SkippedEntry(target=target, reason=reason, detail=detail))


@dataclass
class ScanResult:
    """The public return value of :func:`glance.scan`."""

    components: list[Component] = field(default_factory=list)
    report: ScanReport = field(default_factory=ScanReport)
    #: unix timestamp the scan completed (stamped by the caller / CLI).
    timestamp: float = field(default_factory=time.time)
