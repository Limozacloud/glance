"""rpm cataloger — queries the ``rpm`` binary (the rpmdb format varies by RHEL
release: Berkeley DB on 7, ndb/sqlite on 8/9, so the binary is the portable
reader). Ownership is resolved on demand with ``rpm -qf`` over the small gated
candidate set, rather than building a full file index.

If the ``rpm`` binary is absent we record the cataloger as unavailable (an
honest gap in the report) — direct Berkeley-DB parsing is intentionally out of
scope for v1.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from urllib.parse import quote

from ..models import CatalogerStatus, Component, ComponentType, ScanReport, Source
from ._distro import distro_id

log = logging.getLogger(__name__)

_QF = r"%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n"
_SQLITE_DB = "/var/lib/rpm/rpmdb.sqlite"


def _purl(name: str, epoch: str, version: str, release: str, arch: str) -> str:
    namespace = distro_id() or "redhat"
    purl = f"pkg:rpm/{namespace}/{quote(name)}@{quote(version)}-{quote(release)}"
    params = []
    if arch and arch != "(none)":
        params.append(f"arch={quote(arch)}")
    if epoch and epoch not in ("(none)", "0", ""):
        params.append(f"epoch={quote(epoch)}")
    if params:
        purl += "?" + "&".join(params)
    return purl


class RpmCataloger:
    name = "rpm"

    def __init__(self) -> None:
        self.rpm = shutil.which("rpm")
        self._owner_cache: dict[str, str | None] = {}

    def available(self) -> bool:
        return self.rpm is not None

    def catalog(self, report: ScanReport) -> list[Component]:
        components: list[Component] = []
        if self.rpm is None:
            import os

            detail = (
                "rpm binary not found; sqlite rpmdb present but direct parse not implemented (v1)"
                if os.path.isfile(_SQLITE_DB)
                else "rpm binary not found"
            )
            report.catalogers.append(CatalogerStatus(self.name, False, detail=detail))
            return components
        try:
            proc = subprocess.run(
                [self.rpm, "-qa", "--qf", _QF],
                capture_output=True,
                check=False,
                text=True,
            )
        except OSError as exc:
            report.catalogers.append(CatalogerStatus(self.name, False, detail=str(exc)))
            return components
        if proc.returncode != 0:
            report.catalogers.append(
                CatalogerStatus(self.name, False, detail=f"rpm -qa failed: {proc.stderr.strip()}")
            )
            return components
        for line in proc.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) != 5:
                continue
            name, epoch, version, release, arch = parts
            if not name or not version:
                continue
            purl = _purl(name, epoch, version, release, arch)
            components.append(
                Component(
                    name=name,
                    version=f"{version}-{release}",
                    type=ComponentType.LIBRARY,
                    source=Source.RPM,
                    purl=purl,
                    bom_ref=purl,
                    managed=True,
                    metadata={"arch": arch, "epoch": epoch} if arch != "(none)" else {},
                )
            )
        report.catalogers.append(CatalogerStatus(self.name, True, len(components)))
        return components

    def owner(self, path: str) -> str | None:
        """Return the owning package PURL for ``path`` via ``rpm -qf``, or None."""
        if self.rpm is None:
            return None
        if path in self._owner_cache:
            return self._owner_cache[path]
        result: str | None = None
        try:
            proc = subprocess.run(
                [self.rpm, "-qf", "--qf", _QF, path],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
                text=True,
            )
            if proc.returncode == 0:
                parts = proc.stdout.strip().split("\t")
                if len(parts) == 5 and parts[0]:
                    result = _purl(*parts)
        except OSError:
            result = None
        self._owner_cache[path] = result
        return result
