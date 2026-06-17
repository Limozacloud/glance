"""dpkg cataloger — parses ``/var/lib/dpkg/status`` directly (no dpkg binary).

Also builds a path -> package-PURL index from ``/var/lib/dpkg/info/*.list`` for
ownership correlation of binary finds.
"""

from __future__ import annotations

import logging
import os
from urllib.parse import quote

from ..models import CatalogerStatus, Component, ComponentType, ScanReport, Source
from ._distro import distro_id

log = logging.getLogger(__name__)


class DpkgCataloger:
    name = "dpkg"

    def __init__(self, root: str = "/") -> None:
        self.root = root
        self.status_path = os.path.join(root, "var/lib/dpkg/status")
        self.info_dir = os.path.join(root, "var/lib/dpkg/info")
        self._purl_by_name: dict[str, str] = {}

    def available(self) -> bool:
        return os.path.isfile(self.status_path)

    def _purl(self, name: str, version: str, arch: str) -> str:
        namespace = distro_id() or "debian"
        purl = f"pkg:deb/{namespace}/{quote(name)}@{quote(version)}"
        if arch:
            purl += f"?arch={quote(arch)}"
        return purl

    def catalog(self, report: ScanReport) -> list[Component]:
        components: list[Component] = []
        try:
            with open(self.status_path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            report.catalogers.append(CatalogerStatus(self.name, False, detail=str(exc)))
            return components

        for stanza in text.split("\n\n"):
            fields = _parse_stanza(stanza)
            if not fields:
                continue
            status = fields.get("Status", "")
            if "installed" not in status or "not-installed" in status:
                continue
            name = fields.get("Package")
            version = fields.get("Version")
            if not name or not version:
                continue
            arch = fields.get("Architecture", "")
            purl = self._purl(name, version, arch)
            self._purl_by_name[name] = purl
            if arch:
                self._purl_by_name[f"{name}:{arch}"] = purl
            components.append(
                Component(
                    name=name,
                    version=version,
                    type=ComponentType.LIBRARY,
                    source=Source.DPKG,
                    purl=purl,
                    bom_ref=purl,
                    managed=True,
                    metadata={"arch": arch} if arch else {},
                )
            )
        report.catalogers.append(CatalogerStatus(self.name, True, len(components)))
        return components

    def file_index(self) -> dict[str, str]:
        """Map every packaged file path to the owning package PURL."""
        index: dict[str, str] = {}
        if not os.path.isdir(self.info_dir):
            return index
        try:
            entries = os.listdir(self.info_dir)
        except OSError:
            return index
        for entry in entries:
            if not entry.endswith(".list"):
                continue
            pkg = entry[: -len(".list")]
            purl = self._purl_by_name.get(pkg)
            if purl is None and ":" in pkg:
                purl = self._purl_by_name.get(pkg.split(":", 1)[0])
            if purl is None:
                continue
            try:
                with open(
                    os.path.join(self.info_dir, entry), encoding="utf-8", errors="replace"
                ) as fh:
                    for line in fh:
                        path = line.rstrip("\n")
                        if path and path != "/.":
                            index[path] = purl
            except OSError:
                continue
        return index


def _parse_stanza(stanza: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    key = None
    for line in stanza.splitlines():
        if not line:
            continue
        if line[0] in (" ", "\t"):
            if key:
                fields[key] += "\n" + line.strip()
            continue
        name, _, value = line.partition(":")
        key = name.strip()
        fields[key] = value.strip()
    return fields
