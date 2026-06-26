"""apk cataloger — parses Alpine's ``/lib/apk/db/installed`` directly.

The installed DB is a sequence of blank-line-separated stanzas. Package fields:
``P:`` name, ``V:`` version, ``A:`` arch, ``o:`` origin (source package).
File paths are built from ``F:`` (folder) followed by one or more ``R:``
(regular file) records.
"""

from __future__ import annotations

import logging
import os
from urllib.parse import quote

from ..models import CatalogerStatus, Component, ComponentType, ScanReport, Source
from ._distro import distro_id, distro_version_id

log = logging.getLogger(__name__)


class ApkCataloger:
    name = "apk"

    def __init__(self, root: str = "/") -> None:
        self.root = root
        self.db_path = os.path.join(root, "lib/apk/db/installed")
        self._index: dict[str, str] = {}

    def available(self) -> bool:
        return os.path.isfile(self.db_path)

    def _purl(self, name: str, version: str, arch: str, origin: str = "") -> str:
        namespace = distro_id() or "alpine"
        purl = f"pkg:apk/{namespace}/{quote(name)}@{quote(version)}"
        params = []
        if arch:
            params.append(f"arch={quote(arch)}")
        version_id = distro_version_id()
        if version_id:
            params.append(f"distro={quote(namespace)}-{quote(version_id)}")
        if origin and origin != name:
            params.append(f"upstream={quote(origin)}")
        if params:
            purl += "?" + "&".join(params)
        return purl

    def catalog(self, report: ScanReport) -> list[Component]:
        components: list[Component] = []
        try:
            with open(self.db_path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            report.catalogers.append(CatalogerStatus(self.name, False, detail=str(exc)))
            return components

        for stanza in text.split("\n\n"):
            if not stanza.strip():
                continue
            name = version = arch = origin = ""
            folder = ""
            files: list[str] = []
            for line in stanza.splitlines():
                if len(line) < 2 or line[1] != ":":
                    continue
                tag, value = line[0], line[2:]
                if tag == "P":
                    name = value
                elif tag == "V":
                    version = value
                elif tag == "A":
                    arch = value
                elif tag == "o":
                    origin = value
                elif tag == "F":
                    folder = value
                elif tag == "R":
                    files.append(f"/{folder}/{value}" if folder else f"/{value}")
            if not name or not version:
                continue
            purl = self._purl(name, version, arch, origin)
            for path in files:
                self._index[path] = purl
            components.append(
                Component(
                    name=name,
                    version=version,
                    type=ComponentType.LIBRARY,
                    source=Source.APK,
                    purl=purl,
                    bom_ref=purl,
                    managed=True,
                    metadata={"arch": arch} if arch else {},
                )
            )
        report.catalogers.append(CatalogerStatus(self.name, True, len(components)))
        return components

    def file_index(self) -> dict[str, str]:
        return self._index
