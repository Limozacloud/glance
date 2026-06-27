"""Go binary cataloger — reads build info embedded by the Go linker.

Since Go 1.13 the linker embeds module dependency information directly into
the produced binary.  No Go installation is required; we search for the known
``\\xff Go buildinf:`` magic and parse the text block that follows.
"""

from __future__ import annotations

import logging
import mmap
import os
import re
import stat
from urllib.parse import quote

from ..models import CatalogerStatus, Component, ComponentType, ScanReport, Source

log = logging.getLogger(__name__)

# Magic written by the Go linker into every Go binary.
_MAGIC = b"\xff Go buildinf:"

# New format (Go 1.18+, flags bit 1 set): text starts with "go\tgo1." and is
# embedded directly.
_TEXT_RE = re.compile(
    rb"go\tgo\d[^\n]*\n(?:(?:path|mod|dep|build)\t[^\n]*\n)*",
    re.MULTILINE,
)

# Old format (pre-1.18): linker places infoStart/infoEnd markers around the
# modinfo blob. These are fixed 16-byte sentinels.
_INFO_START = bytes.fromhex("3077af0c9274080241e1c107e6d618e6")
_INFO_END   = bytes.fromhex("f932433186182072008242104116d8f2")

# Skip binaries larger than this to avoid reading entire filesystem images.
_MAX_FILE_SIZE = 256 * 1024 * 1024  # 256 MB


def _is_elf(header: bytes) -> bool:
    return len(header) >= 4 and header[:4] == b"\x7fELF"


def _extract_text(mm: mmap.mmap) -> str | None:
    """Return the raw modinfo text block or None."""
    # New format (Go 1.18+, flags bit 1): text embedded with "go\t" first line.
    m = _TEXT_RE.search(mm)
    if m:
        return m.group(0).decode("utf-8", errors="replace")
    # Old format (pre-1.18): text between infoStart / infoEnd sentinels.
    s = mm.find(_INFO_START)
    if s == -1:
        return None
    s += len(_INFO_START)
    e = mm.find(_INFO_END, s)
    if e == -1:
        return None
    try:
        return mm[s:e].decode("utf-8", errors="replace")
    except Exception:
        return None


def _parse_buildinfo(mm: mmap.mmap) -> dict | None:
    """Return parsed build info or None when the binary is not a Go binary."""
    if mm.find(_MAGIC) == -1:
        return None
    text = _extract_text(mm)
    if not text:
        return None

    info: dict = {"go_version": "", "path": "", "main_version": "", "deps": []}
    for line in text.splitlines():
        parts = line.split("\t")
        tag = parts[0] if parts else ""
        if tag == "go" and len(parts) >= 2:
            info["go_version"] = parts[1].lstrip("go")
        elif tag == "path" and len(parts) >= 2:
            info["path"] = parts[1]
        elif tag == "mod" and len(parts) >= 3:
            if not info["path"]:
                info["path"] = parts[1]
            info["main_version"] = parts[2]
        elif tag == "dep" and len(parts) >= 3:
            info["deps"].append({"module": parts[1], "version": parts[2]})

    return info if (info["path"] or info["go_version"]) else None


def _purl(module: str, version: str) -> str:
    return f"pkg:golang/{module}@{quote(version, safe='./+-_')}"


class GoBinaryCataloger:
    name = "gobinary"

    def available(self) -> bool:
        return True

    def catalog(self, paths: list[str], report: ScanReport) -> list[Component]:
        components: list[Component] = []
        # (module, version) — deduplicate across all scanned binaries
        seen: set[tuple[str, str]] = set()

        for root in paths:
            try:
                walker = os.walk(root, followlinks=False)
            except OSError:
                continue
            for dirpath, _dirs, filenames in walker:
                for fname in filenames:
                    fpath = os.path.join(dirpath, fname)
                    try:
                        st = os.stat(fpath, follow_symlinks=False)
                    except OSError:
                        continue
                    if not stat.S_ISREG(st.st_mode) or st.st_size > _MAX_FILE_SIZE:
                        continue
                    try:
                        with open(fpath, "rb") as f:
                            header = f.read(4)
                    except OSError:
                        continue
                    if not _is_elf(header):
                        continue
                    components.extend(self._scan_file(fpath, st.st_size, seen))

        report.catalogers.append(CatalogerStatus(self.name, True, len(components)))
        return components

    def _scan_file(
        self, path: str, size: int, seen: set[tuple[str, str]]
    ) -> list[Component]:
        if size == 0:
            return []
        try:
            with open(path, "rb") as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    info = _parse_buildinfo(mm)
        except (OSError, ValueError):
            return []
        if info is None:
            return []

        comps: list[Component] = []

        main_module = info["path"]
        main_version = info["main_version"]
        if main_module and main_version and main_version != "(devel)":
            key = (main_module, main_version)
            if key not in seen:
                seen.add(key)
                p = _purl(main_module, main_version)
                comps.append(
                    Component(
                        name=main_module.rsplit("/", 1)[-1],
                        version=main_version,
                        type=ComponentType.APPLICATION,
                        source=Source.GO,
                        purl=p,
                        bom_ref=p,
                        managed=False,
                        metadata={
                            "module": main_module,
                            "go_version": info["go_version"],
                            "binary_path": path,
                        },
                    )
                )

        for dep in info["deps"]:
            module = dep["module"]
            version = dep["version"]
            if not module or not version or version == "(devel)":
                continue
            key = (module, version)
            if key in seen:
                continue
            seen.add(key)
            p = _purl(module, version)
            comps.append(
                Component(
                    name=module.rsplit("/", 1)[-1],
                    version=version,
                    type=ComponentType.LIBRARY,
                    source=Source.GO,
                    purl=p,
                    bom_ref=p,
                    managed=False,
                    metadata={"module": module, "go_version": info["go_version"]},
                )
            )

        return comps
