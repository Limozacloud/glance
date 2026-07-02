"""Windows PE binary cataloger — reads VERSIONINFO resources from EXE/DLL/SYS.

Unlike the Linux binary cataloger (byte-regex on ELF), Windows PE binaries carry
structured VERSIONINFO resources with ProductName, ProductVersion, and CompanyName.
This gives reliable, unambiguous product identity without pattern guessing.

Discovery: MFT (NTFS Master File Table) via FSCTL_ENUM_USN_DATA — fast, requires admin.
Gate: file extension (configurable, default .dll/.exe/.sys) + MZ magic (2-byte read).
Match: ProductName + CompanyName against ``glance/classifiers/win_binary_index.yaml``.
"""

from __future__ import annotations

import ctypes
import logging
import os
import sys

if sys.platform == "win32":
    import ctypes.wintypes

from ..models import CatalogerStatus, Component, ComponentType, Occurrence, ScanReport, Source

log = logging.getLogger(__name__)

#: Default extensions — configurable via Config.win_pe_extensions.
DEFAULT_PE_EXTENSIONS = frozenset({".dll", ".exe", ".sys"})

#: Paths walked by the walk engine. Deliberately excludes C:\Windows — those files
#: are managed by Windows Update.
DEFAULT_WIN_PATHS = [
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\ProgramData",
]

# ── VERSIONINFO reader ────────────────────────────────────────────────────────


def read_versioninfo(path: str) -> dict[str, str]:
    """Return VERSIONINFO StringFileInfo fields from a PE file.

    Returns an empty dict on any error (permission denied, no VERSIONINFO, etc.).
    Fields typically present: ProductName, ProductVersion, CompanyName,
    FileDescription, FileVersion.
    """
    try:
        ver = ctypes.windll.version  # type: ignore[attr-defined]
    except AttributeError:
        return {}

    try:
        dummy = ctypes.wintypes.DWORD()
        size = ver.GetFileVersionInfoSizeW(path, ctypes.byref(dummy))
        if not size:
            return {}

        buf = ctypes.create_string_buffer(size)
        if not ver.GetFileVersionInfoW(path, 0, size, buf):
            return {}

        lp = ctypes.c_void_p()
        ll = ctypes.c_uint()
        if not ver.VerQueryValueW(
            buf, r"\VarFileInfo\Translation", ctypes.byref(lp), ctypes.byref(ll)
        ):
            return {}
        if ll.value < 4:
            return {}
        if lp.value is None:
            return {}
        raw = ctypes.string_at(lp.value, ll.value)
        lang = int.from_bytes(raw[0:2], "little")
        cp = int.from_bytes(raw[2:4], "little")
        prefix = f"\\StringFileInfo\\{lang:04X}{cp:04X}\\"

        result: dict[str, str] = {}
        for field in (
            "ProductName",
            "ProductVersion",
            "CompanyName",
            "FileDescription",
            "FileVersion",
        ):
            vp = ctypes.c_void_p()
            vl = ctypes.c_uint()
            if (
                ver.VerQueryValueW(buf, prefix + field, ctypes.byref(vp), ctypes.byref(vl))
                and vp.value is not None
            ):
                s = ctypes.wstring_at(vp.value, vl.value).rstrip("\x00").strip()
                if s:
                    result[field] = s
        return result
    except Exception:  # noqa: BLE001
        return {}


def _normalize_version(raw: str) -> str:
    """Normalize a Windows VERSIONINFO version string for use in CPE/PURL.

    Strips non-numeric suffixes ("1.64.0.0 (MSVC release)" → "1.64.0"),
    then drops a trailing '.0' from 4-part versions ("3.0.13.0" → "3.0.13").
    """
    import re

    m = re.match(r"[\d]+(?:\.[\d]+)*", raw.strip())
    clean = m.group(0) if m else raw.strip()
    parts = clean.split(".")
    if len(parts) == 4 and parts[-1] == "0":
        parts = parts[:3]
    return ".".join(parts)


# ── Index loading ─────────────────────────────────────────────────────────────


_BINARY_INDEX_CACHE: list[dict] | None = None


def _binary_index() -> list[dict]:
    global _BINARY_INDEX_CACHE
    if _BINARY_INDEX_CACHE is None:
        from ..classifiers.win_binary_data import WIN_BINARY_ENTRIES

        _BINARY_INDEX_CACHE = list(WIN_BINARY_ENTRIES)
    return _BINARY_INDEX_CACHE


# ── Matching ──────────────────────────────────────────────────────────────────


def match_binary(product_name: str, company: str, entry: dict) -> bool:
    """Return True if VERSIONINFO fields match the index entry."""
    pn_lower = product_name.lower()
    pn_patterns: list[str] = entry.get("product_name_contains") or []
    if not any(p.lower() in pn_lower for p in pn_patterns):
        return False
    company_patterns: list[str] = entry.get("company_contains") or []
    if company_patterns:
        co_lower = company.lower()
        if not any(p.lower() in co_lower for p in company_patterns):
            return False
    return True


def _fill(template: str, version: str) -> str:
    return template.replace("{version}", version or "*")


# ── Cataloger ─────────────────────────────────────────────────────────────────


class WinBinaryCataloger:
    name = "win_binary"

    def __init__(
        self,
        paths: list[str] | None = None,
        extensions: list[str] | None = None,
        extra_entries: list[dict] | None = None,
    ) -> None:
        self.paths = paths or DEFAULT_WIN_PATHS
        self.extensions = frozenset(e.lower() for e in (extensions or DEFAULT_PE_EXTENSIONS))
        self._extra_entries: list[dict] = list(extra_entries or [])

    def available(self) -> bool:
        return sys.platform == "win32"

    def _discover(self) -> list[str]:
        from ..discovery import mft as _mft

        if not _mft.available():
            log.warning("win_binary: MFT not available — requires admin privileges")
            return []
        drives = _mft.local_drives()
        return _mft.query(drives, extensions=list(self.extensions), scope_paths=self.paths)

    def catalog(self, report: ScanReport) -> list[Component]:
        if not self.available():
            report.catalogers.append(
                CatalogerStatus(self.name, False, detail="not available on this platform")
            )
            return []

        try:
            index = _binary_index()
            if self._extra_entries:
                index = index + self._extra_entries
        except Exception as exc:
            report.catalogers.append(
                CatalogerStatus(self.name, False, detail=f"failed to load binary index: {exc}")
            )
            return []

        candidates = self._discover()
        log.debug("win_binary: %d candidates via mft", len(candidates))

        components: list[Component] = []
        seen: set[tuple[str, str]] = set()

        for fpath in candidates:
            if os.path.splitext(fpath)[1].lower() not in self.extensions:
                continue
            if not _is_pe(fpath):
                continue
            info = read_versioninfo(fpath)
            if not info:
                continue
            product_name = info.get("ProductName", "")
            company = info.get("CompanyName", "")
            if not product_name:
                continue
            raw_version = info.get("ProductVersion") or info.get("FileVersion") or ""
            version = _normalize_version(raw_version) if raw_version else ""

            for entry in index:
                if not match_binary(product_name, company, entry):
                    continue
                dedup = (entry["id"], version.lower())
                if dedup in seen:
                    break
                seen.add(dedup)
                purl = _fill(entry["purl_template"], version)
                cpe = _fill(entry["cpe_template"], version)
                components.append(
                    Component(
                        name=entry["name"],
                        version=version or None,
                        type=ComponentType.LIBRARY,
                        source=Source.BINARY,
                        purl=purl,
                        cpes=[cpe],
                        bom_ref=purl,
                        managed=False,
                        occurrences=[Occurrence(path=fpath, found_by="win_binary/mft")],
                        metadata={
                            "product_name": product_name,
                            "company": company,
                            "index_id": entry["id"],
                        },
                    )
                )
                break

        report.catalogers.append(
            CatalogerStatus(self.name, True, len(components), detail="engine=mft")
        )
        return components

    def file_index(self) -> dict[str, str]:
        return {}


def _is_pe(path: str) -> bool:
    """Return True if the first two bytes are the PE MZ signature."""
    try:
        with open(path, "rb") as fh:
            return fh.read(2) == b"MZ"
    except OSError:
        return False
