"""Windows PE binary cataloger — reads VERSIONINFO resources from EXE/DLL/SYS.

Unlike the Linux binary cataloger (byte-regex on ELF), Windows PE binaries carry
structured VERSIONINFO resources with ProductName, ProductVersion, and CompanyName.
This gives reliable, unambiguous product identity without pattern guessing.

Discovery engine cascade:
  1. MFT (NTFS Master File Table) — fast, requires admin
  2. os.walk — full filesystem walk, always available as fallback

Gate: file extension (configurable, default .dll/.exe/.sys) + MZ magic (2-byte read).
Match: ProductName + CompanyName against ``glance/classifiers/win_binary_index.yaml``.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import logging
import os
import sys

from ..models import CatalogerStatus, Component, ComponentType, Occurrence, ScanReport, Source

log = logging.getLogger(__name__)

#: Default extensions — configurable via Config.win_pe_extensions.
DEFAULT_PE_EXTENSIONS = frozenset({".dll", ".exe", ".sys"})

#: Default paths to walk when no include_paths are configured.
#: Deliberately excludes C:\Windows — those files are managed by Windows Update.
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


def _load_binary_index(extension_file: str | None = None) -> list[dict]:
    from ..classifiers.win_binary_data import WIN_BINARY_ENTRIES

    entries = list(WIN_BINARY_ENTRIES)
    if extension_file:
        try:
            import yaml
        except ImportError as exc:
            raise ImportError("extension_file requires PyYAML — pip install pyyaml") from exc
        import pathlib

        doc = yaml.safe_load(pathlib.Path(extension_file).read_text(encoding="utf-8")) or {}
        entries.extend(doc.get("binary", {}).get("entries", []))
    return entries


_BINARY_INDEX_CACHE: dict[str | None, list[dict]] = {}


def _binary_index(extension_file: str | None = None) -> list[dict]:
    if extension_file not in _BINARY_INDEX_CACHE:
        _BINARY_INDEX_CACHE[extension_file] = _load_binary_index(extension_file)
    return _BINARY_INDEX_CACHE[extension_file]


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
        engine: str = "auto",
        extension_file: str | None = None,
    ) -> None:
        self.paths = paths or DEFAULT_WIN_PATHS
        self.extensions = frozenset(e.lower() for e in (extensions or DEFAULT_PE_EXTENSIONS))
        self.engine = engine  # "auto" | "mft" | "walk"
        self.extension_file = extension_file

    def available(self) -> bool:
        return sys.platform == "win32"

    def _discover(self, report: ScanReport) -> tuple[list[str], str]:
        """Return (candidate_paths, engine_used)."""
        if self.engine in ("auto", "mft"):
            from ..discovery import mft as _mft

            if _mft.available():
                drives = _mft.local_drives()
                candidates = _mft.query(
                    drives,
                    extensions=list(self.extensions),
                    scope_paths=self.paths,
                )
                return candidates, "mft"
            if self.engine == "mft":
                log.warning("win_binary: MFT not available (no admin?), falling back to walk")

        # walk fallback
        walk_candidates: list[str] = []
        for root_path in self.paths:
            if not os.path.isdir(root_path):
                continue
            for dirpath, _dirs, filenames in os.walk(root_path):
                for fname in filenames:
                    if os.path.splitext(fname)[1].lower() in self.extensions:
                        walk_candidates.append(os.path.join(dirpath, fname))
        return walk_candidates, "walk"

    def catalog(self, report: ScanReport) -> list[Component]:
        if not self.available():
            report.catalogers.append(
                CatalogerStatus(self.name, False, detail="not available on this platform")
            )
            return []

        try:
            index = _binary_index(self.extension_file)
        except Exception as exc:
            report.catalogers.append(
                CatalogerStatus(self.name, False, detail=f"failed to load binary index: {exc}")
            )
            return []

        candidates, engine_used = self._discover(report)
        log.debug("win_binary: %d candidates via %s", len(candidates), engine_used)

        components: list[Component] = []
        seen: set[tuple[str, str]] = set()

        for fpath in candidates:
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
                        occurrences=[Occurrence(path=fpath, found_by=f"win_binary/{engine_used}")],
                        metadata={
                            "product_name": product_name,
                            "company": company,
                            "index_id": entry["id"],
                        },
                    )
                )
                break

        report.catalogers.append(
            CatalogerStatus(self.name, True, len(components), detail=f"engine={engine_used}")
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
