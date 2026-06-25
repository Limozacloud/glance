"""Windows registry cataloger — reads installed software from Uninstall keys.

Reads three hives:
  HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*          (64-bit)
  HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* (32-bit on 64-bit OS)
  HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*          (per-user)

Each entry is matched against ``glance/data/win_cpe_index.yaml``. Matched
components are emitted with a full PURL + CPE so downstream scanners (Grype,
Trivy) can correlate against the NVD.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import Callable

from ..models import CatalogerStatus, Component, ComponentType, Occurrence, ScanReport, Source
from .custom.dotnet import HANDLES as _DOTNET_HANDLES
from .custom.dotnet import read as _dotnet_read
from .custom.mssql import HANDLES as _MSSQL_HANDLES
from .custom.mssql import read as _mssql_read

_CUSTOM_READERS: list[tuple[frozenset[str], Callable[..., list[Component]]]] = [
    (frozenset(_MSSQL_HANDLES), _mssql_read),
    (frozenset(_DOTNET_HANDLES), _dotnet_read),
]

log = logging.getLogger(__name__)

_UNINSTALL_PATHS: list[tuple[int, str]] = []

_HKLM = 0x80000002
_HKCU = 0x80000001

_UNINSTALL_KEYS = [
    (_HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    (_HKLM, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    (_HKCU, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
]


def _load_index(extension_file: str | None = None) -> list[dict]:
    from ..classifiers.win_registry_data import WIN_REGISTRY_ENTRIES

    entries = list(WIN_REGISTRY_ENTRIES)
    if extension_file:
        entries.extend(_load_extension(extension_file, "registry"))
    return entries


def _load_extension(path: str, section: str) -> list[dict]:
    try:
        import yaml
    except ImportError as exc:
        raise ImportError("extension_file requires PyYAML — pip install pyyaml") from exc
    import pathlib

    doc = yaml.safe_load(pathlib.Path(path).read_text(encoding="utf-8")) or {}
    return doc.get(section, {}).get("entries", [])


_INDEX_CACHE: dict[str | None, list[dict]] = {}


def _index(extension_file: str | None = None) -> list[dict]:
    if extension_file not in _INDEX_CACHE:
        _INDEX_CACHE[extension_file] = _load_index(extension_file)
    return _INDEX_CACHE[extension_file]


def _match(display_name: str, publisher: str, entry: dict) -> bool:
    """Return True if this registry entry matches the CPE index entry."""
    dn_lower = display_name.lower()
    patterns: list[str] = entry.get("display_name_contains") or []
    if not any(p.lower() in dn_lower for p in patterns):
        return False
    exclude: list[str] = entry.get("display_name_not_contains") or []
    if any(p.lower() in dn_lower for p in exclude):
        return False
    pub_patterns: list[str] = entry.get("publisher_contains") or []
    if pub_patterns:
        pub_lower = publisher.lower()
        if not any(p.lower() in pub_lower for p in pub_patterns):
            return False
    return True


def _fill(template: str, version: str) -> str:
    return template.replace("{version}", version or "*")


class RegistryCataloger:
    name = "registry"

    def __init__(self, extension_file: str | None = None) -> None:
        self.extension_file = extension_file

    def available(self) -> bool:
        return sys.platform == "win32"

    def catalog(self, report: ScanReport) -> list[Component]:
        if not self.available():
            report.catalogers.append(
                CatalogerStatus(self.name, False, detail="not available on this platform")
            )
            return []

        try:
            import winreg  # noqa: PLC0415 — Windows only
        except ImportError:
            report.catalogers.append(
                CatalogerStatus(self.name, False, detail="winreg not available")
            )
            return []

        try:
            index = _index(self.extension_file)
        except Exception as exc:
            report.catalogers.append(
                CatalogerStatus(self.name, False, detail=f"failed to load CPE index: {exc}")
            )
            return []

        index_by_id = {e["id"]: e for e in index}
        skip_ids = frozenset(e["id"] for e in index if e.get("skip_uninstall"))

        seen: set[tuple[str, str]] = set()
        components: list[Component] = []

        for hive, subkey in _UNINSTALL_KEYS:
            try:
                root_key = winreg.OpenKey(hive, subkey)  # type: ignore[attr-defined]
            except OSError:
                continue
            with root_key:
                i = 0
                while True:
                    try:
                        child_name = winreg.EnumKey(root_key, i)  # type: ignore[attr-defined]
                    except OSError:
                        break
                    i += 1
                    try:
                        child_key = winreg.OpenKey(root_key, child_name)  # type: ignore[attr-defined]
                    except OSError:
                        continue
                    with child_key:
                        display_name = _reg_str(child_key, "DisplayName")
                        if not display_name:
                            continue
                        publisher = _reg_str(child_key, "Publisher") or ""
                        version = _reg_str(child_key, "DisplayVersion") or ""
                        install_location = _reg_str(child_key, "InstallLocation") or ""

                    dedup_key = (display_name.lower(), version.lower())
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    for entry in index:
                        if not _match(display_name, publisher, entry):
                            continue
                        if entry["id"] in skip_ids:
                            break  # handled by custom reader
                        purl = _fill(entry["purl_template"], version)
                        cpe = _fill(entry["cpe_template"], version)
                        components.append(
                            Component(
                                name=entry["name"],
                                version=version or None,
                                type=ComponentType.APPLICATION,
                                source=Source.REGISTRY,
                                purl=purl,
                                cpes=[cpe],
                                bom_ref=purl,
                                managed=True,
                                occurrences=[Occurrence(path=install_location, found_by="registry")]
                                if install_location
                                else [],
                                metadata={
                                    "display_name": display_name,
                                    "publisher": publisher,
                                    "index_id": entry["id"],
                                },
                            )
                        )
                        break  # first match wins

        invoked: set[int] = set()
        for handles, fn in _CUSTOM_READERS:
            if handles & skip_ids and id(fn) not in invoked:
                components.extend(fn(winreg, index_by_id))
                invoked.add(id(fn))

        report.catalogers.append(CatalogerStatus(self.name, True, len(components)))
        return components

    def file_index(self) -> dict[str, str]:
        return {}


def _reg_str(key: object, value_name: str) -> str | None:  # type: ignore[misc]
    try:
        import winreg

        val, _ = winreg.QueryValueEx(key, value_name)  # type: ignore[attr-defined,arg-type]
        return str(val).strip() if val else None
    except OSError:
        return None
