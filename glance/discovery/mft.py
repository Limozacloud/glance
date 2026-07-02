"""Windows MFT fast-path: FSCTL_ENUM_USN_DATA.

Direct NTFS Master File Table enumeration via ctypes — no service, no install.
Requires admin privileges; falls back gracefully when unavailable.

Typical wall-clock on a developer workstation:
  C:\\ manifests  (exact names):   ~8s    vs  os.walk: ~20 min
  C:\\ *.dll      (extension):     ~6s    vs  os.walk: ~20 min
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import logging
import struct
import sys
from typing import Any

log = logging.getLogger(__name__)

if sys.platform == "win32":
    _k32: Any = ctypes.windll.kernel32
else:
    _k32: Any = None

_GENERIC_READ = 0x80000000
_FILE_SHARE_READ = 0x1
_FILE_SHARE_WRITE = 0x2
_OPEN_EXISTING = 3
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FSCTL_ENUM_USN_DATA = 0x900B3
_FILE_ATTRIBUTE_DIRECTORY = 0x10
_ERROR_HANDLE_EOF = 38
_DRIVE_FIXED = 3
_MFT_ROOT_REF = 5

# USN_RECORD_V2: RecordLength, Major, Minor, FileRef, ParentRef, Usn, Timestamp,
#                Reason, SourceInfo, SecurityId, FileAttributes, NameLen, NameOff
_FMT = "<IHHQQqQIIIIHH"
_HS = struct.calcsize(_FMT)  # 60 bytes
_BUF = 1 << 20  # 1 MB per DeviceIoControl call


def _ref(r: int) -> int:
    """Strip 16-bit sequence number from a 64-bit MFT reference."""
    return r & 0x0000_FFFF_FFFF_FFFF


# ── Drive enumeration ─────────────────────────────────────────────────────────


def local_drives() -> list[str]:
    """Return drive letters for all local fixed NTFS drives (e.g. ['C', 'D'])."""
    if sys.platform != "win32":
        return []
    buf = ctypes.create_string_buffer(1024)
    n = _k32.GetLogicalDriveStringsW(len(buf) // 2, buf)
    if n == 0:
        return []
    raw = buf.raw[: n * 2].decode("utf-16-le", "replace")
    drives: list[str] = []
    for token in raw.split("\x00"):
        token = token.strip()
        if not token:
            continue
        letter = token[0].upper()
        root = token if token.endswith("\\") else token + "\\"
        if _k32.GetDriveTypeW(root) == _DRIVE_FIXED:
            drives.append(letter)
    return drives


def available() -> bool:
    """Return True if MFT access works on at least one local drive."""
    if sys.platform != "win32":
        return False
    for drive in local_drives():
        h = _k32.CreateFileW(  # type: ignore[attr-defined]
            f"\\\\.\\{drive}:",
            _GENERIC_READ,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE,
            None,
            _OPEN_EXISTING,
            _FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        if h != ctypes.c_void_p(-1).value:
            _k32.CloseHandle(h)  # type: ignore[attr-defined]
            return True
    return False


# ── Core MFT scan ─────────────────────────────────────────────────────────────


def _scan_volume(
    drive: str,
    names_lower: frozenset[str] | None,
    exts_lower: frozenset[str] | None,
) -> tuple[dict[int, tuple[int, str]], list[tuple[int, str]]] | None:
    """
    Single-pass MFT enumeration.

    Builds dir_map (ref -> (parent_ref, name)) for all directories.
    Collects hits (parent_ref, name) for files matching names or extensions.
    Returns None on permission error / non-NTFS volume.
    """
    try:
        h = _k32.CreateFileW(  # type: ignore[attr-defined]
            f"\\\\.\\{drive}:",
            _GENERIC_READ,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE,
            None,
            _OPEN_EXISTING,
            _FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        if h == ctypes.c_void_p(-1).value:
            log.debug("mft: %s: open failed (not admin or non-NTFS)", drive)
            return None
    except OSError as exc:
        log.debug("mft: %s: %s", drive, exc)
        return None

    dir_map: dict[int, tuple[int, str]] = {}
    hits: list[tuple[int, str]] = []
    out = ctypes.create_string_buffer(_BUF)
    br = ctypes.wintypes.DWORD()
    start_ref = 0

    try:
        while True:
            ib = ctypes.create_string_buffer(
                struct.pack("<QQQ", start_ref, 0, 0x7FFF_FFFF_FFFF_FFFF)
            )
            ok = _k32.DeviceIoControl(  # type: ignore[attr-defined]
                h,
                _FSCTL_ENUM_USN_DATA,
                ib,
                ctypes.sizeof(ib),
                out,
                _BUF,
                ctypes.byref(br),
                None,
            )
            if not ok:
                if _k32.GetLastError() == _ERROR_HANDLE_EOF:  # type: ignore[attr-defined]
                    break
                log.debug("mft: %s: DeviceIoControl error %d", drive, _k32.GetLastError())  # type: ignore[attr-defined]
                return None

            data = out.raw[: br.value]
            start_ref = struct.unpack_from("<Q", data, 0)[0]
            off = 8

            while off + _HS <= len(data):
                (rec_len, _, _, file_ref_raw, parent_ref_raw, _, _, _, _, _, attrs, nl, no) = (
                    struct.unpack_from(_FMT, data, off)
                )

                if rec_len == 0:
                    break

                name = data[off + no : off + no + nl].decode("utf-16-le", "replace")
                is_dir = bool(attrs & _FILE_ATTRIBUTE_DIRECTORY)

                if is_dir:
                    dir_map[_ref(file_ref_raw)] = (_ref(parent_ref_raw), name)
                else:
                    nl_lower = name.lower()
                    # names: substring match (mirrors plocate — "packages.lock.json" also finds "MyApp.packages.lock.json")
                    matched = (names_lower and any(n in nl_lower for n in names_lower)) or (
                        exts_lower and any(nl_lower.endswith(e) for e in exts_lower)
                    )
                    if matched:
                        hits.append((_ref(parent_ref_raw), name))

                off += rec_len
    finally:
        _k32.CloseHandle(h)  # type: ignore[attr-defined]

    log.debug("mft: %s: %d dirs, %d hits", drive, len(dir_map), len(hits))
    return dir_map, hits


def _resolve_path(dir_map: dict[int, tuple[int, str]], ref: int, drive: str) -> str:
    parts: list[str] = []
    seen: set[int] = set()
    cur = ref
    while cur != _MFT_ROOT_REF and cur in dir_map:
        if cur in seen:
            return f"{drive}:\\<cycle>"
        seen.add(cur)
        parent, name = dir_map[cur]
        parts.append(name)
        cur = parent
    parts.reverse()
    return drive + ":\\" + "\\".join(parts)


# ── Public API ────────────────────────────────────────────────────────────────


def query(
    drives: list[str],
    names: list[str] | None = None,
    extensions: list[str] | None = None,
    scope_paths: list[str] | None = None,
) -> list[str]:
    """
    Enumerate files across *drives* matching *names* (exact) or *extensions*.

    Args:
        drives:      Drive letters to scan, e.g. ``["C", "D"]``.
        names:       Exact filenames, e.g. ``["requirements.txt", "go.sum"]``.
        extensions:  File extensions with leading dot, e.g. ``[".dll", ".exe"]``.
        scope_paths: If set, only return paths under these roots.

    Returns:
        Flat list of full absolute paths.
    """
    if sys.platform != "win32":
        return []

    names_lower = frozenset(n.lower() for n in names) if names else None
    exts_lower = frozenset(e.lower() for e in extensions) if extensions else None

    if not names_lower and not exts_lower:
        return []

    results: list[str] = []
    for drive in drives:
        res = _scan_volume(drive, names_lower, exts_lower)
        if res is None:
            continue
        dir_map, hits = res
        for pref, fname in hits:
            parent = _resolve_path(dir_map, pref, drive)
            full = parent + "\\" + fname

            if scope_paths and not any(full.startswith(sp) for sp in scope_paths):
                continue

            results.append(full)

    return results
