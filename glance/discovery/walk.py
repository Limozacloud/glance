"""Filesystem walk fallback and mount/filesystem-type handling.

The walk streams paths via ``os.scandir`` (never materialising the whole tree),
honours excluded filesystem types by reading the mount table, and swallows —
but records — permission errors and vanished files so a broken mount never
aborts the run.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterator

from ..models import ScanReport, SkipReason

log = logging.getLogger(__name__)


def read_mounts() -> list[tuple[str, str]]:
    """Return ``(mountpoint, fstype)`` pairs from ``/proc/self/mounts``."""
    mounts: list[tuple[str, str]] = []
    try:
        with open("/proc/self/mounts", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 3:
                    # field 2 = mountpoint (octal-escaped), field 3 = fstype
                    mountpoint = parts[1].encode().decode("unicode_escape")
                    mounts.append((mountpoint, parts[2]))
    except OSError:
        pass
    return mounts


def excluded_mount_prefixes(exclude_fs_types: list[str]) -> list[str]:
    """Mountpoints whose filesystem type is excluded (longest first).

    The root mount (``/``) is never excluded even if its fstype matches — in
    Docker/OCI containers the root is always an overlay and excluding it would
    make every user-specified ``--include`` path unreachable.
    """
    excluded = {t.lower() for t in exclude_fs_types}
    prefixes = [
        mp
        for mp, fstype in read_mounts()
        if fstype.lower() in excluded and mp not in ("/", "")
    ]
    # de-dup and sort longest-first so the most specific mount wins
    return sorted(set(prefixes), key=len, reverse=True)


def _under(path: str, prefixes: list[str]) -> str | None:
    for prefix in prefixes:
        if path == prefix or path.startswith(prefix.rstrip("/") + "/"):
            return prefix
    return None


def walk_tree(
    root: str,
    *,
    follow_symlinks: bool,
    excluded_prefixes: list[str],
    exclude_paths: list[str],
    report: ScanReport,
    apply_scope: bool = True,
) -> Iterator[str]:
    """Yield regular-file paths under ``root``.

    ``apply_scope=False`` (used for mandatory paths) ignores exclude_paths and
    excluded filesystem types — those locations must never be pruned away.
    """
    if not os.path.exists(root):
        report.skip(root, SkipReason.NOT_FOUND)
        return

    stack = [root]
    while stack:
        current = stack.pop()
        if apply_scope:
            hit = _under(current, exclude_paths)
            if hit is not None:
                report.skip(current, SkipReason.CONFIG_EXCLUDE_PATH, hit)
                continue
            mount = _under(current, excluded_prefixes)
            if mount is not None:
                report.skip(current, SkipReason.CONFIG_FS_TYPE, mount)
                continue
        try:
            with os.scandir(current) as it:
                for entry in it:
                    try:
                        if entry.is_dir(follow_symlinks=follow_symlinks):
                            stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=follow_symlinks):
                            yield entry.path
                    except OSError as exc:
                        report.skip(entry.path, SkipReason.READ_ERROR, str(exc))
        except PermissionError as exc:
            report.skip(current, SkipReason.PERMISSION_DENIED, str(exc))
        except FileNotFoundError:
            report.skip(current, SkipReason.NOT_FOUND)
        except OSError as exc:
            report.skip(current, SkipReason.READ_ERROR, str(exc))
