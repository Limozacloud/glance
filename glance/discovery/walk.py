"""Mount-table utilities for filesystem-type exclusion.

These are used to filter plocate results: if a path lives under a mount point
whose fstype is in exclude_fs_types, it is skipped.
"""

from __future__ import annotations


def read_mounts() -> list[tuple[str, str]]:
    """Return ``(mountpoint, fstype)`` pairs from ``/proc/self/mounts``."""
    mounts: list[tuple[str, str]] = []
    try:
        with open("/proc/self/mounts", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 3:
                    mountpoint = parts[1].encode().decode("unicode_escape")
                    mounts.append((mountpoint, parts[2]))
    except OSError:
        pass
    return mounts


def excluded_mount_prefixes(exclude_fs_types: list[str]) -> list[str]:
    """Mountpoints whose filesystem type is excluded (longest first).

    The root mount (``/``) is never excluded — in Docker/OCI containers the
    root is overlay and excluding it would make every path unreachable.
    """
    excluded = {t.lower() for t in exclude_fs_types}
    prefixes = [
        mp for mp, fstype in read_mounts() if fstype.lower() in excluded and mp not in ("/", "")
    ]
    return sorted(set(prefixes), key=len, reverse=True)
