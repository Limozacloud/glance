"""Minimal /etc/os-release reader for PURL namespaces."""

from __future__ import annotations

import functools


@functools.lru_cache(maxsize=1)
def os_release() -> dict[str, str]:
    data: dict[str, str] = {}
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, _, value = line.partition("=")
                    data[key] = value.strip().strip('"').strip("'")
            break
        except OSError:
            continue
    return data


def distro_id() -> str:
    """The os-release ``ID`` (e.g. ``debian``, ``ubuntu``, ``alpine``, ``rhel``)."""
    return os_release().get("ID", "").lower() or "linux"
