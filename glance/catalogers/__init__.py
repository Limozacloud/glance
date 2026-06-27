"""Catalogers: the binary content cataloger plus package-DB catalogers."""

from __future__ import annotations

from .apk import ApkCataloger
from .binary import BinaryCataloger
from .dpkg import DpkgCataloger
from .ecosystem import ECOSYSTEM_CATALOGERS
from .gobinary import GoBinaryCataloger
from .registry import RegistryCataloger
from .rpm import RpmCataloger
from .win_binary import WinBinaryCataloger

#: OS package-DB catalogers, keyed by name (ordered).
PACKAGE_CATALOGERS = {
    "dpkg": DpkgCataloger,
    "rpm": RpmCataloger,
    "apk": ApkCataloger,
    "registry": RegistryCataloger,
    "win_binary": WinBinaryCataloger,
}

#: Named groups that expand to individual cataloger names.
CATALOGER_GROUPS: dict[str, list[str]] = {
    "software": ["dpkg", "rpm", "apk", "registry"],
    "binary": ["binary", "win_binary"],
    "ecosystem": list(ECOSYSTEM_CATALOGERS),
    "installed": ["dpkg", "rpm", "apk", "registry", "win_binary", "distinfo"],
    "all": ["dpkg", "rpm", "apk", "registry", "binary", "win_binary", "gobinary"] + list(ECOSYSTEM_CATALOGERS),
}


def expand_catalogers(names: list[str]) -> list[str]:
    """Expand group aliases to individual cataloger names, preserving order."""
    result: list[str] = []
    seen: set[str] = set()
    for name in names:
        for expanded in CATALOGER_GROUPS.get(name, [name]):
            if expanded not in seen:
                seen.add(expanded)
                result.append(expanded)
    return result


__all__ = [
    "ApkCataloger",
    "BinaryCataloger",
    "DpkgCataloger",
    "GoBinaryCataloger",
    "RegistryCataloger",
    "RpmCataloger",
    "WinBinaryCataloger",
    "PACKAGE_CATALOGERS",
    "ECOSYSTEM_CATALOGERS",
    "CATALOGER_GROUPS",
    "expand_catalogers",
]
