"""Catalogers: the binary content cataloger plus package-DB catalogers."""

from __future__ import annotations

from .apk import ApkCataloger
from .binary import BinaryCataloger
from .dpkg import DpkgCataloger
from .ecosystem import ECOSYSTEM_INSTALLED_CATALOGERS, ECOSYSTEM_PROJECT_CATALOGERS
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
#: "ecosystem" is a sentinel resolved by scan() based on ecosystem_mode.
CATALOGER_GROUPS: dict[str, list[str]] = {
    "software": ["dpkg", "rpm", "apk", "registry"],
    "binary": ["binary", "win_binary"],
    # "ecosystem" self-expands as a sentinel; scan() picks project vs installed
    # based on config.ecosystem_mode.
    "ecosystem": ["ecosystem"],
    "ecosystem-project": list(ECOSYSTEM_PROJECT_CATALOGERS),
    "ecosystem-installed": list(ECOSYSTEM_INSTALLED_CATALOGERS),
    "all": [
        "dpkg",
        "rpm",
        "apk",
        "registry",
        "binary",
        "win_binary",
        "gobinary",
        "ecosystem",  # sentinel — expands to the mode-selected ecosystem set
    ],
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
    "ECOSYSTEM_PROJECT_CATALOGERS",
    "ECOSYSTEM_INSTALLED_CATALOGERS",
    "CATALOGER_GROUPS",
    "expand_catalogers",
]
