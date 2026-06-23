"""Catalogers: the binary content cataloger plus package-DB catalogers."""

from __future__ import annotations

from .apk import ApkCataloger
from .binary import BinaryCataloger
from .dpkg import DpkgCataloger
from .registry import RegistryCataloger
from .rpm import RpmCataloger
from .win_binary import WinBinaryCataloger

#: package-DB catalogers, keyed by name (ordered).
PACKAGE_CATALOGERS = {
    "dpkg": DpkgCataloger,
    "rpm": RpmCataloger,
    "apk": ApkCataloger,
    "registry": RegistryCataloger,
    "win_binary": WinBinaryCataloger,
}

__all__ = [
    "ApkCataloger",
    "BinaryCataloger",
    "DpkgCataloger",
    "RegistryCataloger",
    "RpmCataloger",
    "WinBinaryCataloger",
    "PACKAGE_CATALOGERS",
]
