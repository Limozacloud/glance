"""Catalogers: the binary content cataloger plus package-DB catalogers."""

from __future__ import annotations

from .apk import ApkCataloger
from .binary import BinaryCataloger
from .dpkg import DpkgCataloger
from .rpm import RpmCataloger

#: package-DB catalogers, keyed by name (ordered).
PACKAGE_CATALOGERS = {
    "dpkg": DpkgCataloger,
    "rpm": RpmCataloger,
    "apk": ApkCataloger,
}

__all__ = ["ApkCataloger", "BinaryCataloger", "DpkgCataloger", "RpmCataloger", "PACKAGE_CATALOGERS"]
