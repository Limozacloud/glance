"""Ecosystem (language package manager) catalogers."""

from __future__ import annotations

from .gem import GemCataloger
from .go import GoCataloger
from .maven import MavenCataloger
from .npm import NpmCataloger
from .nuget import NugetCataloger
from .pip import PipCataloger

ECOSYSTEM_CATALOGERS: dict[str, type] = {
    "pip": PipCataloger,
    "go": GoCataloger,
    "npm": NpmCataloger,
    "nuget": NugetCataloger,
    "maven": MavenCataloger,
    "gem": GemCataloger,
}

__all__ = [
    "GemCataloger",
    "GoCataloger",
    "MavenCataloger",
    "NpmCataloger",
    "NugetCataloger",
    "PipCataloger",
    "ECOSYSTEM_CATALOGERS",
]
